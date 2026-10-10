// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-audit/internal/config"
	"github.com/Sneakers-PAM/sneakers-audit/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-audit/internal/server"
	"google.golang.org/grpc"
)

const serviceName = "audit"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.New(serviceName)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}

	otelShutdown, err := otel.Init(ctx, serviceName, cfg.OTLPEndpoint)
	if err != nil {
		logger.Fatal().Err(err).Msg("otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn().Err(err).Msg("otel shutdown")
		}
	}()

	// Service-to-service authentication fails closed: check it before anything
	// else so a missing issuer stops the boot with the schema untouched.
	if _, _, err := server.WorkloadConfigFromEnv(os.Getenv); err != nil {
		logger.Fatal().Err(err).Msg("workload auth config")
	}

	svcLog := log.NewLogger(serviceName)
	// The port answers health from here on, while the boot waits for
	// Postgres and runs the migrations: liveness SERVING, so the startup probe
	// passes on a slow boot, and readiness NOT_SERVING with postgres listed
	// down until it is reached.
	boot, err := server.StartBootHealth(cfg.GRPCPort, svcLog, "postgres")
	if err != nil {
		logger.Fatal().Err(err).Msg("boot health")
	}

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = "migrations"
	}
	// Migrations need a direct/session Postgres connection (advisory locks,
	// CURRENT_SCHEMA, prepared statements) which break through a
	// transaction-pooling proxy. Use MIGRATE_DSN when set, otherwise fall back
	// to the runtime DSN.
	migrateDSN := os.Getenv("MIGRATE_DSN")
	if migrateDSN == "" {
		migrateDSN = cfg.DatabaseDSN
	}
	db, err := openPostgres(ctx, boot, migrateDSN, migrationsDir, cfg.DatabaseDSN)
	if err != nil {
		if ctx.Err() != nil {
			boot.Stop()
			logger.Info().Msg("stopped while waiting for postgres")
			return
		}
		logger.Fatal().Err(err).Msg("postgres")
	}
	defer db.Close()

	// Direct (no-broker) audit: services call RecordEvent over gRPC and the
	// hash-chained trail is persisted append-only to Postgres.
	svc := grpcsvc.NewPG(db.Querier())
	// Every caller is authenticated by its workload identity and checked
	// against grpcsvc.CallerPolicy.
	workloadVerifier, authOpts, err := server.WorkloadAuth(ctx, os.Getenv, grpcsvc.CallerPolicy(), svcLog)
	if err != nil {
		logger.Fatal().Err(err).Msg("workload auth")
	}
	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	// Readiness follows Postgres: every RPC reads or writes the trail there.
	// The workload-identity verifier is required too once authentication is
	// on: no caller can be checked before its key set loads. It's left out
	// when authentication is disabled (verifier nil).
	deps := []health.Dependency{server.Postgres(db)}
	if workloadVerifier != nil {
		deps = append(deps, server.WorkloadIdentity(workloadVerifier))
	}
	checker, err := server.NewChecker(svcLog, deps)
	if err != nil {
		logger.Fatal().Err(err).Msg("health checker")
	}
	boot.Stop()
	if err := server.RunWithHealth(ctx, cfg.GRPCPort, svcLog, checker, func(gs *grpc.Server) {
		grpcsvc.RegisterServer(gs, svc)
	}, authOpts...); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
