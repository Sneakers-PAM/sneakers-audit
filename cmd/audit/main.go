// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
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
	if err := postgres.Migrate(migrateDSN, migrationsDir); err != nil {
		logger.Fatal().Err(err).Msg("migrate")
	}
	db, err := postgres.New(ctx, cfg.DatabaseDSN, otelpg.WithTracing())
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()

	// Direct (no-broker) audit: services call RecordEvent over gRPC and the
	// hash-chained trail is persisted append-only to Postgres.
	svc := grpcsvc.NewPG(db.Querier())
	logger.Info().Str("port", cfg.GRPCPort).Msg("starting")
	if err := server.RunWithLogger(ctx, cfg.GRPCPort, log.NewLogger(serviceName), func(gs *grpc.Server) {
		grpcsvc.RegisterServer(gs, svc)
	}); err != nil {
		logger.Fatal().Err(err).Msg("server exited")
	}
}
