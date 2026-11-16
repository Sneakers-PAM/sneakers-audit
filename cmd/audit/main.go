// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	mtls "github.com/Bugs5382/go-mtls"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-audit/internal/config"
	"github.com/Sneakers-PAM/sneakers-audit/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-audit/internal/server"
	"github.com/Sneakers-PAM/sneakers-audit/internal/telemetry"
	"google.golang.org/grpc"
)

const serviceName = "audit"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger := log.NewLoggerWithOptions(serviceName, log.WithOutput(telemetry.LogOutput(os.Getenv, os.Stdout)))
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal(err, "config")
	}

	otelShutdown, err := otel.InitWithOptions(ctx, serviceName, cfg.OTLPEndpoint, telemetry.Options(os.Getenv)...)
	if err != nil {
		logger.Fatal(err, "otel init")
	}
	defer func() {
		if err := otelShutdown(context.Background()); err != nil {
			logger.Warn("otel shutdown", log.F("error", err.Error()))
		}
	}()

	// Service-to-service authentication fails closed: check it before anything
	// else so a missing issuer stops the boot with the schema untouched.
	if _, _, err := server.WorkloadConfigFromEnv(os.Getenv); err != nil {
		logger.Fatal(err, "workload auth config")
	}

	// Mutual TLS is on when the MTLS_* file variables are set: the gRPC port
	// then requires a client certificate and health moves to its own plain
	// port (HEALTH_PORT), because the kubelet probe cannot present one. Unset
	// keeps plaintext on GRPC_PORT.
	tlsProvider, bootPort, healthPort, err := setupMTLS(cfg, logger)
	if err != nil {
		logger.Fatal(err, "mtls config")
	}

	// The port answers health from here on, while the boot waits for
	// Postgres and runs the migrations: liveness SERVING, so the startup probe
	// passes on a slow boot, and readiness NOT_SERVING with postgres listed
	// down until it is reached.
	boot, err := server.StartBootHealth(bootPort, logger, "postgres")
	if err != nil {
		logger.Fatal(err, "boot health")
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
			logger.Info("stopped while waiting for postgres")
			return
		}
		logger.Fatal(err, "postgres")
	}
	defer db.Close()

	// Direct (no-broker) audit: services call RecordEvent over gRPC and the
	// hash-chained trail is persisted append-only to Postgres.
	svc := grpcsvc.NewPG(db.Querier())
	// Every caller is authenticated by its workload identity and checked
	// against grpcsvc.CallerPolicy.
	workloadVerifier, authOpts, err := server.WorkloadAuth(ctx, os.Getenv, grpcsvc.CallerPolicy(), logger)
	if err != nil {
		logger.Fatal(err, "workload auth")
	}
	authOpts = withMTLS(authOpts, tlsProvider)
	logger.Info("starting", log.F("port", cfg.GRPCPort), log.F("health_port", healthPort), log.F("mtls", tlsProvider != nil))
	// Readiness follows Postgres: every RPC reads or writes the trail there.
	// The workload-identity verifier is required too once authentication is
	// on: no caller can be checked before its key set loads. It's left out
	// when authentication is disabled (verifier nil).
	deps := []health.Dependency{server.Postgres(db)}
	if workloadVerifier != nil {
		deps = append(deps, server.WorkloadIdentity(workloadVerifier))
	}
	deps = append(deps, telemetry.Dependencies(cfg.OTLPEndpoint, os.Getenv)...)
	checker, err := server.NewChecker(logger, deps)
	if err != nil {
		logger.Fatal(err, "health checker")
	}
	boot.Stop()
	if err := server.RunWithHealthPort(ctx, cfg.GRPCPort, healthPort, logger, checker, func(gs *grpc.Server) {
		grpcsvc.RegisterServer(gs, svc)
	}, authOpts...); err != nil {
		logger.Fatal(err, "server exited")
	}
}

// setupMTLS loads the mTLS provider (nil when the MTLS_* variables are unset)
// and the health ports that go with it.
func setupMTLS(cfg config.Config, lg log.Logger) (*mtls.Provider, string, string, error) {
	p, err := server.MTLSFromEnv(os.Getenv, lg)
	if err != nil {
		return nil, "", "", err
	}
	boot, healthPort, err := healthPorts(cfg, p != nil)
	return p, boot, healthPort, err
}

// withMTLS adds the provider's server credentials to opts; a nil provider
// leaves them plaintext.
func withMTLS(opts []grpc.ServerOption, p *mtls.Provider) []grpc.ServerOption {
	if p == nil {
		return opts
	}
	return append(opts, p.ServerOption())
}

// healthPorts picks the port the boot health listens on and the plain
// health-only port for the running server. Without mTLS health stays on the
// gRPC port and there is no second port; with it, health moves to HEALTH_PORT
// for the whole run, so the probes never need a client certificate.
func healthPorts(cfg config.Config, mtlsOn bool) (bootPort, healthPort string, err error) {
	if !mtlsOn {
		return cfg.GRPCPort, "", nil
	}
	if cfg.HealthPort == cfg.GRPCPort {
		return "", "", fmt.Errorf("HEALTH_PORT and GRPC_PORT are both %s", cfg.HealthPort)
	}
	return cfg.HealthPort, cfg.HealthPort, nil
}
