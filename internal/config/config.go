// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseDSN string
	GRPCPort    string
	// HealthPort serves the health service in plaintext when mTLS is on, so the
	// kubelet probe (which has no client certificate) can reach it. Unused
	// without mTLS: health stays on GRPCPort.
	HealthPort   string
	OTLPEndpoint string
}

func Load() (Config, error) {
	c := Config{
		DatabaseDSN: os.Getenv("DATABASE_DSN"),
		GRPCPort:    getOr("GRPC_PORT", "9090"),
		HealthPort:  getOr("HEALTH_PORT", "9091"),
		// Empty means no collector: otel.Init runs without an exporter instead
		// of retrying a default localhost address that is rarely there.
		OTLPEndpoint: getOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
	}
	if c.DatabaseDSN == "" {
		return c, fmt.Errorf("DATABASE_DSN is required")
	}
	return c, nil
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
