// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"
)

func TestLoadRequiredAndDefault(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.DatabaseDSN != "postgres://x" {
		t.Fatalf("got %q", c.DatabaseDSN)
	}
	if c.GRPCPort != "9090" {
		t.Fatalf("default GRPCPort got %q", c.GRPCPort)
	}
	if c.OTLPEndpoint != "" {
		t.Fatalf("default OTLPEndpoint got %q, want empty (no collector)", c.OTLPEndpoint)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	if err := os.Unsetenv("DATABASE_DSN"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing DATABASE_DSN")
	}
}

func TestLoadHealthPort(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.HealthPort != "9091" {
		t.Fatalf("default HealthPort got %q, want 9091", c.HealthPort)
	}
	t.Setenv("HEALTH_PORT", "9191")
	if c, err = Load(); err != nil || c.HealthPort != "9191" {
		t.Fatalf("HealthPort = %q, %v", c.HealthPort, err)
	}
}
