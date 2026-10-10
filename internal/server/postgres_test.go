// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
)

// TestPostgres_StopAndStartMidTest runs against a throwaway Postgres container
// it stops and starts again. Set AUDIT_PG_DSN and AUDIT_PG_CONTAINER (the
// container's name) to run it. Publish the container on a fixed host port
// (a random one can change on restart) and run packages one at a time (-p 1),
// since stopping the server breaks any other Postgres test running then.
func TestPostgres_StopAndStartMidTest(t *testing.T) {
	dsn, name := os.Getenv("AUDIT_PG_DSN"), os.Getenv("AUDIT_PG_CONTAINER")
	if dsn == "" || name == "" {
		t.Skip("set AUDIT_PG_DSN and AUDIT_PG_CONTAINER to run the Postgres stop/start test")
	}
	ctx := context.Background()
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()

	c, err := NewChecker(log.Nop(), []health.Dependency{Postgres(db)}, health.WithTTL(testTTL))
	if err != nil {
		t.Fatal(err)
	}
	refreshed(t, c)
	report := func() health.Report { time.Sleep(2 * testTTL); return c.Report(ctx) }

	if r := report(); r.Status != health.StateOK || r.Dependencies[0].Version == "unknown" {
		t.Fatalf("before the stop: %+v", r)
	}
	docker(t, "stop", name)
	stopped := true
	t.Cleanup(func() {
		if stopped {
			_ = exec.Command("docker", "start", name).Run()
		}
	})
	if r := report(); r.Status != health.StateDown || r.Ready || r.Dependencies[0].Error == "" {
		t.Fatalf("while stopped: %+v", r)
	}
	docker(t, "start", name)
	stopped = false
	deadline := time.Now().Add(30 * time.Second)
	for {
		r := report()
		if r.Status == health.StateOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery after the restart: %+v", r)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func docker(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
		t.Fatalf("docker %v: %v (%s)", args, err, out)
	}
}
