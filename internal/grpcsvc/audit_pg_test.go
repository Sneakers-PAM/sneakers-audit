// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
)

// TestPGChainPersistsAndVerifies runs against a live Postgres when AUDIT_PG_DSN
// is set (otherwise skipped). It proves the chain persists across a "restart"
// (a fresh Server on the same DB) and that SQL-level tampering is detected.
//
//	AUDIT_PG_DSN=postgres://audit@localhost:5432/audit?sslmode=disable \
//	  go test ./internal/grpcsvc -run TestPG -v
func TestPGChainPersistsAndVerifies(t *testing.T) {
	dsn := os.Getenv("AUDIT_PG_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_PG_DSN to run the Postgres integration test")
	}
	if err := postgres.Migrate(dsn, "../../migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	pool := db.Pool()
	if _, err := pool.Exec(ctx, `TRUNCATE audit_records`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	s := NewPG(pool)
	for _, a := range []string{"secret.create", "secret.reveal", "secret.copy"} {
		if _, err := s.RecordEvent(ctx, &auditv1.RecordEventRequest{
			Tier: auditv1.Tier_TIER_AUDIT, Action: a, ActorUserId: "user-alice", Subject: "secret-seed-1", Sensitive: true,
			Attributes: map[string]string{"src": "test"},
		}); err != nil {
			t.Fatalf("record %s: %v", a, err)
		}
	}

	// "Restart": a fresh Server on the same DB sees the persisted chain.
	s2 := NewPG(pool)
	resp, err := s2.VerifyChain(ctx, &auditv1.VerifyChainRequest{})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !resp.GetValid() || resp.GetLength() != 3 {
		t.Fatalf("after restart: valid=%v length=%d, want valid, 3", resp.GetValid(), resp.GetLength())
	}

	// Attributes round-trip through JSONB.
	list, err := s2.ListRecords(ctx, &auditv1.ListRecordsRequest{Subject: "secret-seed-1"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.GetRecords()) != 3 || list.GetRecords()[0].GetAttributes()["src"] != "test" {
		t.Fatalf("list/attrs wrong: %+v", list.GetRecords())
	}

	// Tamper at the SQL level -> chain must break at seq 2.
	if _, err := pool.Exec(ctx, `UPDATE audit_records SET action='tampered' WHERE seq=2`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	resp, _ = s2.VerifyChain(ctx, &auditv1.VerifyChainRequest{})
	if resp.GetValid() || resp.GetBrokenAtSeq() != 2 {
		t.Fatalf("tamper not detected: valid=%v brokenAt=%d", resp.GetValid(), resp.GetBrokenAtSeq())
	}

	_, _ = pool.Exec(ctx, `TRUNCATE audit_records`)
}
