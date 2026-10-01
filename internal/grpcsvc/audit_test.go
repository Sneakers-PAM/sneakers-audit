// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
)

func record(t *testing.T, s *Server, action, actor, subject string) {
	t.Helper()
	if _, err := s.RecordEvent(context.Background(), &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: action, ActorUserId: actor, Subject: subject, Sensitive: true,
	}); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
}

func TestChainLinksAndVerifies(t *testing.T) {
	s := New()
	record(t, s, "secret.create", "user-alice", "secret-1")
	record(t, s, "secret.reveal", "user-alice", "secret-1#password")
	record(t, s, "secret.update", "user-bob", "secret-1")

	resp, err := s.VerifyChain(context.Background(), &auditv1.VerifyChainRequest{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !resp.GetValid() || resp.GetLength() != 3 {
		t.Fatalf("valid=%v length=%d, want valid, 3", resp.GetValid(), resp.GetLength())
	}
	// prev_hash linkage
	recs := s.store.(*memStore).records
	if recs[0].GetPrevHash() != "" {
		t.Fatal("first record should have empty prev_hash")
	}
	if recs[1].GetPrevHash() != recs[0].GetHash() {
		t.Fatal("record 2 prev_hash must equal record 1 hash")
	}
}

func TestTamperBreaksChain(t *testing.T) {
	s := New()
	record(t, s, "a", "u1", "s1")
	record(t, s, "b", "u2", "s2")
	record(t, s, "c", "u3", "s3")

	// Tamper with record 2's action after the fact.
	s.store.(*memStore).records[1].Action = "b-tampered"

	resp, _ := s.VerifyChain(context.Background(), &auditv1.VerifyChainRequest{})
	if resp.GetValid() {
		t.Fatal("expected chain to be invalid after tampering")
	}
	if resp.GetBrokenAtSeq() != 2 {
		t.Fatalf("broken_at_seq = %d, want 2", resp.GetBrokenAtSeq())
	}
}

func TestListFiltersAndLimits(t *testing.T) {
	s := New()
	record(t, s, "a", "user-alice", "s1")
	record(t, s, "b", "user-bob", "s2")
	record(t, s, "c", "user-alice", "s3")

	byActor, _ := s.ListRecords(context.Background(), &auditv1.ListRecordsRequest{ActorUserId: "user-alice"})
	if len(byActor.GetRecords()) != 2 {
		t.Fatalf("actor filter returned %d, want 2", len(byActor.GetRecords()))
	}
	limited, _ := s.ListRecords(context.Background(), &auditv1.ListRecordsRequest{Limit: 1})
	if len(limited.GetRecords()) != 1 || limited.GetRecords()[0].GetAction() != "c" {
		t.Fatalf("limit=1 should return most recent ('c'), got %+v", limited.GetRecords())
	}
}

func TestExcludeActionsSpansWholeChainBeforeLimit(t *testing.T) {
	s := New()
	// A busy tail of noise ('c') sits after the interesting events, so a
	// client-side filter over the last N would drop 'a'/'b' entirely.
	record(t, s, "a", "u1", "s1")
	record(t, s, "b", "u2", "s2")
	record(t, s, "c", "u3", "s3")
	record(t, s, "c", "u3", "s4")
	record(t, s, "c", "u3", "s5")

	// Exclude 'c' then take the most-recent 2: exclusion must span the whole
	// chain first, so we keep 'a' and 'b' (not an empty page of hidden 'c's).
	resp, _ := s.ListRecords(context.Background(), &auditv1.ListRecordsRequest{
		ExcludeActions: []string{"c"}, Limit: 2,
	})
	got := resp.GetRecords()
	if len(got) != 2 || got[0].GetAction() != "a" || got[1].GetAction() != "b" {
		t.Fatalf("exclude 'c' + limit 2 should yield [a b] across the whole chain, got %+v", got)
	}
}

func TestDistinctActions(t *testing.T) {
	s := New()
	record(t, s, "a", "user-alice", "s1")
	record(t, s, "b", "user-bob", "s2")
	record(t, s, "a", "user-alice", "s3")

	all, _ := s.DistinctActions(context.Background(), &auditv1.DistinctActionsRequest{})
	if len(all.GetActions()) != 2 {
		t.Fatalf("distinct actions = %v, want 2 unique", all.GetActions())
	}
	byActor, _ := s.DistinctActions(context.Background(), &auditv1.DistinctActionsRequest{ActorUserId: "user-bob"})
	if len(byActor.GetActions()) != 1 || byActor.GetActions()[0] != "b" {
		t.Fatalf("distinct actions for bob = %v, want [b]", byActor.GetActions())
	}
}
