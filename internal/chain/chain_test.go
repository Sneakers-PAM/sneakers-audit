// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"fmt"
	"testing"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
)

func links(n int) []*auditv1.AuditRecord {
	var out []*auditv1.AuditRecord
	prev := ""
	for i := 1; i <= n; i++ {
		r := &auditv1.AuditRecord{Seq: uint64(i), Tier: auditv1.Tier_TIER_AUDIT, Action: fmt.Sprintf("a%d", i), ActorUserId: "u", Subject: "s",
			Attributes: map[string]string{"k": fmt.Sprint(i)}, OccurredAt: "2026-10-13T10:00:00Z", PrevHash: prev}
		r.Hash = Hash(r)
		prev = r.Hash
		out = append(out, r)
	}
	return out
}

// A Verifier fed one record at a time answers what Verify answers for the
// whole chain, and counts every record, after a break too.
func TestTheVerifierAnswersAsVerifyDoes(t *testing.T) {
	for name, mod := range map[string]func([]*auditv1.AuditRecord) []*auditv1.AuditRecord{
		"valid":      func(r []*auditv1.AuditRecord) []*auditv1.AuditRecord { return r },
		"empty":      func([]*auditv1.AuditRecord) []*auditv1.AuditRecord { return nil },
		"tampered":   func(r []*auditv1.AuditRecord) []*auditv1.AuditRecord { r[3].Action = "x"; return r },
		"bad prev":   func(r []*auditv1.AuditRecord) []*auditv1.AuditRecord { r[2].PrevHash = "00"; return r },
		"seq gap":    func(r []*auditv1.AuditRecord) []*auditv1.AuditRecord { return append(r[:4], r[5:]...) },
		"first only": func(r []*auditv1.AuditRecord) []*auditv1.AuditRecord { r[0].Hash = "ff"; return r },
	} {
		t.Run(name, func(t *testing.T) {
			recs := mod(links(10))
			wantValid, wantAt := Verify(recs)
			var v Verifier
			for _, r := range recs {
				v.Add(r)
			}
			valid, at := v.Result()
			if valid != wantValid || at != wantAt || v.Length() != uint64(len(recs)) {
				t.Fatalf("Verifier: valid %v at %d length %d; Verify: %v at %d, %d records", valid, at, v.Length(), wantValid, wantAt, len(recs))
			}
		})
	}
}
