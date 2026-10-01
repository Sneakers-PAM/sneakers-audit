// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package chain implements the hash-chaining that makes the audit trail
// tamper-evident: each record's hash covers its own canonical form plus the
// previous record's hash, so editing, deleting, or reordering any record breaks
// every hash after it.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
)

// Canonical returns the deterministic byte form of a record that gets hashed.
// It intentionally excludes the record's own Hash field and sorts attribute
// keys so the encoding is stable regardless of map iteration order.
func Canonical(r *auditv1.AuditRecord) string {
	keys := make([]string, 0, len(r.GetAttributes()))
	for k := range r.GetAttributes() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var attrs strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&attrs, "%s=%s;", k, r.GetAttributes()[k])
	}
	return strings.Join([]string{
		fmt.Sprintf("%d", r.GetSeq()),
		r.GetTier().String(),
		r.GetAction(),
		r.GetActorUserId(),
		r.GetSubject(),
		r.GetGroupId(),
		fmt.Sprintf("%t", r.GetSensitive()),
		attrs.String(),
		r.GetOccurredAt(),
		r.GetPrevHash(),
	}, "|")
}

// Hash returns the hex sha-256 of a record's canonical form.
func Hash(r *auditv1.AuditRecord) string {
	sum := sha256.Sum256([]byte(Canonical(r)))
	return hex.EncodeToString(sum[:])
}

// Verify walks the chain and returns (valid, brokenAtSeq). A record is bad if
// its recomputed hash differs from its stored hash, or its prev_hash doesn't
// match the previous record's hash (or the ordering/seq is wrong). brokenAtSeq
// is the seq of the first bad record; 0 when the chain is valid.
func Verify(records []*auditv1.AuditRecord) (bool, uint64) {
	prev := ""
	for i, r := range records {
		if r.GetSeq() != uint64(i+1) {
			return false, r.GetSeq()
		}
		if r.GetPrevHash() != prev {
			return false, r.GetSeq()
		}
		if Hash(r) != r.GetHash() {
			return false, r.GetSeq()
		}
		prev = r.GetHash()
	}
	return true, 0
}
