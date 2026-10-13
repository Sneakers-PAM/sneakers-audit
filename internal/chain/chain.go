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
	var v Verifier
	for _, r := range records {
		v.Add(r)
	}
	return v.Result()
}

// Verifier checks a chain one record at a time, in seq order, so a chain of
// any length is verified without holding it: it keeps only the last hash and
// the first bad record's seq.
type Verifier struct {
	n        uint64
	prev     string
	brokenAt uint64
	broken   bool
}

// Add checks the next record. After the first bad record it only counts.
func (v *Verifier) Add(r *auditv1.AuditRecord) {
	v.n++
	if v.broken {
		return
	}
	if r.GetSeq() != v.n || r.GetPrevHash() != v.prev || Hash(r) != r.GetHash() {
		v.broken, v.brokenAt = true, r.GetSeq()
		return
	}
	v.prev = r.GetHash()
}

// Result is (valid, brokenAtSeq), as Verify answers.
func (v *Verifier) Result() (bool, uint64) { return !v.broken, v.brokenAt }

// Length is how many records were added.
func (v *Verifier) Length() uint64 { return v.n }
