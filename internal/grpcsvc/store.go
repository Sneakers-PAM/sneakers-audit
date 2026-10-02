// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/json"

	postgres "github.com/Bugs5382/go-postgres"
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
)

// Store persists the hash-chained audit trail. The record assembly (seq,
// prev_hash, hash) lives in the Server; the Store only appends and reads.
type Store interface {
	// Last returns the most recent record, or nil if the chain is empty.
	Last(ctx context.Context) (*auditv1.AuditRecord, error)
	Append(ctx context.Context, rec *auditv1.AuditRecord) error
	// All returns every record ordered by seq (for chain verification).
	All(ctx context.Context) ([]*auditv1.AuditRecord, error)
	// List filters by actor/subject (empty = any), drops records whose action is
	// in excludeActions across the WHOLE chain, then keeps the most-recent limit
	// (0 = all). Exclusion is applied BEFORE the limit so it spans the entire
	// chain, not just the last N records.
	List(ctx context.Context, actorUserID, subject string, excludeActions []string, limit int) ([]*auditv1.AuditRecord, error)
	// DistinctActions returns the distinct action values in the chain (optionally
	// scoped to one actor), for the full "hide actions" option set.
	DistinctActions(ctx context.Context, actorUserID string) ([]string, error)
}

// ---- in-memory store (used by unit tests) -----------------------------------

type memStore struct{ records []*auditv1.AuditRecord }

func (m *memStore) Last(context.Context) (*auditv1.AuditRecord, error) {
	if len(m.records) == 0 {
		return nil, nil
	}
	return m.records[len(m.records)-1], nil
}
func (m *memStore) Append(_ context.Context, rec *auditv1.AuditRecord) error {
	m.records = append(m.records, rec)
	return nil
}
func (m *memStore) All(context.Context) ([]*auditv1.AuditRecord, error) {
	return m.records, nil
}
func (m *memStore) List(_ context.Context, actor, subject string, excludeActions []string, limit int) ([]*auditv1.AuditRecord, error) {
	excluded := make(map[string]bool, len(excludeActions))
	for _, a := range excludeActions {
		excluded[a] = true
	}
	var out []*auditv1.AuditRecord
	for _, r := range m.records {
		if actor != "" && r.GetActorUserId() != actor {
			continue
		}
		if subject != "" && r.GetSubject() != subject {
			continue
		}
		if excluded[r.GetAction()] {
			continue
		}
		out = append(out, r)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (m *memStore) DistinctActions(_ context.Context, actor string) ([]string, error) {
	seen := make(map[string]bool)
	var out []string
	for _, r := range m.records {
		if actor != "" && r.GetActorUserId() != actor {
			continue
		}
		if a := r.GetAction(); a != "" && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

// ---- Postgres store ----------------------------------------------------------

type pgStore struct{ db postgres.Querier }

func scanRecord(row interface {
	Scan(...any) error
}) (*auditv1.AuditRecord, error) {
	r := &auditv1.AuditRecord{}
	var attrs []byte
	var tier int32
	if err := row.Scan(&r.Seq, &tier, &r.Action, &r.ActorUserId, &r.Subject, &r.GroupId,
		&r.Sensitive, &attrs, &r.OccurredAt, &r.PrevHash, &r.Hash); err != nil {
		return nil, err
	}
	r.Tier = auditv1.Tier(tier)
	if len(attrs) > 0 {
		_ = json.Unmarshal(attrs, &r.Attributes)
	}
	return r, nil
}

const selectCols = `seq, tier, action, actor_user_id, subject, group_id, sensitive, attributes, occurred_at, prev_hash, hash`

func (p *pgStore) Last(ctx context.Context) (*auditv1.AuditRecord, error) {
	rec, err := scanRecord(p.db.QueryRow(ctx, `SELECT `+selectCols+` FROM audit_records ORDER BY seq DESC LIMIT 1`))
	if err != nil {
		return nil, nil // empty chain (no rows) is not an error to the caller
	}
	return rec, nil
}

func (p *pgStore) Append(ctx context.Context, rec *auditv1.AuditRecord) error {
	attrs, _ := json.Marshal(rec.GetAttributes())
	if len(attrs) == 0 {
		attrs = []byte("{}")
	}
	_, err := p.db.Exec(ctx,
		`INSERT INTO audit_records (`+selectCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		rec.GetSeq(), int32(rec.GetTier()), rec.GetAction(), rec.GetActorUserId(), rec.GetSubject(),
		rec.GetGroupId(), rec.GetSensitive(), attrs, rec.GetOccurredAt(), rec.GetPrevHash(), rec.GetHash())
	return err
}

func (p *pgStore) All(ctx context.Context) ([]*auditv1.AuditRecord, error) {
	rows, err := p.db.Query(ctx, `SELECT `+selectCols+` FROM audit_records ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*auditv1.AuditRecord
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *pgStore) List(ctx context.Context, actor, subject string, excludeActions []string, limit int) ([]*auditv1.AuditRecord, error) {
	// action <> ALL($3) drops excluded actions across the whole chain; an empty
	// array keeps every row (x <> ALL('{}') is true). The limit is applied after
	// exclusion so it bounds the already-filtered set, not the raw window.
	// A nil slice is sent as NULL, and x <> ALL(NULL) is NULL, which would drop
	// every row, so it's sent as an empty array instead.
	if excludeActions == nil {
		excludeActions = []string{}
	}
	rows, err := p.db.Query(ctx,
		`SELECT `+selectCols+` FROM audit_records
		 WHERE ($1 = '' OR actor_user_id = $1) AND ($2 = '' OR subject = $2)
		   AND action <> ALL($3::text[])
		 ORDER BY seq`, actor, subject, excludeActions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*auditv1.AuditRecord
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (p *pgStore) DistinctActions(ctx context.Context, actor string) ([]string, error) {
	rows, err := p.db.Query(ctx,
		`SELECT DISTINCT action FROM audit_records
		 WHERE ($1 = '' OR actor_user_id = $1)
		 ORDER BY action`, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
