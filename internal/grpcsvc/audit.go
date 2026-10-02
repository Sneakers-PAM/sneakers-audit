// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcsvc implements sneakers.audit.v1.AuditService over a hash-chained
// log. The chaining/verification logic is storage-independent (see chain), so
// the trail is served from either an in-memory store (tests) or Postgres (prod)
// via the Store interface.
package grpcsvc

import (
	"context"
	"sync"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-audit/internal/chain"
	"google.golang.org/grpc"
)

// Server records and verifies the audit chain. Appends are serialized (mu) so
// each record's prev_hash/seq is computed against a stable tail.
type Server struct {
	auditv1.UnimplementedAuditServiceServer

	mu    sync.Mutex
	store Store
}

// New builds an in-memory Server (used by unit tests).
func New() *Server { return &Server{store: &memStore{}} }

// NewPG builds a Postgres-backed Server.
func NewPG(db postgres.Querier) *Server { return &Server{store: &pgStore{db: db}} }

// Register wires an in-memory audit service into a gRPC server.
func Register(gs *grpc.Server) { auditv1.RegisterAuditServiceServer(gs, New()) }

// RegisterServer wires an explicit Server (e.g. Postgres-backed) into gRPC.
func RegisterServer(gs *grpc.Server, s *Server) { auditv1.RegisterAuditServiceServer(gs, s) }

func (s *Server) RecordEvent(ctx context.Context, req *auditv1.RecordEventRequest) (*auditv1.RecordEventResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	occurred := req.GetOccurredAt()
	if occurred == "" {
		occurred = time.Now().UTC().Format(time.RFC3339Nano)
	}
	last, err := s.store.Last(ctx)
	if err != nil {
		return nil, err
	}
	var seq uint64 = 1
	prev := ""
	if last != nil {
		seq = last.GetSeq() + 1
		prev = last.GetHash()
	}
	rec := &auditv1.AuditRecord{
		Seq:         seq,
		Tier:        req.GetTier(),
		Action:      req.GetAction(),
		ActorUserId: req.GetActorUserId(),
		Subject:     req.GetSubject(),
		GroupId:     req.GetGroupId(),
		Sensitive:   req.GetSensitive(),
		Attributes:  req.GetAttributes(),
		OccurredAt:  occurred,
		PrevHash:    prev,
	}
	rec.Hash = chain.Hash(rec)
	if err := s.store.Append(ctx, rec); err != nil {
		return nil, err
	}
	return &auditv1.RecordEventResponse{Record: rec}, nil
}

func (s *Server) ListRecords(ctx context.Context, req *auditv1.ListRecordsRequest) (*auditv1.ListRecordsResponse, error) {
	out, err := s.store.List(ctx, req.GetActorUserId(), req.GetSubject(), req.GetExcludeActions(), int(req.GetLimit()))
	if err != nil {
		return nil, err
	}
	return &auditv1.ListRecordsResponse{Records: out}, nil
}

func (s *Server) DistinctActions(ctx context.Context, req *auditv1.DistinctActionsRequest) (*auditv1.DistinctActionsResponse, error) {
	actions, err := s.store.DistinctActions(ctx, req.GetActorUserId())
	if err != nil {
		return nil, err
	}
	return &auditv1.DistinctActionsResponse{Actions: actions}, nil
}

func (s *Server) VerifyChain(ctx context.Context, _ *auditv1.VerifyChainRequest) (*auditv1.VerifyChainResponse, error) {
	records, err := s.store.All(ctx)
	if err != nil {
		return nil, err
	}
	valid, brokenAt := chain.Verify(records)
	return &auditv1.VerifyChainResponse{Valid: valid, BrokenAtSeq: brokenAt, Length: uint64(len(records))}, nil
}
