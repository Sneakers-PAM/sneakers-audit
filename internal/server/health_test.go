// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// testTTL is the cache window the tests run with; waiting it out lets the next
// check run again.
const testTTL = time.Second

// switchedVerifier is a ReadinessVerifier fake whose answer the test changes
// while the background refresh reads it.
type switchedVerifier struct {
	mu  sync.Mutex
	err error
}

func (v *switchedVerifier) set(err error) { v.mu.Lock(); v.err = err; v.mu.Unlock() }

func (v *switchedVerifier) Ready() error { v.mu.Lock(); defer v.mu.Unlock(); return v.err }

// refreshed runs c's background refresh for the test and waits for its first
// pass, so Report has results to read.
func refreshed(t *testing.T, c *health.Checker) *health.Checker {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(5 * time.Second)
	for {
		pending := false
		for _, d := range c.Report(context.Background()).Dependencies {
			pending = pending || d.Error == ClassPending
		}
		if !pending {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatal("the first background refresh never settled")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func newTestChecker(t *testing.T, deps ...health.Dependency) *health.Checker {
	t.Helper()
	c, err := NewChecker(log.Nop(), deps, health.WithTTL(testTTL))
	if err != nil {
		t.Fatalf("checker: %v", err)
	}
	return c
}

// healthClient runs a server with checker and returns a health client on it.
func healthClient(t *testing.T, checker *health.Checker) healthpb.HealthClient {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunWithHealth(ctx, port, log.Nop(), checker, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return healthpb.NewHealthClient(conn)
}

func check(t *testing.T, c healthpb.HealthClient, service string) (healthpb.HealthCheckResponse_ServingStatus, metadata.MD) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var md metadata.MD
	resp, err := c.Check(ctx, &healthpb.HealthCheckRequest{Service: service}, grpc.Header(&md), grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("check %q: %v", service, err)
	}
	return resp.GetStatus(), md
}

func TestHealth_ReadinessFollowsPostgresLivenessDoesNot(t *testing.T) {
	var down atomic.Bool
	checker := newTestChecker(t, health.Dependency{Name: "postgres", Required: true, Check: func(context.Context) error {
		if down.Load() {
			return errors.New("dial tcp db.example.test:5432: secret-dsn-text")
		}
		return nil
	}, Version: func(context.Context) (string, error) { return "17.11", nil }})
	c := healthClient(t, checker)

	eventuallyServing(t, c)
	down.Store(true)
	time.Sleep(2 * testTTL)
	st, md := check(t, c, "")
	if st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness while postgres is down = %v, want NOT_SERVING", st)
	}
	if st, _ := check(t, c, "liveness"); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness while postgres is down = %v, want SERVING", st)
	}

	raw := md.Get(HeaderHealth)
	if len(raw) != 1 {
		t.Fatalf("%s = %v, want one value", HeaderHealth, raw)
	}
	var body struct {
		Status       string
		Dependencies []struct {
			Name, State, Error, CheckedAt, Version string
			Required                               bool
		}
	}
	if err := json.Unmarshal([]byte(raw[0]), &body); err != nil {
		t.Fatalf("%s is not JSON: %v (%s)", HeaderHealth, err, raw[0])
	}
	d := body.Dependencies
	if body.Status != "down" || len(d) != 1 || d[0].Name != "postgres" || d[0].State != "down" || !d[0].Required ||
		d[0].Error != "error" || d[0].Version != "17.11" || d[0].CheckedAt == "" {
		t.Fatalf("health body = %s", raw[0])
	}
	for _, bad := range []string{"secret-dsn-text", "db.example.test"} {
		if contains(raw[0], bad) {
			t.Fatalf("health body carries %q: %s", bad, raw[0])
		}
	}
	if v := md.Get("sneakers-version"); len(v) != 1 {
		t.Fatalf("the version header is gone: %v", md)
	}

	down.Store(false)
	time.Sleep(2 * testTTL)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness after recovery = %v, want SERVING", st)
	}
}

func TestHealth_ReadinessWaitsForTheWorkloadKeySet(t *testing.T) {
	v := &switchedVerifier{}
	v.set(workloadauth.ErrUnavailable)
	checker := newTestChecker(t, WorkloadIdentity(v))
	c := healthClient(t, checker)

	st, md := check(t, c, "")
	if st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("readiness before the key set loads = %v, want NOT_SERVING", st)
	}
	raw := md.Get(HeaderHealth)
	if len(raw) != 1 || !strings.Contains(raw[0], `"name":"workload-identity"`) || !strings.Contains(raw[0], `"state":"down"`) {
		t.Fatalf("health body = %v", raw)
	}

	v.set(nil)
	time.Sleep(2 * testTTL)
	st, md = check(t, c, "")
	if st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness once the key set loads = %v, want SERVING", st)
	}
	if raw := md.Get(HeaderHealth); len(raw) != 1 || !strings.Contains(raw[0], `"name":"workload-identity"`) {
		t.Fatalf("health body = %v", raw)
	}
}

func TestHealth_LivenessCarriesNoHealthBody(t *testing.T) {
	c := healthClient(t, newTestChecker(t))
	if _, md := check(t, c, "liveness"); len(md.Get(HeaderHealth)) != 0 {
		t.Fatalf("liveness carried %v", md.Get(HeaderHealth))
	}
}

func TestHealth_UnknownServiceAndWatch(t *testing.T) {
	c := healthClient(t, newTestChecker(t))
	check(t, c, "") // wait for the server
	_, err := c.Check(context.Background(), &healthpb.HealthCheckRequest{Service: "nope"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown service: %v, want NotFound", err)
	}
	w, err := c.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	if resp, err := w.Recv(); err != nil || resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("watch: %v %v, want SERVING", resp.GetStatus(), err)
	}
}

func TestHealth_NilCheckerIsAlwaysReady(t *testing.T) {
	c := healthClient(t, nil)
	if st, _ := check(t, c, ""); st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("readiness without a checker = %v", st)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// Readiness reads a cache refreshed in the background: a probe never waits on
// a dependency check, however slow it is.
func TestHealth_ReadinessNeverWaitsOnACheck(t *testing.T) {
	var slow atomic.Bool
	checker := newTestChecker(t, health.Dependency{Name: "postgres", Required: true, Check: func(ctx context.Context) error {
		if slow.Load() {
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}})
	c := healthClient(t, checker)
	eventuallyServing(t, c)
	slow.Store(true)
	time.Sleep(2 * testTTL)
	for range 5 {
		start := time.Now()
		check(t, c, "")
		if d := time.Since(start); d > 200*time.Millisecond {
			t.Fatalf("readiness took %v during a slow check, want a cache read", d)
		}
	}
}

// eventuallyServing waits for the first background refresh to make the
// service ready.
func eventuallyServing(t *testing.T, c healthpb.HealthClient) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, _ := check(t, c, ""); st == healthpb.HealthCheckResponse_SERVING {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness never became SERVING")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
