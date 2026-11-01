// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-audit/internal/server"
	"github.com/Sneakers-PAM/sneakers-audit/internal/telemetry"
	otelapi "go.opentelemetry.io/otel"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const canary = "CANARY-7f3a"

func env(vals map[string]string) func(string) string {
	return func(k string) string { return vals[k] }
}

// collector is an in-process OTLP logs collector. It refuses every export
// while reject is set.
type collector struct {
	collogspb.UnimplementedLogsServiceServer
	reject bool
	mu     sync.Mutex
	reqs   []*collogspb.ExportLogsServiceRequest
}

func (c *collector) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if c.reject {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reqs = append(c.reqs, req)
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (c *collector) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, r := range c.reqs {
		b.WriteString(r.String())
	}
	return b.String()
}

func startCollector(t *testing.T, c *collector) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(srv, c)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return "http://" + lis.Addr().String()
}

func jsonLogs(t *testing.T) {
	t.Helper()
	t.Setenv("LOG_LEVEL", "info")
	t.Setenv("LOG_FORMAT", "json")
}

func TestUnsetEnvLeavesStdoutAlone(t *testing.T) {
	var out bytes.Buffer
	if got := telemetry.LogOutput(env(nil), &out); got != &out {
		t.Fatalf("LogOutput = %T, want stdout itself", got)
	}
	for _, v := range []string{"1", "TRUE", "yes", "false"} {
		if got := telemetry.LogOutput(env(map[string]string{telemetry.EnvLogsEnabled: v}), &out); got != &out {
			t.Fatalf("%s=%s turned logs on", telemetry.EnvLogsEnabled, v)
		}
	}
}

func TestUnsetEnvExportsNoLogs(t *testing.T) {
	c := &collector{}
	shutdown, err := otel.InitWithOptions(context.Background(), "audit", startCollector(t, c), telemetry.Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	if otel.ExportState().Logs.Disabled == "" {
		t.Fatal("logs are on with the env unset")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLogsEnabledKeepsStdoutAndFiltersExport(t *testing.T) {
	jsonLogs(t)
	vals := map[string]string{telemetry.EnvLogsEnabled: "true"}
	var out bytes.Buffer
	lg := log.NewLoggerWithOptions("audit", log.WithOutput(telemetry.LogOutput(env(vals), &out)))

	// Written before Init: the writer must drop it without complaint.
	lg.Info("before init")

	c := &collector{}
	shutdown, err := otel.InitWithOptions(context.Background(), "audit", startCollector(t, c), telemetry.Options(env(vals))...)
	if err != nil {
		t.Fatal(err)
	}

	lg.Info("canary line token snk_abc123DEF", log.F("method", "/sneakers.audit.v1.AuditService/RecordEvent"),
		log.F("error", canary), log.F("stack", canary), log.F("actor", canary), log.F("target", canary),
		log.F("metadata", canary), log.F("entry", canary), log.F("payload", canary))
	lg.Debug("below the floor " + canary)

	// A panic while handling a RecordEvent can carry an audit entry in its value.
	_, _ = server.RecoveryUnaryInterceptor(lg)(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/sneakers.audit.v1.AuditService/RecordEvent"},
		func(context.Context, any) (any, error) { panic("entry " + canary) })

	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := c.received()
	if !strings.Contains(got, "canary line") || !strings.Contains(got, "RecordEvent") {
		t.Fatalf("collector missed the allowed record: %s", got)
	}
	if !strings.Contains(got, "recovered from panic") {
		t.Fatalf("collector missed the panic record: %s", got)
	}
	if strings.Contains(got, canary) {
		t.Fatalf("canary reached the collector: %s", got)
	}
	if strings.Contains(got, "snk_abc123DEF") {
		t.Fatalf("token reached the collector: %s", got)
	}
	if !strings.Contains(out.String(), canary) || !strings.Contains(out.String(), "snk_abc123DEF") {
		t.Fatalf("stdout lost what it logs today: %s", out.String())
	}
}

// Audit entries must have no way into the log path, so the packages that hold
// them may not import a logger at all.
func TestAuditEntryPackagesHaveNoLogger(t *testing.T) {
	banned := []string{"github.com/Bugs5382/go-log", "github.com/rs/zerolog", "log", "log/slog"}
	for _, dir := range []string{"../grpcsvc", "../chain"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil || len(files) == 0 {
			t.Fatalf("%s: %v, %d files", dir, err, len(files))
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range parsed.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if slices.Contains(banned, p) {
					t.Errorf("%s imports %s", f, p)
				}
			}
		}
	}
}

func TestAllowListHoldsNoFreeText(t *testing.T) {
	for _, name := range []string{
		"error", "panic", "stack", "issuer", "audience", "allowed_serviceaccounts",
		"caller", "service_account", "reason", "jwks_url", "target", "outcome",
	} {
		if slices.Contains(telemetry.AllowedLogFields(), name) {
			t.Errorf("%q must stay off the allow-list", name)
		}
	}
}

func TestDependencyOnlyWithEndpoint(t *testing.T) {
	for _, ep := range []string{"", "   "} {
		if deps := telemetry.Dependencies(ep, env(nil)); len(deps) != 0 {
			t.Fatalf("endpoint %q: got %d dependencies", ep, len(deps))
		}
	}
	deps := telemetry.Dependencies("https://collector.example.org:4317", env(nil))
	if len(deps) != 1 || deps[0].Name != "otlp" || deps[0].Required {
		t.Fatalf("got %+v, want one optional otlp dependency", deps)
	}
}

func TestFailingCollectorDegradesAndStaysReady(t *testing.T) {
	jsonLogs(t)
	vals := map[string]string{telemetry.EnvLogsEnabled: "true"}
	lg := log.NewLoggerWithOptions("audit", log.WithOutput(telemetry.LogOutput(env(vals), &bytes.Buffer{})))
	endpoint := startCollector(t, &collector{reject: true})
	shutdown, err := otel.InitWithOptions(context.Background(), "audit", endpoint, telemetry.Options(env(vals))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	checker, err := server.NewChecker(log.Nop(), telemetry.Dependencies(endpoint, env(vals)), health.WithTTL(10*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go checker.Run(ctx)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		lg.Info("keeps the exporter busy")
		r := checker.Report(ctx)
		if r.Status == health.StateDegraded {
			if !r.Ready || r.Dependencies[0].Name != "otlp" || r.Dependencies[0].State != health.StateDegraded {
				t.Fatalf("report = %+v", r)
			}
			if strings.Contains(r.Dependencies[0].Error, "127.0.0.1") {
				t.Fatalf("report names the endpoint: %q", r.Dependencies[0].Error)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("never degraded: %+v", checker.Report(ctx))
}

func TestExportErrorsLeaveOutEndpointAndHeaders(t *testing.T) {
	jsonLogs(t)
	var out bytes.Buffer
	telemetry.SetErrorHandler(log.NewLoggerWithOptions("audit", log.WithOutput(&out)))
	t.Cleanup(func() { telemetry.SetErrorHandler(log.Nop()) })

	otelapi.Handle(errors.New("dial collector.example.org:4317: authorization=" + canary))

	if strings.Contains(out.String(), canary) || strings.Contains(out.String(), "collector.example.org") {
		t.Fatalf("export error leaked: %s", out.String())
	}
	if !strings.Contains(out.String(), `"error_class":"error"`) {
		t.Fatalf("export error not logged: %s", out.String())
	}
}
