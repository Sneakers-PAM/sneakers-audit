// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	stdlog "log"
	"net"
	"os"
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
	postgres "github.com/Bugs5382/go-postgres"
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-audit/internal/server"
	"github.com/Sneakers-PAM/sneakers-audit/internal/telemetry"
	otelapi "go.opentelemetry.io/otel"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
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
	spans  []*coltracepb.ExportTraceServiceRequest
	points []*colmetricpb.ExportMetricsServiceRequest
}

type traceCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	c *collector
}

func (t traceCollector) Export(_ context.Context, req *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	if t.c.reject {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.c.spans = append(t.c.spans, req)
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type metricCollector struct {
	colmetricpb.UnimplementedMetricsServiceServer
	c *collector
}

func (m metricCollector) Export(_ context.Context, req *colmetricpb.ExportMetricsServiceRequest) (*colmetricpb.ExportMetricsServiceResponse, error) {
	if m.c.reject {
		return nil, status.Error(codes.PermissionDenied, "refused")
	}
	m.c.mu.Lock()
	defer m.c.mu.Unlock()
	m.c.points = append(m.c.points, req)
	return &colmetricpb.ExportMetricsServiceResponse{}, nil
}

// everything is all three signals as text, for canary checks.
func (c *collector) everything() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	for _, r := range c.reqs {
		b.WriteString(r.String())
	}
	for _, r := range c.spans {
		b.WriteString(r.String())
	}
	for _, r := range c.points {
		b.WriteString(r.String())
	}
	return b.String()
}

func (c *collector) spanNames() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var names []string
	for _, r := range c.spans {
		for _, rs := range r.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				for _, s := range ss.GetSpans() {
					names = append(names, s.GetName())
				}
			}
		}
	}
	return names
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
	coltracepb.RegisterTraceServiceServer(srv, traceCollector{c: c})
	colmetricpb.RegisterMetricsServiceServer(srv, metricCollector{c: c})
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

// stubAudit stands in for the real handler, so a panic or an error can carry
// the audit entry it was given.
type stubAudit struct {
	auditv1.UnimplementedAuditServiceServer
}

func (stubAudit) RecordEvent(_ context.Context, req *auditv1.RecordEventRequest) (*auditv1.RecordEventResponse, error) {
	if req.GetAction() == "panic" {
		panic(fmt.Errorf("entry %s", req.GetSubject()))
	}
	return nil, status.Error(codes.InvalidArgument, req.GetSubject())
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// A canary on every path, sent to the service's real gRPC wiring: the panic
// path carries an audit entry into the span, the error path into the status,
// and the method, baggage, trace state and resource come from outside.
func TestCanaryReachesNoSignal(t *testing.T) {
	jsonLogs(t)
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.name="+canary)
	vals := map[string]string{telemetry.EnvLogsEnabled: "true"}
	lg := log.NewLoggerWithOptions("audit", log.WithOutput(telemetry.LogOutput(env(vals), &bytes.Buffer{})))

	c := &collector{}
	shutdown, err := otel.InitWithOptions(context.Background(), "audit", startCollector(t, c), telemetry.Options(env(vals))...)
	if err != nil {
		t.Fatal(err)
	}
	if fields := otelapi.GetTextMapPropagator().Fields(); slices.Contains(fields, "baggage") {
		t.Fatalf("propagator carries baggage: %v", fields)
	}

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() {
		stopped <- server.RunWithLogger(ctx, port, lg, func(gs *grpc.Server) {
			auditv1.RegisterAuditServiceServer(gs, stubAudit{})
		})
	}()

	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	call := metadata.AppendToOutgoingContext(context.Background(),
		"traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"tracestate", "vendor="+canary,
		"baggage", "member="+canary)
	client := auditv1.NewAuditServiceClient(conn)
	waitCtx, waitCancel := context.WithTimeout(call, 5*time.Second)
	defer waitCancel()
	for _, action := range []string{"panic", "error"} {
		_, err := client.RecordEvent(waitCtx, &auditv1.RecordEventRequest{Action: action, Subject: canary},
			grpc.WaitForReady(true))
		if status.Code(err) == codes.Unavailable || err == nil {
			t.Fatalf("%s: %v", action, err)
		}
	}
	_ = conn.Invoke(waitCtx, "/sneakers.audit.v1."+canary+"/Method", &auditv1.RecordEventRequest{}, &auditv1.RecordEventResponse{})

	cancel()
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	got := c.everything()
	if strings.Contains(got, canary) {
		t.Fatalf("canary reached the collector: %s", got)
	}
	if strings.Contains(got, "exception") {
		t.Fatalf("an exception event reached the collector: %s", got)
	}
	const method = "sneakers.audit.v1.AuditService/RecordEvent"
	if !slices.Contains(c.spanNames(), method) {
		t.Fatalf("no span for the real method: %v", c.spanNames())
	}
	for _, want := range []string{`"rpc.method"`, `"rpc.response.status_code"`, method} {
		if !strings.Contains(got, want) {
			t.Errorf("collector is missing %s", want)
		}
	}
	for _, unwanted := range []string{"server.address", "server.port", "network.peer", "client.address", "url."} {
		if strings.Contains(got, unwanted) {
			t.Errorf("collector received %s", unwanted)
		}
	}
}

// SQL and a database error both carry the canary. Needs AUDIT_PG_DSN.
func TestPostgresSpansLeaveNoSQL(t *testing.T) {
	dsn := os.Getenv("AUDIT_PG_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_PG_DSN to run the database span test")
	}
	c := &collector{}
	shutdown, err := otel.InitWithOptions(context.Background(), "audit", startCollector(t, c), telemetry.Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	// otelpgx records a query only under a span, as a request gives it.
	ctx, span := otelapi.Tracer("test").Start(context.Background(), "request")
	db, err := postgres.New(ctx, dsn, telemetry.PostgresTracing())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var one string
	if err := db.Querier().QueryRow(ctx, "SELECT '"+canary+"'").Scan(&one); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Querier().Exec(ctx, "SELECT 1 FROM \""+canary+"\""); err == nil {
		t.Fatal("query on a missing table worked")
	}
	span.End()
	if err := shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	if got := c.everything(); strings.Contains(got, canary) {
		t.Fatalf("canary reached the collector: %s", got)
	}
	if !slices.Contains(c.spanNames(), "query SELECT") {
		t.Fatalf("no query span: %v", c.spanNames())
	}
}

func TestExportErrorsPrintOnlyTheCode(t *testing.T) {
	var out bytes.Buffer
	stdlog.SetOutput(&out)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })

	shutdown, err := otel.InitWithOptions(context.Background(), "audit", startCollector(t, &collector{}), telemetry.Options(env(nil))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	otelapi.Handle(errors.New("dial collector.example.org:4317: authorization=" + canary))

	if strings.Contains(out.String(), canary) || strings.Contains(out.String(), "collector.example.org") {
		t.Fatalf("export error leaked: %s", out.String())
	}
}
