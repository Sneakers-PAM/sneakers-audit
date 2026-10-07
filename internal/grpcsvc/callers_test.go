// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"maps"
	"net"
	"testing"

	log "github.com/Bugs5382/go-log"
	workloadauth "github.com/Bugs5382/go-workload-identity"
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-audit/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// TestCallerPolicyPerMethod pins the allow-list of every audit method:
// RecordEvent takes the five writers, the migrate Job and the appliance, each
// as itself;
// VerifyChain takes the gateway and migrate; the other reads behind the audit
// viewer take the gateway only.
func TestCallerPolicyPerMethod(t *testing.T) {
	self := workloadauth.Self
	writers := map[string]workloadauth.Access{
		CallerGateway: self, CallerVault: self, CallerSSHBroker: self, CallerIdentity: self, CallerWorkflow: self,
		CallerMigrate: self, CallerAppliance: self,
	}
	want := map[string]map[string]workloadauth.Access{
		auditv1.AuditService_RecordEvent_FullMethodName:     writers,
		auditv1.AuditService_ListRecords_FullMethodName:     {CallerGateway: self},
		auditv1.AuditService_DistinctActions_FullMethodName: {CallerGateway: self},
		auditv1.AuditService_VerifyChain_FullMethodName:     {CallerGateway: self, CallerMigrate: self},
	}
	p := CallerPolicy()
	desc := auditv1.AuditService_ServiceDesc
	if len(desc.Streams) != 0 {
		t.Fatalf("audit has streaming methods now; give them an allow-list: %v", desc.Streams)
	}
	if len(p) != len(desc.Methods) || len(want) != len(desc.Methods) {
		t.Fatalf("policy covers %d methods, the test %d, the service has %d", len(p), len(want), len(desc.Methods))
	}
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		if got := p[full]; !maps.Equal(got, want[full]) {
			t.Errorf("%s: allow-list %v, want %v", md.MethodName, got, want[full])
		}
		for _, c := range []string{"mcp", "connector", "notify", "audit"} {
			if _, ok := p.Lookup(full, c); ok {
				t.Errorf("%s: %s must not be allowed", md.MethodName, c)
			}
		}
	}
}

const authNS = "sneakers"

type authFixture struct {
	s      *Server
	iss    *testIssuer
	client auditv1.AuditServiceClient
	health healthpb.HealthClient
}

// newAuthFixture serves the audit service behind the real workload-auth
// interceptors and the real verifier, over a gRPC connection. The verifier's
// service-account list is the chart's for audit while the migration Job runs,
// plus mcp, so mcp shows what a listed caller outside the method policy gets.
func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	iss := newTestIssuer(t)
	var allowed []string
	for _, c := range []string{"gateway", "vault", "sshbroker", "identity", "workflow", "migrate", "appliance", "mcp"} {
		allowed = append(allowed, authNS+"/sneakers-"+c)
	}
	v, err := workloadauth.NewVerifier(workloadauth.Config{
		Issuer: iss.URL, CAFile: iss.CAFile, AllowedServiceAccounts: allowed,
		Audience: server.WorkloadAudience, ServiceAccountPrefix: server.WorkloadServiceAccountPrefix,
	}, log.Nop())
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := New()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(v, CallerPolicy(), log.Nop())),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, CallerPolicy(), log.Nop())),
	)
	RegisterServer(gs, s)
	healthpb.RegisterHealthServer(gs, health.NewServer())
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &authFixture{s: s, iss: iss, client: auditv1.NewAuditServiceClient(conn), health: healthpb.NewHealthClient(conn)}
}

// as returns a context carrying a valid token for the service account
// sneakers-<caller>.
func (f *authFixture) as(t *testing.T, caller string) context.Context {
	t.Helper()
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+f.iss.token(t, authNS, "sneakers-"+caller))
}

func (f *authFixture) record(ctx context.Context) error {
	_, err := f.client.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "secret.reveal", ActorUserId: "user-made-up", Subject: "secret-1",
	})
	return err
}

func (f *authFixture) length(t *testing.T) int {
	t.Helper()
	return len(f.s.store.(*memStore).records)
}

func wantCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("%s: %v, want %s", what, err, want)
	}
}

func TestCallerAuth_UnlistedPodIsRefusedEvenWithAValidToken(t *testing.T) {
	f := newAuthFixture(t)
	// A correctly signed token for a service account that isn't on the list.
	wantCode(t, "connector RecordEvent", f.record(f.as(t, "connector")), codes.Unauthenticated)
	_, err := f.client.VerifyChain(f.as(t, "notify"), &auditv1.VerifyChainRequest{})
	wantCode(t, "notify VerifyChain", err, codes.Unauthenticated)
	// On the list, but in no method's policy.
	wantCode(t, "mcp RecordEvent", f.record(f.as(t, "mcp")), codes.PermissionDenied)
	_, err = f.client.ListRecords(f.as(t, "mcp"), &auditv1.ListRecordsRequest{})
	wantCode(t, "mcp ListRecords", err, codes.PermissionDenied)
	if n := f.length(t); n != 0 {
		t.Fatalf("refused calls wrote %d records; a refusal must never reach the chain", n)
	}
}

func TestCallerAuth_NoTokenIsUnauthenticated(t *testing.T) {
	f := newAuthFixture(t)
	wantCode(t, "no token", f.record(context.Background()), codes.Unauthenticated)
	bad := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer not-a-token")
	wantCode(t, "bad token", f.record(bad), codes.Unauthenticated)
	if n := f.length(t); n != 0 {
		t.Fatalf("refused calls wrote %d records", n)
	}
}

func TestCallerAuth_EveryWriterRecordsAsItself(t *testing.T) {
	f := newAuthFixture(t)
	writers := []string{"gateway", "vault", "sshbroker", "identity", "workflow"}
	for _, c := range writers {
		if err := f.record(f.as(t, c)); err != nil {
			t.Fatalf("%s RecordEvent: %v", c, err)
		}
	}
	if n := f.length(t); n != len(writers) {
		t.Fatalf("chain length %d, want %d", n, len(writers))
	}
}

func TestCallerAuth_ReadsAreForTheGatewayOnly(t *testing.T) {
	f := newAuthFixture(t)
	if err := f.record(f.as(t, "vault")); err != nil {
		t.Fatal(err)
	}
	gw := f.as(t, "gateway")
	if _, err := f.client.ListRecords(gw, &auditv1.ListRecordsRequest{}); err != nil {
		t.Fatalf("gateway ListRecords: %v", err)
	}
	if _, err := f.client.DistinctActions(gw, &auditv1.DistinctActionsRequest{}); err != nil {
		t.Fatalf("gateway DistinctActions: %v", err)
	}
	if v, err := f.client.VerifyChain(gw, &auditv1.VerifyChainRequest{}); err != nil || !v.GetValid() || v.GetLength() != 1 {
		t.Fatalf("gateway VerifyChain: %v %v", v, err)
	}
	for _, c := range []string{"vault", "sshbroker", "identity", "workflow"} {
		ctx := f.as(t, c)
		_, err := f.client.ListRecords(ctx, &auditv1.ListRecordsRequest{})
		wantCode(t, c+" ListRecords", err, codes.PermissionDenied)
		_, err = f.client.DistinctActions(ctx, &auditv1.DistinctActionsRequest{})
		wantCode(t, c+" DistinctActions", err, codes.PermissionDenied)
		_, err = f.client.VerifyChain(ctx, &auditv1.VerifyChainRequest{})
		wantCode(t, c+" VerifyChain", err, codes.PermissionDenied)
	}
}

func TestCallerAuth_MigrateRecordsAndVerifiesOnly(t *testing.T) {
	f := newAuthFixture(t)
	m := f.as(t, "migrate")
	if err := f.record(m); err != nil {
		t.Fatalf("migrate RecordEvent: %v", err)
	}
	if v, err := f.client.VerifyChain(m, &auditv1.VerifyChainRequest{}); err != nil || !v.GetValid() || v.GetLength() != 1 {
		t.Fatalf("migrate VerifyChain: %v %v", v, err)
	}
	_, err := f.client.ListRecords(m, &auditv1.ListRecordsRequest{})
	wantCode(t, "migrate ListRecords", err, codes.PermissionDenied)
	_, err = f.client.DistinctActions(m, &auditv1.DistinctActionsRequest{})
	wantCode(t, "migrate DistinctActions", err, codes.PermissionDenied)
	if got := f.s.store.(*memStore).records[0].GetActorUserId(); got != "user-made-up" {
		t.Fatalf("migrate's actor_user_id stored as %q, want it as sent", got)
	}
}

func TestCallerPolicy_MigrateOnlyOnRecordAndVerify(t *testing.T) {
	p := CallerPolicy()
	allowed := map[string]bool{
		auditv1.AuditService_RecordEvent_FullMethodName: true,
		auditv1.AuditService_VerifyChain_FullMethodName: true,
	}
	desc := auditv1.AuditService_ServiceDesc
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		a, ok := p.Lookup(full, CallerMigrate)
		switch {
		case allowed[full] && (!ok || a != workloadauth.Self):
			t.Errorf("%s: migrate access %v (listed %v), want self", md.MethodName, a, ok)
		case !allowed[full] && ok:
			t.Errorf("%s: migrate must not be allowed", md.MethodName)
		}
	}
}

func TestCallerAuth_HealthNeedsNoToken(t *testing.T) {
	f := newAuthFixture(t)
	if _, err := f.health.Check(context.Background(), &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("health without a token: %v", err)
	}
}
