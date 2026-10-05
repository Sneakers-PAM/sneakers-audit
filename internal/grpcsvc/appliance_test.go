// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"testing"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"google.golang.org/grpc/codes"
)

func applianceEvent(actorType string) *auditv1.RecordEventRequest {
	attrs := map[string]string{"host": "box-1.example.org"}
	if actorType != "" {
		attrs[AttrActorType] = actorType
	}
	return &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "appliance.shell.elevate", ActorUserId: "owner-made-up",
		Subject: "box-1", Attributes: attrs,
	}
}

func TestAppliance_RecordsApplianceAdminEventsIntoTheChain(t *testing.T) {
	f := newAuthFixture(t)
	if err := f.record(f.as(t, "vault")); err != nil {
		t.Fatal(err)
	}
	ctx := f.as(t, "appliance")
	for range 2 {
		if _, err := f.client.RecordEvent(ctx, applianceEvent(ActorTypeApplianceAdmin)); err != nil {
			t.Fatalf("appliance RecordEvent: %v", err)
		}
	}
	if err := f.record(f.as(t, "gateway")); err != nil {
		t.Fatal(err)
	}
	if n := f.length(t); n != 4 {
		t.Fatalf("chain length %d, want 4", n)
	}
	if got := f.s.store.(*memStore).records[1].GetAttributes()[AttrActorType]; got != ActorTypeApplianceAdmin {
		t.Fatalf("stored actor type %q, want %q", got, ActorTypeApplianceAdmin)
	}
	v, err := f.client.VerifyChain(f.as(t, "gateway"), &auditv1.VerifyChainRequest{})
	if err != nil || !v.GetValid() || v.GetLength() != 4 {
		t.Fatalf("VerifyChain after appliance events: %v %v", v, err)
	}
}

func TestAppliance_OtherActorTypesAreRefused(t *testing.T) {
	f := newAuthFixture(t)
	ctx := f.as(t, "appliance")
	for _, at := range []string{"", "user", "service", "Appliance-Admin"} {
		_, err := f.client.RecordEvent(ctx, applianceEvent(at))
		wantCode(t, "appliance RecordEvent with actor type "+at, err, codes.PermissionDenied)
	}
	if n := f.length(t); n != 0 {
		t.Fatalf("refused appliance events wrote %d records", n)
	}
}

func TestAppliance_OnlyTheApplianceMaySendTheApplianceAdminActorType(t *testing.T) {
	f := newAuthFixture(t)
	for _, c := range []string{"gateway", "vault", "sshbroker", "identity", "workflow", "migrate"} {
		_, err := f.client.RecordEvent(f.as(t, c), applianceEvent(ActorTypeApplianceAdmin))
		wantCode(t, c+" RecordEvent as appliance-admin", err, codes.PermissionDenied)
	}
	if n := f.length(t); n != 0 {
		t.Fatalf("refused events wrote %d records", n)
	}
}

func TestAppliance_EveryOtherRPCIsRefused(t *testing.T) {
	f := newAuthFixture(t)
	ctx := f.as(t, "appliance")
	_, err := f.client.ListRecords(ctx, &auditv1.ListRecordsRequest{})
	wantCode(t, "appliance ListRecords", err, codes.PermissionDenied)
	_, err = f.client.DistinctActions(ctx, &auditv1.DistinctActionsRequest{})
	wantCode(t, "appliance DistinctActions", err, codes.PermissionDenied)
	_, err = f.client.VerifyChain(ctx, &auditv1.VerifyChainRequest{})
	wantCode(t, "appliance VerifyChain", err, codes.PermissionDenied)
}
