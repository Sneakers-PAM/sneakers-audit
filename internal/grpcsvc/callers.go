// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-audit/internal/workloadauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Caller names, from the service accounts sneakers-<name>.
const (
	CallerGateway   = "gateway"
	CallerVault     = "vault"
	CallerSSHBroker = "sshbroker"
	CallerIdentity  = "identity"
	CallerWorkflow  = "workflow"
	CallerMigrate   = "migrate"
	CallerAppliance = "appliance"
)

// AttrActorType is the event attribute that names the kind of actor, and
// ActorTypeApplianceAdmin is the one value the appliance may send: its OS
// audit entries are about the box's owners, not product users.
const (
	AttrActorType           = "actor_type"
	ActorTypeApplianceAdmin = "appliance-admin"
)

// writers record events, each as itself: the actor_user_id they send is the
// user the event is about, which the audit service stores as given. migrate is
// the migration Job, listed in WORKLOAD_ALLOWED_SERVICEACCOUNTS only while it runs.
// appliance forwards the appliance's OS audit entries, and only those
// (checkActorType).
var writers = []string{CallerGateway, CallerVault, CallerSSHBroker, CallerIdentity, CallerWorkflow, CallerMigrate, CallerAppliance}

// readMethods serve the gateway's audit viewer.
var readMethods = []string{
	auditv1.AuditService_ListRecords_FullMethodName,
	auditv1.AuditService_DistinctActions_FullMethodName,
	auditv1.AuditService_VerifyChain_FullMethodName,
}

// CallerPolicy is the audit service's per-method allow-list: RecordEvent for
// the writers, the reads for the gateway, and VerifyChain for migrate too, so
// the Job can check the chain it wrote. Anything else is refused.
func CallerPolicy() workloadauth.Policy {
	record := map[string]workloadauth.Access{}
	for _, c := range writers {
		record[c] = workloadauth.Self
	}
	p := workloadauth.Policy{auditv1.AuditService_RecordEvent_FullMethodName: record}
	for _, m := range readMethods {
		p[m] = map[string]workloadauth.Access{CallerGateway: workloadauth.Self}
	}
	p[auditv1.AuditService_VerifyChain_FullMethodName][CallerMigrate] = workloadauth.Self
	return p
}

// checkActorType ties the appliance-admin actor type to the appliance caller:
// the appliance may record only appliance-admin events, and no other caller
// may record one. Without a grant (workload auth turned off for local
// development) there is no caller to check.
func checkActorType(ctx context.Context, req *auditv1.RecordEventRequest) error {
	g, ok := workloadauth.GrantFromContext(ctx)
	if !ok {
		return nil
	}
	isAppliance := g.Caller.Name == CallerAppliance
	isApplianceAdmin := req.GetAttributes()[AttrActorType] == ActorTypeApplianceAdmin
	switch {
	case isAppliance && !isApplianceAdmin:
		return status.Errorf(codes.PermissionDenied, "caller %s may record only %s=%s events", CallerAppliance, AttrActorType, ActorTypeApplianceAdmin)
	case !isAppliance && isApplianceAdmin:
		return status.Errorf(codes.PermissionDenied, "only caller %s may record %s=%s events", CallerAppliance, AttrActorType, ActorTypeApplianceAdmin)
	}
	return nil
}
