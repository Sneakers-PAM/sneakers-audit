// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	auditv1 "github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1"
	"github.com/Sneakers-PAM/sneakers-audit/internal/workloadauth"
)

// Caller names, from the service accounts sneakers-<name>.
const (
	CallerGateway   = "gateway"
	CallerVault     = "vault"
	CallerSSHBroker = "sshbroker"
	CallerIdentity  = "identity"
	CallerWorkflow  = "workflow"
	CallerMigrate   = "migrate"
)

// writers record events, each as itself: the actor_user_id they send is the
// user the event is about, which the audit service stores as given. migrate is
// the migration Job, listed in WORKLOAD_ALLOWED_SERVICEACCOUNTS only while it runs.
var writers = []string{CallerGateway, CallerVault, CallerSSHBroker, CallerIdentity, CallerWorkflow, CallerMigrate}

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
