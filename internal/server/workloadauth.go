// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"strings"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-audit/internal/workloadauth"
	"google.golang.org/grpc"
)

// WorkloadAuth returns the server options that authenticate every caller
// against policy (see internal/workloadauth). It fails closed: with no
// WORKLOAD_OIDC_ISSUER it returns an error, unless WORKLOAD_AUTH=disabled, in
// which case it returns no options and warns now and every 5 minutes.
//
// Refusals are logged by the interceptors only. They are never recorded in
// the audit chain itself, so a caller that can't authenticate can't grow it.
func WorkloadAuth(ctx context.Context, getenv func(string) string, policy workloadauth.Policy, lg log.Logger) ([]grpc.ServerOption, error) {
	cfg, enabled, err := workloadauth.ServerConfigFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	if !enabled {
		go workloadauth.WarnDisabled(ctx, lg, workloadauth.DisabledWarnInterval)
		return nil, nil
	}
	v, err := workloadauth.NewVerifier(cfg, lg)
	if err != nil {
		return nil, err
	}
	go v.Run(ctx)
	lg.Info("service-to-service authentication on",
		log.F("issuer", cfg.Issuer), log.F("audience", cfg.Audience),
		log.F("jwks_override", cfg.JWKSURL != ""), log.F("ca_file", cfg.CAFile != ""), log.F("bearer_file", cfg.BearerFile != ""),
		log.F("allowed_serviceaccounts", strings.Join(cfg.AllowedServiceAccounts, ",")))
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(v, policy, lg)),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(v, policy, lg)),
	}, nil
}
