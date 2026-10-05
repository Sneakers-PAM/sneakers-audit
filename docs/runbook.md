# Runbook

## Start up

At start the service:

1. reads its configuration (it exits if `DATABASE_DSN` is missing);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. checks the service-to-service authentication settings: it exits when `WORKLOAD_OIDC_ISSUER` is
   unset, unless `WORKLOAD_AUTH=disabled`, which it then warns about every 5 minutes;
4. applies the migrations in `MIGRATIONS_DIR` using `MIGRATE_DSN` (or `DATABASE_DSN`);
5. connects to Postgres and serves gRPC on `GRPC_PORT`.

Any failure in these steps is logged at fatal level and the process exits non-zero.

## Refused callers

A refused call is logged at warn as `call refused`, with the method, the caller and the reason;
it is never written to the chain. `Unauthenticated` means no token, a bad one, or a service
account missing from `WORKLOAD_ALLOWED_SERVICEACCOUNTS`; `PermissionDenied` means the caller is
known but not allowed on that method. `Unavailable` with `workload verifier unavailable` means no
JWKS key set has loaded yet: check that the issuer or `WORKLOAD_OIDC_JWKS_URL` is reachable.

## Health

Use the standard gRPC health check. It needs no workload token, so a kubelet `grpc` probe works
as is, and so does a client that knows the health API without asking the server:

```bash
grpc_health_probe -addr localhost:9090                    # readiness
grpc_health_probe -addr localhost:9090 -service liveness  # liveness
```

Readiness fails while PostgreSQL doesn't answer, and recovers on its own within about 5 seconds
of it answering again. Liveness only shows that the process answers, so a database outage takes
audit out of its Service without restarting it. The kubelet's liveness probe has to ask for the
`liveness` service to get that; the probes are set in sneakers-release's chart.

| Dependency | Required | Why |
|---|---|---|
| PostgreSQL | yes | Every RPC reads or appends to the trail in `audit_records`; without it audit can't answer any of them. |

Audit calls no other service and uses no broker. The `sneakers-health` header (see
[api.md](api.md)) shows each dependency's state, error class and last check. A state change logs
one line: `health: dependency down` at warn, `health: dependency recovered` at info, with the
dependency, whether it's required and the error class; never the DSN or the error text.

To see which build is running, ask for the response headers (`grpcurl -v`): the answer carries
`sneakers-version`, `sneakers-commit` and, once the database answered, `sneakers-dep-postgres`
(a `postgres version unknown` warning at start means it didn't). The image build stamps the
version and commit from its `VERSION` and `COMMIT` build arguments:

```bash
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

Server reflection, which grpcurl uses to find a method, is not on any caller's allow-list, so
with authentication on it is refused. Give grpcurl the protos instead (`-import-path proto
-proto <file>`), or run locally with `WORKLOAD_AUTH=disabled`, where reflection works as before.

## Checking the trail

```bash
token="$(kubectl -n sneakers create token sneakers-gateway --audience sneakers --duration 10m)"
grpcurl -plaintext -import-path proto -proto sneakers/audit/v1/audit.proto \
  -H "authorization: Bearer $token" localhost:9090 sneakers.audit.v1.AuditService/VerifyChain
```

Run it from a checkout of this repo. Only the gateway may call it, so the call carries a
short-lived gateway token. Locally, with `WORKLOAD_AUTH=disabled`, leave the header out.

A result with `"valid": false` means a record was changed, removed or reordered outside the
service. `broken_at_seq` names the first bad record; every record after it fails too, because each
hash covers the one before. Treat this as a security incident: keep the database as it is, take a
copy for investigation, and compare the records around `broken_at_seq` with your backups.

## Shutdown

On SIGINT or SIGTERM the server stops accepting new calls and waits up to 10 seconds for in-flight
calls to finish before stopping.

## Panics

A panic in a handler is recovered: the caller gets a generic `Internal` error, and the panic value
and stack go only to the log (at error level) and to the active trace span.

## Database

The schema is one table, `audit_records`, keyed by `seq`, with indexes on the actor and the subject.
The service only inserts and reads. Back the database up like any other system of record; a restore
keeps the chain valid as long as it restores whole.
