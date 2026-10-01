# Runbook

## Start up

At start the service:

1. reads its configuration (it exits if `DATABASE_DSN` is missing);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. applies the migrations in `MIGRATIONS_DIR` using `MIGRATE_DSN` (or `DATABASE_DSN`);
4. connects to Postgres and serves gRPC on `GRPC_PORT`.

Any failure in these steps is logged at fatal level and the process exits non-zero.

## Health

Use the standard gRPC health check:

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

## Checking the trail

```bash
grpcurl -plaintext localhost:9090 sneakers.audit.v1.AuditService/VerifyChain
```

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
