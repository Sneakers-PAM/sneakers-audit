# sneakers-audit

The Sneakers-PAM audit trail: an append-only, hash-chained record of who did what.

## What it is

A gRPC service, `sneakers.audit.v1.AuditService`, that records audit events in a hash chain stored
in Postgres. Each record's hash covers the record and the previous record's hash, so an insert,
edit, delete or reorder anywhere in the trail is detectable with `VerifyChain`. It stores metadata
about actions, never secret material.

- **Hash chained:** every record links to the one before it.
- **Verifiable:** `VerifyChain` walks the whole trail and names the first bad record.
- **Append only:** records are never updated or deleted by the service.

## Run it

```bash
docker run -d --name audit-pg -e POSTGRES_USER=audit -e POSTGRES_DB=audit \
  -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:17-alpine
DATABASE_DSN='postgres://audit@localhost:5432/audit?sslmode=disable' go run ./cmd/audit
```

The container trusts local connections without a password, for development only. The service
applies its migrations at start and listens for gRPC on port 9090.

Run the tests, including the Postgres integration test:

```bash
AUDIT_PG_DSN='postgres://audit@localhost:5432/audit?sslmode=disable' go test ./...
```

## Where to look

- [docs/configuration.md](docs/configuration.md): environment variables.
- [docs/api.md](docs/api.md): the gRPC API and the hash chain.
- [docs/runbook.md](docs/runbook.md): operating the service.
- [proto/sneakers/audit/v1/audit.proto](proto/sneakers/audit/v1/audit.proto): the API definition.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
