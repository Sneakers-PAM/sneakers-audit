# Configuration

The service reads its configuration from the environment.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_DSN` | (required) | Postgres connection string used at runtime. Keep the password out of it and supply it with `PGPASSWORD` or a password file (`PGPASSFILE`). |
| `MIGRATE_DSN` | `DATABASE_DSN` | Connection string for running migrations. Set it when the runtime DSN goes through a transaction-pooling proxy: migrations need a direct session (advisory locks, prepared statements). |
| `MIGRATIONS_DIR` | `migrations` | Directory holding the migration files. The container image sets `/migrations`. |
| `GRPC_PORT` | `9090` | TCP port the gRPC server listens on (all interfaces). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OTLP gRPC endpoint for traces and metrics (plaintext). |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` or `disabled`. |
| `LOG_FORMAT` | `json` | `json`, `console` (or `pretty`), or `both` (JSON on stdout, console on stderr). |

## Service-to-service authentication

Every caller must present its workload identity: its projected Kubernetes ServiceAccount token
(audience `sneakers`) as `authorization: Bearer <token>`. The shared code is
`internal/workloadauth`, a byte-for-byte copy of the package in sneakers-vault at
`SNEAKERS_VAULT_REF` (`proto-refs.env`); CI checks the copy with `scripts/workloadauth-check.sh`.
The audit service makes no gRPC calls of its own, so it needs no token of its own.

| Variable | Default | Purpose |
|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | (required) | The cluster's ServiceAccount token issuer (`https://`). The token's `iss` must equal it. |
| `WORKLOAD_OIDC_JWKS_URL` | discovered | JWKS URL (`https://`); when unset it's read from the issuer's OpenID configuration. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM CA bundle for discovery and the JWKS fetch. |
| `WORKLOAD_OIDC_BEARER_FILE` | (unset) | Bearer token sent on discovery and the JWKS fetch, re-read on every fetch. |
| `WORKLOAD_AUDIENCE` | `sneakers` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | (required) | Comma list of `<namespace>/<serviceaccount>`: for audit, `<ns>/sneakers-gateway,<ns>/sneakers-vault,<ns>/sneakers-sshbroker,<ns>/sneakers-identity,<ns>/sneakers-workflow`. |
| `WORKLOAD_AUTH` | (unset) | `disabled` turns the check off, for local development only: every caller that reaches the port is trusted, and a warning is logged at start and every 5 minutes. No other value is accepted. |

Without `WORKLOAD_OIDC_ISSUER` the service refuses to start, unless `WORKLOAD_AUTH=disabled`;
setting both is refused too.

Example:

```bash
DATABASE_DSN='postgres://audit@db.example.org:5432/audit?sslmode=require'
PGPASSWORD=...   # from your secret store
GRPC_PORT=9090
OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector.example.org:4317
WORKLOAD_OIDC_ISSUER=https://kubernetes.default.svc.cluster.local
WORKLOAD_OIDC_CA_FILE=/var/run/secrets/tokens/ca.crt
WORKLOAD_OIDC_BEARER_FILE=/var/run/secrets/tokens/token
WORKLOAD_AUDIENCE=sneakers
WORKLOAD_ALLOWED_SERVICEACCOUNTS=sneakers/sneakers-gateway,sneakers/sneakers-vault,sneakers/sneakers-sshbroker,sneakers/sneakers-identity,sneakers/sneakers-workflow
LOG_LEVEL=info
```
