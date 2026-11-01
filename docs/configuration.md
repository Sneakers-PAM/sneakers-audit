# Configuration

The service reads its configuration from the environment.

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_DSN` | (required) | Postgres connection string used at runtime. Keep the password out of it and supply it with `PGPASSWORD` or a password file (`PGPASSFILE`). |
| `MIGRATE_DSN` | `DATABASE_DSN` | Connection string for running migrations. Set it when the runtime DSN goes through a transaction-pooling proxy: migrations need a direct session (advisory locks, prepared statements). |
| `MIGRATIONS_DIR` | `migrations` | Directory holding the migration files. The container image sets `/migrations`. |
| `GRPC_PORT` | `9090` | TCP port the gRPC server listens on (all interfaces). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | (none) | OTLP gRPC collector for traces and metrics, as a URL: `http://collector:4317` for plaintext, `https://collector:4317` for TLS. A bare `host:port` still connects as plaintext, but the OpenTelemetry SDK, which reads this variable too, logs `parse url` errors at start. Any other scheme stops the service at start. Unset or empty runs without a collector: no export, no error log. |
| `OTLP_INSECURE_SKIP_VERIFY` | (unset) | `true` turns off the collector's certificate check on an `https` endpoint. The connection stays encrypted but the collector isn't authenticated, so logs stay off while it's on; traces and metrics keep flowing. Any other value is off. |
| `OTLP_LOGS_ENABLED` | (unset) | `true` also exports logs to the collector, on the same endpoint. Any other value is off. Stdout doesn't change. See [Log export](#log-export). |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` or `disabled`. |
| `LOG_FORMAT` | `json` | `json`, `console` (or `pretty`), or `both` (JSON on stdout, console on stderr). |

## Log export

Export is default-deny. A record carries its time, level, service, message and trace ids, plus only
the fields listed in `internal/telemetry` (ids, counts, durations, classes, states and short enums).
Error text, panic values and stacks, URLs, caller names and refusal reasons stay on stdout and never
leave. A new log field exports nothing until it's added to that list. Debug and trace lines never
leave, whatever `LOG_LEVEL` says, and `snk_` tokens are redacted from what does. Only JSON lines are
read, so `LOG_FORMAT=console` exports no logs.

Audit entries are never logged, so they can't reach this path: the packages that hold them import no
logger, and a test keeps it that way.

## Health: the `otlp` dependency

With an endpoint set, the readiness body and the gRPC health report list an optional `otlp`
dependency. It shows `degraded` when the last export error is newer than the last success on traces
or metrics, or on logs when logs are on. It never fails readiness, and its error is a class, never
the exporter's text. Export errors are logged the same way, as `otel export failed` with an
`error_class`, leaving out the endpoint and headers. Without an endpoint it isn't listed.

## Service-to-service authentication

Every caller must present its workload identity: its projected Kubernetes ServiceAccount token
(audience `sneakers`) as `authorization: Bearer <token>`. The code is the owner's
helper package [`github.com/Bugs5382/go-workload-identity`](https://github.com/Bugs5382/go-workload-identity)
(v1.0.0), which every Sneakers service imports in place of its old private copy.
`internal/server/workloadauth.go` sets the Sneakers values the package has no default for: the
audience `sneakers` when `WORKLOAD_AUDIENCE` is unset, and the caller-name prefix `sneakers-`
(`WORKLOAD_SERVICEACCOUNT_PREFIX` is not read).
The audit service makes no gRPC calls of its own, so it needs no token of its own.

| Variable | Default | Purpose |
|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | (required) | The cluster's ServiceAccount token issuer (`https://`). The token's `iss` must equal it. |
| `WORKLOAD_OIDC_JWKS_URL` | discovered | JWKS URL (`https://`); when unset it's read from the issuer's OpenID configuration. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM CA bundle for discovery and the JWKS fetch. |
| `WORKLOAD_OIDC_BEARER_FILE` | (unset) | Bearer token sent on discovery and the JWKS fetch, re-read on every fetch. |
| `WORKLOAD_AUDIENCE` | `sneakers` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | (required) | Comma list of `<namespace>/<serviceaccount>`: for audit, `<ns>/sneakers-gateway,<ns>/sneakers-vault,<ns>/sneakers-sshbroker,<ns>/sneakers-identity,<ns>/sneakers-workflow`. Add `<ns>/sneakers-migrate` only while the migration Job runs, and take it out when the Job is done. On the appliance, add `<ns>/sneakers-appliance` (OS audit forwarding, `RecordEvent` with `actor_type=appliance-admin` only). |
| `WORKLOAD_AUTH` | (unset) | `disabled` turns the check off, for local development only: every caller that reaches the port is trusted, and a warning is logged at start and every 5 minutes. No other value is accepted. |

Without `WORKLOAD_OIDC_ISSUER` the service refuses to start, unless `WORKLOAD_AUTH=disabled`;
setting both is refused too.

No caller can be checked before the issuer's key set has loaded, so readiness waits for it too:
`/readyz` and the gRPC health check answer `NOT_SERVING`, with `workload-identity` reported down
in the readiness body (`server.WorkloadIdentity`, checking `Verifier.Ready`), until then. It's
left out of the readiness body when `WORKLOAD_AUTH=disabled`. Liveness is unaffected.

Example:

```bash
DATABASE_DSN='postgres://audit@db.example.org:5432/audit?sslmode=require'
PGPASSWORD=...   # from your secret store
GRPC_PORT=9090
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector.example.org:4317
WORKLOAD_OIDC_ISSUER=https://kubernetes.default.svc.cluster.local
WORKLOAD_OIDC_CA_FILE=/var/run/secrets/tokens/ca.crt
WORKLOAD_OIDC_BEARER_FILE=/var/run/secrets/tokens/token
WORKLOAD_AUDIENCE=sneakers
WORKLOAD_ALLOWED_SERVICEACCOUNTS=sneakers/sneakers-gateway,sneakers/sneakers-vault,sneakers/sneakers-sshbroker,sneakers/sneakers-identity,sneakers/sneakers-workflow
LOG_LEVEL=info
```
