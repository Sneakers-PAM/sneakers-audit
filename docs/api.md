# API

The service implements `sneakers.audit.v1.AuditService`, defined in
[proto/sneakers/audit/v1/audit.proto](../proto/sneakers/audit/v1/audit.proto). Go clients import the
generated code from `github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1`.

The server also registers the standard gRPC health service (`grpc.health.v1.Health`) and server
reflection.

A health check's answer carries the build in its response headers: `sneakers-version` (the image
tag, `dev` when unstamped) and `sneakers-commit` (the source commit, `unknown` when neither the
build nor Go's VCS stamp knows it). It also carries `sneakers-dep-postgres`, the database
server's version (`SHOW server_version`, first token, at most 64 characters), read once at start;
the header is left out when that read failed. The gateway's diagnostics read them.

The health check has two services:

- `""` (the default) is readiness. It answers `NOT_SERVING` while PostgreSQL, a required
  dependency, doesn't answer a ping, and `SERVING` again once it does. Each ping has a 1-second
  timeout and its result answers for 5 seconds, so frequent probes don't load the database. Its
  answer carries `sneakers-health`, a compact JSON report:

  ```json
  {"status":"down","dependencies":[{"name":"postgres","state":"down","required":true,"error":"refused","checkedAt":"2026-10-05T12:00:05Z","version":"17.11"}]}
  ```

  `status` and each `state` are `ok`, `degraded` (an optional dependency is failing; still
  serving) or `down` (a required one is; not serving). `error` is a class, never the error
  itself: `timeout`, `refused`, `unavailable`, `unauthenticated` or `error`. `version` is the one
  in `sneakers-dep-*`, when known.
- `liveness` answers `SERVING` whenever the process does and never touches a dependency.

Any other service name is `NOT_FOUND`. `Watch` is not supported (`UNIMPLEMENTED`); poll `Check`.

## Callers

Every call must carry the caller's workload identity: its projected Kubernetes ServiceAccount
token as `authorization: Bearer <token>` (see
[configuration.md](configuration.md#service-to-service-authentication)). The service verifies it
and checks the caller against a per-method allow-list (`grpcsvc.CallerPolicy`):

| Caller | Methods | Access |
|---|---|---|
| `gateway`, `vault`, `sshbroker`, `identity`, `workflow` | `RecordEvent` | as itself |
| `gateway` | `ListRecords`, `DistinctActions`, `VerifyChain` | as itself (the audit viewer) |
| `migrate` | `RecordEvent`, `VerifyChain` | as itself (the migration Job) |
| `appliance` | `RecordEvent` | as itself, `appliance-admin` events only |

Every writer, migrate included, sends `actor_user_id` as the user the event is about, and the
service stores it as given. `migrate` is in `WORKLOAD_ALLOWED_SERVICEACCOUNTS` only while the
migration Job runs; the rest of the time its token gets `Unauthenticated`.

`appliance` is the appliance's controller (the `sneakers-appliance` service account), forwarding
the box's OS audit entries into the same chain. Its events must carry the attribute
`actor_type=appliance-admin`, because they are about the box's owners rather than product users;
any other or missing `actor_type` from `appliance` gets `PermissionDenied`, and so does an
`actor_type=appliance-admin` event from any other caller. A refused event is never written. Only
installs that run the appliance list `sneakers-appliance` in `WORKLOAD_ALLOWED_SERVICEACCOUNTS`.

No or a bad token, or a service account that isn't in `WORKLOAD_ALLOWED_SERVICEACCOUNTS`, gets
`Unauthenticated`; a listed caller on a method it isn't listed for gets `PermissionDenied`. The
health service is exempt. A refusal is logged at warn (`call refused`, with the method, caller and
reason) and never recorded in the chain.

## RPCs

| RPC | What it does |
|---|---|
| `RecordEvent` | Appends one event and returns the stored record with its `seq`, `prev_hash` and `hash`. If `occurred_at` is empty the server stamps the current UTC time (RFC 3339). |
| `ListRecords` | Returns records in chain order, filtered by `actor_user_id` and `subject` (empty matches any). Records whose action is in `exclude_actions` are dropped across the whole chain first; then the most recent `limit` records are kept (`0` keeps all). |
| `DistinctActions` | Returns every distinct action in the chain, optionally for one actor, so a client can offer a complete "hide actions" list. |
| `VerifyChain` | Walks the whole chain and returns `valid`, the chain `length`, and `broken_at_seq`, the first bad record (`0` when valid). |

## Records

Each record carries a tier (`TIER_AUDIT` for security-relevant events, `TIER_ACTIVITY` for routine
activity), the action (for example `secret.reveal`), the actor, the subject (for example a secret id
plus `#field`), a group id, a sensitive flag, free-form string attributes, and the time it occurred.

## The hash chain

- Records are numbered from 1 with no gaps. Appends are serialized, so each new record is computed
  against a stable tail.
- A record's `hash` is the hex SHA-256 of its canonical form: `seq`, tier, action, actor, subject,
  group id, sensitive flag, the attributes sorted by key, `occurred_at` and `prev_hash`, joined
  with `|`.
- `prev_hash` is the previous record's `hash`, and empty for the first record.
- `VerifyChain` flags the first record whose `seq` is out of order, whose `prev_hash` doesn't match
  the previous hash, or whose recomputed hash doesn't match the stored one.
