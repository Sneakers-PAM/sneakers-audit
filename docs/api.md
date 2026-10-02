# API

The service implements `sneakers.audit.v1.AuditService`, defined in
[proto/sneakers/audit/v1/audit.proto](../proto/sneakers/audit/v1/audit.proto). Go clients import the
generated code from `github.com/Sneakers-PAM/sneakers-audit/gen/go/sneakers/audit/v1`.

The server also registers the standard gRPC health service (`grpc.health.v1.Health`) and server
reflection.

## Callers

Every call must carry the caller's workload identity: its projected Kubernetes ServiceAccount
token as `authorization: Bearer <token>` (see
[configuration.md](configuration.md#service-to-service-authentication)). The service verifies it
and checks the caller against a per-method allow-list (`grpcsvc.CallerPolicy`):

| Caller | Methods | Access |
|---|---|---|
| `gateway`, `vault`, `sshbroker`, `identity`, `workflow` | `RecordEvent` | as itself |
| `gateway` | `ListRecords`, `DistinctActions`, `VerifyChain` | as itself (the audit viewer) |

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
