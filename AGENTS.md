# AGENTS.md - sneakers-audit

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers audit service: the tamper-evident audit trail. A gRPC service
(`sneakers.audit.v1.AuditService`) that appends hash-chained records to Postgres. Before changing
it, know that each record's hash covers the previous record's hash (`internal/chain`), so any
change to the canonical form or the hash breaks `VerifyChain` for every stored trail.

## Layout

- `cmd/audit/` - the entrypoint: config, migrations, the gRPC server.
- `internal/chain/` - canonical form and hash chaining.
- `internal/grpcsvc/` - the service and its Postgres and in-memory stores, with their tests.
- `internal/workloadauth/` - service-to-service authentication, a byte-for-byte copy of
  sneakers-vault's package at `SNEAKERS_VAULT_REF` (`proto-refs.env`). Never edit it here: change
  it in the vault, then copy it and bump the ref (`scripts/workloadauth-check.sh` fails CI
  otherwise). The allow-list is `internal/grpcsvc/callers.go`; a new RPC needs an entry there.
- `internal/config/`, `internal/server/` - the env loader and the gRPC server bootstrap.
- `proto/` - the API; `gen/go/` - the generated Go (committed, checked current in CI).
- `migrations/` - the Postgres schema, forward only.
- `docs/` - configuration, API and runbook.

## Build, test, lint

- Build: `task build`
- Test: `task test`; set `AUDIT_PG_DSN` to a Postgres database to run the integration test
  (see README.md), otherwise it is skipped.
- Lint: `task lint`, plus `buf lint` for the proto.
- Generated code: `buf generate` with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names.
