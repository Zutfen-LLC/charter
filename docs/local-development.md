# Local development

Synthetic data only. This stack is disposable and is **not** a deployment.

## Prerequisites
Go 1.24+, Docker with compose v2 (or your own disposable PostgreSQL 16 via `CHARTER_TEST_DATABASE_URL`), Python 3.

## One command
```bash
scripts/dev.sh test
```
Starts a throwaway Postgres (tmpfs, nothing persists), runs the gofmt check, `go vet`, Go tests (including migrations against the real DB) and the contract fixtures, then destroys the database. `scripts/dev.sh up|down` start/destroy the DB alone. The DB tests create a uniquely named `charter_test_*` schema and drop only that schema afterwards; tests that exercise runtime credentials also create (and drop) randomly named `charter_rt_*` login roles, so `CHARTER_TEST_DATABASE_URL` must be a disposable database whose user can create roles (a superuser such as the dev stack and CI use). Still prefer a disposable database for `CHARTER_TEST_DATABASE_URL`.

## Run the server
The server never serves with the schema owner's credential and never migrates. Bootstrap (migrate as the owner, create the two least-privilege logins) is separate from serving:
```bash
scripts/dev.sh up        # starts Postgres, runs `charter migrate` as the owner, creates charter_ws / charter_ev
export CHARTER_DATABASE_URL='postgres://charter_ws:charter-ws-dev-only@127.0.0.1:55432/charter?sslmode=disable'
export CHARTER_EVIDENCE_DATABASE_URL='postgres://charter_ev:charter-ev-dev-only@127.0.0.1:55432/charter?sslmode=disable'
go run ./cmd/charter serve    # listens on 127.0.0.1:8080
curl -s localhost:8080/healthz
scripts/dev.sh down
```
| Variable | Used by | Credential |
| --- | --- | --- |
| `CHARTER_MIGRATE_DATABASE_URL` | `charter migrate` only | schema **owner**; `serve` refuses to start if this is set |
| `CHARTER_DATABASE_URL` | `serve` | workspace login, member of `charter_workspace_app` (no privilege on evidence tables) |
| `CHARTER_EVIDENCE_DATABASE_URL` | `serve` | evidence login, member of `charter_evidence_app` (INSERT and SELECT on evidence tables only) |

At startup `serve` validates the [restricted runtime credential profile](runtime-protection.md), takes the [ownership and drain fence](fence-ownership.md), and recovers unfinished turns before accepting requests. Authenticated model serving also requires the separately provisioned accounting login; see [C05 setup and the local endpoint protocol](model-routing-and-budget.md). For a shared environment create the logins with `scripts/provision-runtime-roles.sql` (real secrets) after `charter migrate`. `/healthz` is liveness; `/readyz` pings both pools and returns 503 if either is unreachable. A process that loses ownership stops serving rather than reconnecting and continuing. `charter migrate` falls back to `CHARTER_DATABASE_URL` only as a development convenience.

## Evidence backends

`CHARTER_EVIDENCE_BACKEND=postgres-append-only` is the default (`test-fixture` remains an alias). It is durable, not WORM: a database owner can alter it and `/healthz` reports `retention_enforced: false`.

The same `charter serve` entrypoint can explicitly select `s3-object-lock` **only in the isolated synthetic lab**. Provision the database binding, qualified storage, separate runtime credential, signed activation statement and signing seed out of process. Use the [pinned lab procedure](retention-qualification.md) and [retained evidence profile](retention-candidate.md), not the ordinary development database. A missing opt-in, invalid qualification, unsafe runtime credentials or invalid live storage blocks startup. The retained deployment does not fall back to PostgreSQL; `/readyz` also checks storage protection, while `/healthz` identifies the backend and its startup qualification scope. Keep all storage-management credentials outside the serving identity.

## Egress and providers

By default, the server makes no outbound calls except to the configured OIDC JWKS endpoint when OIDC is enabled. The retention lab adds loopback S3 access and uses the synthetic loopback IdP; its deterministic model adapter consumes the exact sealed input without calling a remote model. No production storage or provider deployment is authorized by this mode.

## Stack decision
Go + PostgreSQL, as the issue prefers: one static binary, a small dependency set (`pgx`), and embedded SQL migrations applied in order under an advisory lock. Migration `0003` defines the evidence schema from ADR 0001.
