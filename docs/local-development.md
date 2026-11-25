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

At startup `serve` refuses unsafe configuration: either login being a superuser, `CREATEROLE`, the owner or a member of the owner role, holding any privilege it should not (for example UPDATE/DELETE/TRUNCATE on evidence, or any access to evidence from the workspace login), the two logins being the same, or the database not being fully migrated. It then takes a single-instance fence, recovers unfinished turns, and serves. For a shared environment create the logins with `scripts/provision-runtime-roles.sql` (real secrets) after `charter migrate`. `/healthz` is liveness; `/readyz` pings both pools and returns 503 if either is unreachable. `charter migrate` falls back to `CHARTER_DATABASE_URL` only as a development convenience.

## Evidence is durable but not retention-enforced storage
Evidence is written to append-only PostgreSQL tables ([evidence capture](evidence-capture.md)). That backend (`CHARTER_EVIDENCE_BACKEND=postgres-append-only`, default; `test-fixture` is an alias) is **not** WORM: a database owner can still alter it, `/healthz` reports `retention_enforced: false` with a notice, and the server logs it at startup. Do not advertise or use it as a preservation backend. Qualifying a genuinely retention-capable backend is still open (#4).

## Egress and providers
The server makes no outbound calls unless OIDC is configured, and then only to the configured https JWKS URL, never following redirects ([identity and access](identity-and-access.md)). Tests use an in-process synthetic IdP. Model calls go through the evidence recorder; deterministic fake model providers arrive with #5 (until then a stub answers). Any future outbound call must be opt-in and default off.

## Stack decision
Go + PostgreSQL, as the issue prefers: one static binary, a small dependency set (`pgx`), and embedded SQL migrations applied in order under an advisory lock. Migration `0003` defines the evidence schema from ADR 0001.
