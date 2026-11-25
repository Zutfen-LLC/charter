# Local development

Synthetic data only. This stack is disposable and is **not** a deployment.

## Prerequisites
Go 1.24+, Docker with compose v2 (or your own disposable PostgreSQL 16 via `CHARTER_TEST_DATABASE_URL`), Python 3.

## One command
```bash
scripts/dev.sh test
```
Starts a throwaway Postgres (tmpfs, nothing persists), runs the gofmt check, `go vet`, Go tests (including migrations against the real DB) and the contract fixtures, then destroys the database. `scripts/dev.sh up|down` start/destroy the DB alone. The DB test creates a uniquely named `charter_test_*` schema and drops only that schema afterwards; it never touches other schemas. Still prefer a disposable database for `CHARTER_TEST_DATABASE_URL`.

## Run the server
```bash
scripts/dev.sh up
export CHARTER_DATABASE_URL='postgres://charter:charter-dev-only@127.0.0.1:55432/charter?sslmode=disable'
go run ./cmd/charter serve    # migrates, then listens on 127.0.0.1:8080
curl -s localhost:8080/healthz
scripts/dev.sh down
```
`/healthz` is liveness; `/readyz` checks the database and returns 503 if it is unreachable.

## Evidence is durable but not retention-enforced storage
Evidence is written to append-only PostgreSQL tables ([evidence capture](evidence-capture.md)). That backend (`CHARTER_EVIDENCE_BACKEND=postgres-append-only`, default; `test-fixture` is an alias) is **not** WORM: a database owner can still alter it, `/healthz` reports `retention_enforced: false` with a notice, and the server logs it at startup. Do not advertise or use it as a preservation backend. Qualifying a genuinely retention-capable backend is still open (#4).

## Egress and providers
The server makes no outbound calls unless OIDC is configured, and then only to the configured https JWKS URL, never following redirects ([identity and access](identity-and-access.md)). Tests use an in-process synthetic IdP. Model calls go through the evidence recorder; deterministic fake model providers arrive with #5 (until then a stub answers). Any future outbound call must be opt-in and default off.

## Stack decision
Go + PostgreSQL, as the issue prefers: one static binary, a small dependency set (`pgx`), and embedded SQL migrations applied in order under an advisory lock. Migration `0003` defines the evidence schema from ADR 0001.
