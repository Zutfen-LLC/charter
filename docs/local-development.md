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

## Test evidence is not retention-enforced storage
The only evidence backend is `test-fixture`. It is **not immutable and does not enforce retention or holds**; `/healthz` reports `retention_enforced: false` with a notice, and the server logs it at startup. Do not advertise or use it as a preservation backend. Qualifying real storage protection is a later, separate test (#4); until then it is a recorded gap.

## Egress and providers
The server makes no outbound calls unless OIDC is configured, and then only to the configured JWKS URL ([identity and access](identity-and-access.md)). Tests use an in-process synthetic IdP. Deterministic fake model providers arrive with #5. Any future outbound call must be opt-in and default off.

## Stack decision
Go + PostgreSQL, as the issue prefers: one static binary, a small dependency set (`pgx`), and embedded SQL migrations applied in order under an advisory lock. The initial migration holds instance metadata only; the durable evidence schema follows ADR 0001 in #4.
