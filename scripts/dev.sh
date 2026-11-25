#!/usr/bin/env bash
# One entry point for the disposable local stack.
#   scripts/dev.sh test       start DB, run all Go + contract tests, tear down
#   scripts/dev.sh up|down    start / destroy the DB only
# Prerequisites: Go >= 1.24, Docker with compose v2, Python 3 (contract tests).
# Set CHARTER_TEST_DATABASE_URL to use your own disposable Postgres instead of Docker.
#   scripts/dev.sh up also migrates (as the schema owner) and creates the two
#   least-privilege serving logins, then prints the environment to serve with.
set -euo pipefail
cd "$(dirname "$0")/.."
URL_DEFAULT='postgres://charter:charter-dev-only@127.0.0.1:55432/charter?sslmode=disable'

case "${1:-}" in
  up)
    docker compose up -d --wait db
    # Bootstrap only: the owner credential is used here and never by `serve`.
    CHARTER_MIGRATE_DATABASE_URL="$URL_DEFAULT" go run ./cmd/charter migrate
    docker compose exec -T db psql -q -U charter -d charter \
      -v ws_user=charter_ws -v ws_password=charter-ws-dev-only \
      -v ev_user=charter_ev -v ev_password=charter-ev-dev-only \
      < scripts/provision-runtime-roles.sql
    cat <<'EOT'
Serve with the restricted logins (never the owner):
  export CHARTER_DATABASE_URL='postgres://charter_ws:charter-ws-dev-only@127.0.0.1:55432/charter?sslmode=disable'
  export CHARTER_EVIDENCE_DATABASE_URL='postgres://charter_ev:charter-ev-dev-only@127.0.0.1:55432/charter?sslmode=disable'
  go run ./cmd/charter serve
EOT
    ;;
  down) docker compose down -v ;;
  test)
    if [ -z "${CHARTER_TEST_DATABASE_URL:-}" ]; then
      docker compose up -d --wait db
      trap 'docker compose down -v' EXIT
      export CHARTER_TEST_DATABASE_URL="$URL_DEFAULT"
    fi
    test -z "$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
    go vet ./...
    go test -count=1 ./...
    python3 -m unittest discover -s tests/contracts
    ;;
  *) echo "usage: $0 test|up|down" >&2; exit 2 ;;
esac
