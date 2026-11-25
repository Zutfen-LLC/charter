#!/usr/bin/env bash
# One entry point for the disposable local stack.
#   scripts/dev.sh test       start DB, run all Go + contract tests, tear down
#   scripts/dev.sh up|down    start / destroy the DB only
# Prerequisites: Go >= 1.24, Docker with compose v2, Python 3 (contract tests).
# Set CHARTER_TEST_DATABASE_URL to use your own disposable Postgres instead of Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
URL_DEFAULT='postgres://charter:charter-dev-only@127.0.0.1:55432/charter?sslmode=disable'

case "${1:-}" in
  up)   docker compose up -d --wait db ;;
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
