#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
P=/mnt/rgw-payload
E=/mnt/rgw-evidence/run
cd "$P"
[[ -z "$(ip -o link show | awk -F': ' '$2 !~ /^(lo)$/ {print $2}')" ]]
[[ -z "$(ip route show default)" ]]
[[ "${C04_BUCKET_DEFAULT_ONLY:-}" == 1 ]]
mkdir -m 0711 /run/charter-c04-serving
export C04_SERVING_FILES=/run/charter-c04-serving
exec > >(tee -a "$E/drill-$C04_RUN.log") 2>&1
python3 "$P/lab-qualification.py"
source "$C04_PRIVATE/serving.env"
[[ "$CHARTER_S3_DEPLOYMENT" == "lab-$C04_RUN" ]]
image='sha256:a3c40a6a77a9a545ed6d766860c45f82ab8bc254148266e56c4139f91beec635'
systemctl start docker
docker --version
[[ "$(docker image inspect "$image" --format '{{.Id}}' 2>/dev/null || true)" == "$image" ]] || docker load -i "$P/postgres-16.16-alpine.tar.gz"
[[ "$(docker image inspect "$image" --format '{{.Id}}')" == "$image" ]]
name="charter-c04-$C04_RUN"
ownerpw=$(openssl rand -hex 20)
wspw=$(openssl rand -hex 20)
evpw=$(openssl rand -hex 20)
db="charter_c04_disposable_$C04_RUN"
export POSTGRES_PASSWORD="$ownerpw"
docker run --pull=never --name "$name" -d --rm --network host -e POSTGRES_PASSWORD -e "POSTGRES_DB=$db" --tmpfs /var/lib/postgresql/data "$image" postgres -c listen_addresses=127.0.0.1 -p 55433
unset POSTGRES_PASSWORD
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
for i in $(seq 1 40); do
  if docker exec "$name" pg_isready -h 127.0.0.1 -p 55433 -U postgres -d "$db" >/dev/null 2>&1; then break; fi
  sleep 1
done
pg() { docker exec -i "$name" psql -p 55433 -q -U postgres -d "$db" -v ON_ERROR_STOP=1 "$@"; }
export CHARTER_DRILL_OWNER_DSN="postgres://postgres:$ownerpw@127.0.0.1:55433/$db?sslmode=disable"
CHARTER_MIGRATE_DATABASE_URL="$CHARTER_DRILL_OWNER_DSN" ./charter migrate
CHARTER_MIGRATE_DATABASE_URL="$CHARTER_DRILL_OWNER_DSN" ./charter migrate
{ printf '\\set ws_user charter_ws\n\\set ws_password %s\n\\set ev_user charter_ev\n\\set ev_password %s\n' "$wspw" "$evpw"; cat provision-runtime-roles.sql; } | pg
printf "ALTER DATABASE %s SET charter.evidence_binding TO '%s:%s';\n" "$db" 'charter-s3-compliance-v1' "$CHARTER_S3_DEPLOYMENT" | pg
export CHARTER_DATABASE_URL="postgres://charter_ws:$wspw@127.0.0.1:55433/$db?sslmode=disable"
export CHARTER_EVIDENCE_DATABASE_URL="postgres://charter_ev:$evpw@127.0.0.1:55433/$db?sslmode=disable"
export CHARTER_EVIDENCE_BACKEND=s3-object-lock CHARTER_ADDR=127.0.0.1:55434
export CHARTER_DRILL_BINARY="$P/charter" CHARTER_DRILL_OUTPUT="$E/drill-$C04_RUN"
./retention-drill.test -test.v -test.run '^TestRetentionReconstructionDrill$' -test.timeout 5m
./retention-real.test -test.v -test.run '^TestRealRetainedBoundaryFailures$' -test.timeout 4m
python3 "$P/lab-qualification.py" post
printf 'FULL_CHARTER_DRILL_PASS run=%s UTC=%s\n' "$C04_RUN" "$(date -u +%FT%TZ)"
