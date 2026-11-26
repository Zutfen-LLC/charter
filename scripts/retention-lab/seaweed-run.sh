#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
P=/mnt/rgw-payload
mountpoint -q "$P"
[[ -z "$(ip -o link show | awk -F': ' '$2 !~ /^(lo)$/ {print $2}')" ]]
[[ -z "$(ip route show default)" ]]
mkdir -p /mnt/rgw-evidence
mount -L RGWQ110EVID /mnt/rgw-evidence
E=/mnt/rgw-evidence/run
mkdir -p "$E"
exec > >(tee -a "$E/seaweed-boot.log") 2>&1
trap 'rc=$?; echo "SEAWEED_LAB_FAIL rc=$rc line=$LINENO"; sync; systemctl poweroff; exit $rc' ERR
cd "$P"
sha256sum -c ARTIFACT-SHA256SUMS
[[ "$(sha256sum weed | cut -d' ' -f1)" == b0e48a0d0bd26d206cc4e96b3edcfebded8086b47d77f619b9a676f4f51abd36 ]]
./weed version
export C04_STORAGE=seaweed
[[ -f ./full-drill.sh && -x ./retention-drill.test && -x ./retention-real.test ]]
export C04_BUCKET_DEFAULT_ONLY=1
export C04_RUN=$(python3 -c 'import secrets; print(secrets.token_hex(8))')
export C04_PRIVATE=$(mktemp -d /run/charter-seaweed.XXXXXXXX)
mkdir -m 0700 "$C04_PRIVATE/data"
python3 - <<'PY'
import json,os,pathlib,secrets
home=pathlib.Path(os.environ['C04_PRIVATE'])
bucket='charter-c04-protected-'+os.environ['C04_RUN']
identities=[]
for role in ['admin','runtime']:
 name='rgwq110-'+role
 access='c04'+secrets.token_hex(10)
 secret=secrets.token_hex(32)
 (home/(name+'.json')).write_text(json.dumps({'user_id':name,'keys':[{'access_key':access,'secret_key':secret}]}))
 identities.append(dict(name=name,credentials=[dict(accessKey=access,secretKey=secret)],actions=['Admin'] if role=='admin' else [],policyNames=[] if role=='admin' else ['C04Runtime']))
policy={'Version':'2012-10-17','Statement':[
 dict(Effect='Allow',Action=['s3:GetBucketVersioning','s3:GetBucketObjectLockConfiguration','s3:ListBucketVersions'],Resource=['arn:aws:s3:::'+bucket]),
 dict(Effect='Allow',Action=['s3:PutObject','s3:GetObjectVersion','s3:GetObjectRetention'],Resource=['arn:aws:s3:::'+bucket+'/*']),
]}
(home/'iam.json').write_text(json.dumps(dict(identities=identities,policies=[dict(name='C04Runtime',content=json.dumps(policy))])))
pathlib.Path('/mnt/rgw-evidence/run/seaweed-runtime-policy.json').write_text(json.dumps(policy,indent=2)+'\n')
PY
# Static lab credentials, no IAM modification endpoints and no non-loopback binds.
./weed mini -dir="$C04_PRIVATE/data" -ip=127.0.0.1 -ip.bind=127.0.0.1 -s3.port=7481 -s3.iam.config="$C04_PRIVATE/iam.json" -s3.iam.readOnly=true -s3.iam.selfServiceRequiresGrant=true > "$C04_PRIVATE/private-server.log" 2>&1 &
server_pid=$!
export CHARTER_DRILL_STORAGE_PID="$server_pid"
for attempt in $(seq 1 45); do
  if code=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' --noproxy '*' http://127.0.0.1:7481/ 2>/dev/null) && [[ "$code" == 403 ]]; then break; fi
  kill -0 "$server_pid"
  sleep 2
done
[[ "$code" == 403 ]]
ss -lntH 'sport = :7481' | tee "$E/seaweed-listener.txt" | grep -q '127.0.0.1:7481'
result=0
python3 ./native-probe.py || result=$?
printf 'SEAWEED_PROBE_EXIT=%s\n' "$result" | tee "$E/SEAWEED-PROBE-EXIT"
if [[ "$result" == 0 ]]; then
  bash ./full-drill.sh
fi
kill -TERM "$server_pid" || true
wait "$server_pid" || true
printf 'SEAWEED_FINISHED UTC=%s\n' "$(date -u +%FT%TZ)" | tee "$E/SEAWEED-RESULT"
sync
systemctl poweroff
