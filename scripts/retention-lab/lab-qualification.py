#!/usr/bin/env python3
"""Create a signed synthetic-only statement from successful live probes."""
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, '/mnt/rgw-payload')
# Load exactly the staged Python source (hyphenated executable filename).
import runpy
p = runpy.run_path('/mnt/rgw-payload/native-probe.py')
rt, ad = (p['Client']('rgwq110-' + x) for x in ('runtime', 'admin'))
rd, protected = p['OUT'], p['PROT']
base = pathlib.Path(os.environ['C04_SERVING_FILES'])
public = pathlib.Path(os.environ['C04_PRIVATE'])
report = json.loads(rd.read_bytes())
assert p['DEFAULT_ONLY'] and all(x['passed'] for x in report['checks'])
results = {x['name']: x for x in report['checks']}
controls = {
 'admin_exact_delete': ['admin_delete_exact', 'admin_bypass_compliance'],
 'admin_shorten': ['admin_shorten_to_future'],
 'runtime_exact_delete': ['runtime_delete_exact'],
 'runtime_delete_marker': ['runtime_delete_marker'],
 'runtime_retention_mutations': ['runtime_shorten_to_future','runtime_downgrade','runtime_remove_retention','runtime_bypass_compliance','wrong_initial_mode','explicit_short_retention'],
 'runtime_cannot_administer': ['runtime_bucket_delete','runtime_suspend_versioning','runtime_remove_lock_default','runtime_write_policy','runtime_write_lifecycle','runtime_cannot_change_legal_hold'],
 'runtime_cannot_escalate': ['runtime_admin_key_creation'],
 'runtime_single_bucket': ['runtime_write_other_bucket'],
 'latest_exact_version':['new_latest_never_substitutes_exact_version','runtime_unqualified_latest_read'],
 'linearizable_conditional_create':[f'conditional_create_32_round_{i}' for i in range(6)],
 'unprotected_positive_controls':['admin_unprotected_exact_delete_positive','admin_set_retention_on_unprotected_version'],
}
for labels in controls.values():
    assert all(results[x]['passed'] for x in labels)

if len(sys.argv) > 1 and sys.argv[1] in ('unsafe-default', 'restore-default'):
    # Change only the bucket default in this disposable lab. No object version
    # is edited. The admin restores the qualified default before any turn runs.
    mode = 'GOVERNANCE' if sys.argv[1] == 'unsafe-default' else 'COMPLIANCE'
    body = p['xml']('ObjectLockConfiguration',
        '<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention>'
        f'<Mode>{mode}</Mode><Days>1</Days></DefaultRetention></Rule>')
    result = ad.call('PUT', protected, query={'object-lock':''}, data=body)
    observed = rt.call('GET', protected, query={'object-lock':''})
    assert result.status in (200, 204) and observed.status == 200 and p['field'](observed.raw, 'Mode') == mode
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == 'substitute':
    run_dir = rd.parent / ('drill-' + p['RUN'])
    items = json.loads((run_dir / 'exact-version-inventory.json').read_bytes())
    checks=[]
    for part in ('/data/events/', '/admissions/', '/data/objects/'):
        x = next(i for i in items if part in i['key'])
        key, original = x['key'], x['version_id']
        new = ('unsigned synthetic replacement ' + part + '\n').encode()
        put = rt.call('PUT', protected, key, data=new)
        latest = ad.call('GET', protected, key)
        passed, readback = p['verify_version'](rt, protected, key, original, base64.b64decode(x['bytes']), x['retain_until'])
        passed = passed and put.status==200 and put.version not in ('',None,'null',original) and latest.status==200 and latest.version==put.version and latest.raw==new
        checks.append(dict(key=key, passed=passed, original=original, latest=latest.summary(), overwrite=put.summary(), exact=readback))
    (run_dir / 'latest-substitution-results.json').write_text(json.dumps(checks,indent=2)+'\n')
    assert all(x['passed'] for x in checks)
    sys.exit(0)

if len(sys.argv) > 1 and sys.argv[1] == 'post':
    items = json.loads((rd.parent / ('drill-' + p['RUN']) / 'exact-version-inventory.json').read_bytes())
    markers = [x for x in items if '/admissions/' in x['key'] or '/events/' in x['key']]
    assert markers
    out = []
    for item in items:
        key, vid = item['key'], item['version_id']
        body = base64.b64decode(item['bytes'], validate=True)
        q = {'versionId':vid}
        assert 'sha256:' + p['digest'](body) == item['sha256'] and len(body) == item['byte_length']
        # On the protected original version of every evidence object and marker,
        # verify the permission distinction independently using both identities.
        for label, ident, verb, query, data in [
            ('runtime_delete',rt,'DELETE',q,b''),
            ('admin_delete',ad,'DELETE',q,b''),
            ('admin_shorten',ad,'PUT',q|{'retention':''},p['date_xml']('COMPLIANCE',p['shorter'])),
        ]:
            a = ident.call(verb, protected, key, query, data=data)
            ok, obs = p['verify_version'](rt, protected, key, vid, body, item['retain_until'])
            passed = ok and a.status==403 and a.code=='AccessDenied'
            out.append(dict(label=label, key=key, original_version=vid, passed=passed, mutation=a.summary(), **obs))
    (rd.parent / ('drill-' + p['RUN']) / 'exact-version-mutation-results.json').write_text(json.dumps(out, indent=2)+'\n')
    assert all(x['passed'] for x in out)
    sys.exit(0)

now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
valid = now + dt.timedelta(minutes=35)
retain = now + dt.timedelta(hours=2)
sha = lambda b: 'sha256:' + hashlib.sha256(b).hexdigest()
run = 'lab-' + p['RUN']
key = 'charter/v1/' + run + '/authority'
body = ('Charter C04 synthetic authority ' + run + '\n').encode()
made = ad.call('PUT', protected, key, headers={'if-none-match':'*','x-amz-object-lock-mode':'COMPLIANCE','x-amz-object-lock-retain-until-date':p['brief'](retain)},data=body)
assert made.status==200 and made.version not in ('',None,'null')
ok, obs = p['verify_version'](rt, protected, key, made.version, body, p['brief'](retain))
assert ok
cert = dict(version='charter-s3-lab-qualification-v1', profile='charter-s3-compliance-v1',endpoint=p['ORIGIN'],region='us-east-1',bucket=protected,deployment=run,runtime_access_key_sha256=sha(rt.access.encode()),
    storage_implementation='SeaweedFS 4.55 a98c9e27185cf1003eca095761a39973c60734db',storage_digest='sha256:b0e48a0d0bd26d206cc4e96b3edcfebded8086b47d77f619b9a676f4f51abd36',qualification_report_sha256=sha(rd.read_bytes()),issued_at=p['brief'](now), valid_until=p['brief'](valid),controls=list(controls),
    canary=dict(key=key,version=made.version,sha256=sha(body),length=len(body),mode='COMPLIANCE',retain_until=p['brief'](retain)))
def sh(*cmd): return subprocess.check_output(cmd)
qual = public/'qualification.private.pem'
seed = public/'commit.private.pem'
for f in (qual, seed):
    sh('openssl','genpkey','-algorithm','ED25519','-out',str(f))
qpub, cpub = (sh('openssl','pkey','-in',str(f),'-pubout','-outform','DER')[-32:].hex() for f in (qual,seed))
cert.update(commit_public_key=cpub,minimum_retention_seconds='600')
payload = json.dumps(cert, separators=(',',':'))
message = public/'signature-input'
message.write_bytes(b'CHARTER-S3-LAB-QUALIFICATION-v1\0'+payload.encode())
sig=sh('openssl','pkeyutl','-sign','-inkey',str(qual),'-rawin','-in',str(message))
envelope = json.dumps(dict(payload=payload,signature=sig.hex()))+'\n'
(base/'qualification.json').write_text(envelope)
(base/'commit.seed').write_text(sh('openssl','pkey','-in',str(seed),'-outform','DER')[-32:].hex()+'\n')
(base/'s3.secret').write_text(rt.secret+'\n')
for f in base.iterdir(): os.chown(f,65534,65534)
(public/'serving.env').write_text('\n'.join(f'export {k}={v}' for k,v in dict(
    CHARTER_S3_ENDPOINT=p['ORIGIN'],CHARTER_S3_REGION='us-east-1',CHARTER_S3_BUCKET=protected,CHARTER_S3_DEPLOYMENT=run,CHARTER_S3_RUNTIME_ACCESS_KEY=rt.access,CHARTER_S3_RUNTIME_SECRET_FILE=base/'s3.secret',CHARTER_S3_COMMIT_SEED_FILE=base/'commit.seed',CHARTER_S3_COMMIT_PUBLIC_KEY=cpub,CHARTER_S3_QUALIFICATION_FILE=base/'qualification.json',CHARTER_S3_QUALIFICATION_PUBLIC_KEY=qpub,CHARTER_S3_RETENTION_SECONDS='600',CHARTER_S3_SYNTHETIC_OPT_IN='I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB').items())+'\n')
(rd.parent / ('qualification-' + p['RUN'] + '.json')).write_text(json.dumps(dict(certificate=json.loads(envelope),qualification_public_key=qpub,commit_public_key=cpub,canary_readback=obs),indent=2)+'\n')
