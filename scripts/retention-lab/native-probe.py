#!/usr/bin/env python3
"""Native, destructive test solely for the no-NIC VM 110 synthetic buckets."""
import base64
import concurrent.futures
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

NS = 'http://s3.amazonaws.com/doc/2006-03-01/'
STORAGE = os.environ.get('C04_STORAGE', 'ceph')
DEFAULT_ONLY = os.environ.get('C04_BUCKET_DEFAULT_ONLY') == '1'
assert STORAGE in ('ceph','seaweed')
PORT = '127.0.0.1:7480' if STORAGE=='ceph' else '127.0.0.1:7481'
ORIGIN = 'http://' + PORT
RUN = os.environ.get('C04_RUN', uuid.uuid4().hex[:16])
assert len(RUN)==16 and all(c in '0123456789abcdef' for c in RUN)
PROT = 'charter-c04-protected-' + RUN
PLAIN = 'charter-c04-plain-' + RUN
CONTROL = 'charter-c04-control-' + RUN
OUT = pathlib.Path('/mnt/rgw-evidence/run/native-'+RUN+'.json')
NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
brief = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
until = brief(NOW + dt.timedelta(hours=2))
shorter = brief(NOW + dt.timedelta(hours=1))
longer = brief(NOW + dt.timedelta(hours=3))
digest = lambda data: hashlib.sha256(data).hexdigest()
xml = lambda name, inner: f'<{name} xmlns="{NS}">{inner}</{name}>'.encode()

def keys(path, expected):
    info = json.loads(pathlib.Path(path).read_text())
    info = info.get('user', info)
    assert info['user_id'] == expected and len(info['keys']) == 1
    return info['keys'][0]['access_key'], info['keys'][0]['secret_key']

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class Client:
    def __init__(self, identity):
        self.identity = identity
        self.access, self.secret = keys(('/root/' if STORAGE=='ceph' else os.environ['C04_PRIVATE']+'/')+identity+'.json', identity)

    def call(self, method, bucket, key='', query=None, headers=None, data=b'', service='s3'):
        assert (bucket in (PROT, PLAIN, CONTROL) or (bucket=='' and method=='POST' and service=='iam')) and not key.startswith('/')
        path = urllib.parse.quote('/'+bucket+('/'+key if key else ''), safe='/-_.~')
        qs = urllib.parse.urlencode(sorted((query or {}).items()), quote_via=urllib.parse.quote, safe='-_.~')
        hdr = dict(headers or {})
        timestamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        body_hash = digest(data)
        day = timestamp[:8]
        hdr.update({'host': PORT, 'x-amz-date': timestamp, 'x-amz-content-sha256': body_hash})
        if method == 'PUT' and data:
            hdr['content-md5'] = base64.b64encode(hashlib.md5(data).digest()).decode()
        names = sorted(hdr)
        signed = ';'.join(names)
        canonical = '\n'.join((method, path, qs, ''.join(k+':'+str(hdr[k]).strip()+'\n' for k in names), signed, body_hash))
        scope = day+'/us-east-1/'+service+'/aws4_request'
        material = ('AWS4'+self.secret).encode()
        for token in (day, 'us-east-1', service, 'aws4_request'):
            material = hmac.digest(material, token.encode(), 'sha256')
        sig = hmac.new(material, ('AWS4-HMAC-SHA256\n'+timestamp+'\n'+scope+'\n'+digest(canonical.encode())).encode(), 'sha256').hexdigest()
        hdr['authorization'] = f'AWS4-HMAC-SHA256 Credential={self.access}/{scope}, SignedHeaders={signed}, Signature={sig}'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        request = urllib.request.Request(ORIGIN+path+('?' + qs if qs else ''), data=data if method in ('PUT','POST') else None, method=method, headers=hdr)
        try:
            with opener.open(request, timeout=20) as r:
                return Response(r.status, r.headers, r.read(), self)
        except urllib.error.HTTPError as e:
            return Response(e.code, e.headers, e.read(), self)
        except (TimeoutError, urllib.error.URLError, ConnectionError):
            return Response(0, {}, b'', self)

class Response:
    def __init__(self, status, hdr, raw, client):
        self.status, self.raw = status, raw
        self.version = hdr.get('x-amz-version-id')
        self.request_id = hdr.get('x-amz-request-id')
        self.code = field(raw, 'Code') if status >= 400 else None
        self.message = field(raw, 'Message') if status >= 400 else None
        if self.message:
            self.message = self.message.replace(client.access,'[redacted]').replace(client.secret,'[redacted]')
    def summary(self):
        return dict(status=self.status, version_id=self.version, request_id=self.request_id, service_code=self.code, service_message=self.message, body_sha256=digest(self.raw))

def field(raw, tag):
    try: root = ET.fromstring(raw)
    except ET.ParseError: return None
    return next((n.text for n in root.iter() if n.tag.split('}')[-1] == tag), None)

checks=[]
def checkpoint(name, ok, **data):
    checks.append(dict(name=name,passed=ok,**data))
    OUT.write_text(json.dumps(dict(run=RUN,endpoint=ORIGIN,protected=PROT,unprotected=PLAIN,control=CONTROL,retention=until,checks=checks), indent=2)+'\n')
    print('pass' if ok else 'FAIL',name,flush=True)
    return ok

def require(name,response,statuses):
    if not checkpoint(name,response.status in statuses,response=response.summary()):
        raise SystemExit(2)

def date_xml(mode, stamp):
    return xml('Retention', f'<Mode>{mode}</Mode><RetainUntilDate>{stamp}</RetainUntilDate>')


def verify_version(client, bucket, key, version, expected, stamp):
    body = client.call('GET', bucket, key, {'versionId':version})
    ret = client.call('GET', bucket, key, {'retention':'','versionId':version})
    actual = field(ret.raw, 'RetainUntilDate')
    mode = field(ret.raw, 'Mode')
    valid_stamp = False
    if actual:
        try: valid_stamp = dt.datetime.fromisoformat(actual) == dt.datetime.fromisoformat(stamp)
        except ValueError: pass
    ok = body.status==200 and body.version==version and body.raw==expected and ret.status==200 and mode=='COMPLIANCE' and valid_stamp
    return ok, dict(get=body.summary(), retention=ret.summary(), mode=mode, retain_until=actual)


def main():
    global until
    admin, runtime = Client('rgwq110-admin'), Client('rgwq110-runtime')
    assert admin.access != runtime.access and admin.secret != runtime.secret
    for bucket in (PROT, CONTROL, PLAIN):
        hdr = {'x-amz-bucket-object-lock-enabled':'true'} if bucket != PLAIN else {}
        require('create_'+bucket, admin.call('PUT',bucket,headers=hdr), (200,201))
        require('enable_versioning_'+bucket,admin.call('PUT',bucket,query={'versioning':''},data=xml('VersioningConfiguration','<Status>Enabled</Status>')), (200,204))
    lock_xml=xml('ObjectLockConfiguration','<ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>1</Days></DefaultRetention></Rule>')
    require('configure_compliance_default',admin.call('PUT',PROT,query={'object-lock':''},data=lock_xml),(200,204))
    # No object-administration, identity-management or retention mutations are granted.
    policy={'Version':'2012-10-17','Statement':[
        {'Effect':'Allow','Principal':{'AWS':'arn:aws:iam:::user/rgwq110-runtime'},'Action':['s3:GetBucketVersioning','s3:GetBucketObjectLockConfiguration','s3:ListBucketVersions'],'Resource':['arn:aws:s3:::'+PROT]},
        {'Effect':'Allow','Principal':{'AWS':'arn:aws:iam:::user/rgwq110-runtime'},'Action':['s3:PutObject','s3:GetObjectVersion','s3:GetObjectRetention'],'Resource':['arn:aws:s3:::'+PROT+'/*']},
    ]}
    if STORAGE=='ceph':
        require('install_runtime_policy',admin.call('PUT',PROT,query={'policy':''},data=json.dumps(policy).encode()),(200,204))
    v=runtime.call('GET',PROT,query={'versioning':''})
    o=runtime.call('GET',PROT,query={'object-lock':''})
    if not checkpoint('actual_runtime_bucket_config',v.status==o.status==200 and field(v.raw,'Status')=='Enabled' and field(o.raw,'ObjectLockEnabled')=='Enabled' and field(o.raw,'Mode')=='COMPLIANCE', versioning=v.summary(),object_lock=o.summary(),versioning_xml=v.raw.decode(),object_lock_xml=o.raw.decode()): raise SystemExit(2)
    hdr={'x-amz-object-lock-mode':'COMPLIANCE','x-amz-object-lock-retain-until-date':until}
    if DEFAULT_ONLY: hdr={}
    key='evidence/original'
    body=b'Charter C04 exact synthetic evidence bytes\n'
    put=runtime.call('PUT',PROT,key,headers=hdr|{'if-none-match':'*'},data=body)
    if not checkpoint('actual_runtime_protected_put',put.status in (200,201) and put.version not in (None,'','null'),write=put.summary(),expected_sha256=digest(body),retain_until=until): raise SystemExit(2)
    ver=put.version
    if DEFAULT_ONLY:
        vr=runtime.call('GET',PROT,key,{'retention':'','versionId':ver})
        observed=field(vr.raw,'RetainUntilDate')
        if not checkpoint('default_applied_by_storage', bool(observed and dt.datetime.fromisoformat(observed)>NOW+dt.timedelta(hours=23)), response=vr.summary(), retain_until=observed): raise SystemExit(2)
        until=observed
    q={'versionId':ver}
    ok, observed=verify_version(runtime,PROT,key,ver,body,until)
    if not checkpoint('protected_initial_readback',ok,**observed): raise SystemExit(2)
    # Positive controls are needed to disambiguate a refusal under admin.
    ctrl=admin.call('PUT',PLAIN,'positive/delete',data=body)
    d=admin.call('DELETE',PLAIN,'positive/delete',{'versionId':ctrl.version or '?'})
    missing=admin.call('GET',PLAIN,'positive/delete',{'versionId':ctrl.version or '?'})
    checkpoint('admin_unprotected_exact_delete_positive',ctrl.status==200 and ctrl.version not in (None,'','null') and d.status==204 and missing.status==404,put=ctrl.summary(),delete=d.summary(),readback=missing.summary())
    ctrl=admin.call('PUT',CONTROL,'positive/retain',data=body)
    r=admin.call('PUT',CONTROL,'positive/retain',{'versionId':ctrl.version or '?','retention':''},data=date_xml('COMPLIANCE',shorter))
    ok,observed=verify_version(admin,CONTROL,'positive/retain',ctrl.version or '?',body,shorter)
    checkpoint('admin_set_retention_on_unprotected_version',ctrl.status==200 and r.status in (200,204) and ok,put=ctrl.summary(),mutation=r.summary(),**observed)
    for name, actor, method, rq, hdrs, payload in (
      ('admin_delete_exact',admin,'DELETE',q,{},b''),
      ('admin_bypass_compliance',admin,'DELETE',q,{'x-amz-bypass-governance-retention':'true'},b''),
      ('admin_shorten_to_future',admin,'PUT',q|{'retention':''},{},date_xml('COMPLIANCE',shorter)),
      ('runtime_delete_exact',runtime,'DELETE',q,{},b''),
      ('runtime_delete_marker',runtime,'DELETE',{}, {},b''),
      ('runtime_shorten_to_future',runtime,'PUT',q|{'retention':''},{},date_xml('COMPLIANCE',shorter)),
      ('runtime_downgrade',runtime,'PUT',q|{'retention':''},{},date_xml('GOVERNANCE',longer)),
      ('runtime_remove_retention',runtime,'PUT',q|{'retention':''},{},xml('Retention','')),
      ('runtime_bypass_compliance',runtime,'DELETE',q,{'x-amz-bypass-governance-retention':'true'},b''),
    ):
        op=actor.call(method,PROT,key,rq,hdrs,payload)
        good, observed=verify_version(runtime,PROT,key,ver,body,until)
        valid=op.status in (400,403) and op.code in ('AccessDenied','InvalidRequest','InvalidArgument') and good
        # An empty retention XML rejection is only a malformed-request result,
        # not by itself proof that a valid removal mechanism is prohibited.
        status='REFUSED' if valid and ('remove_retention' not in name or (DEFAULT_ONLY and op.status==403 and op.code=='AccessDenied')) else 'ALLOWED' if 200<=op.status<300 else 'INCONCLUSIVE'
        checkpoint(name,status=='REFUSED',outcome=status,mutation=op.summary(),**observed)
    impostor=b'latest version is not authoritative\n'
    new=runtime.call('PUT',PROT,key,headers=hdr,data=impostor)
    latest=admin.call('GET',PROT,key)
    good, observed=verify_version(runtime,PROT,key,ver,body,until)
    checkpoint('new_latest_never_substitutes_exact_version',new.status==200 and new.version!=ver and latest.status==200 and latest.raw==impostor and latest.version==new.version and good,write=new.summary(),latest=latest.summary(),**observed)
    versioning_off=xml('VersioningConfiguration','<Status>Suspended</Status>')
    lock_unset=xml('ObjectLockConfiguration','<ObjectLockEnabled>Enabled</ObjectLockEnabled>')
    deny_policy=json.dumps({'Version':'2012-10-17','Statement':[dict(Effect='Deny', Principal='*',Action='s3:DeleteObject',Resource='arn:aws:s3:::'+PROT+'/probe/*')]}).encode()
    lifecycle=xml('LifecycleConfiguration','<Rule><ID>synthetic-disabled</ID><Filter><Prefix>probe/</Prefix></Filter><Status>Disabled</Status><Expiration><Days>1</Days></Expiration></Rule>')
    for name, bucket, method, target, query, data in (
        ('runtime_bucket_delete',PROT,'DELETE','',{},b''),
        ('runtime_suspend_versioning',PROT,'PUT','',{'versioning':''},versioning_off),
        ('runtime_remove_lock_default',PROT,'PUT','',{'object-lock':''},lock_unset),
        ('runtime_write_policy',PROT,'PUT','',{'policy':''},deny_policy),
        ('runtime_write_lifecycle',PROT,'PUT','',{'lifecycle':''},lifecycle),
        ('runtime_write_other_bucket',PLAIN,'PUT','probe/unprotected',{},body),
        ('runtime_unqualified_latest_read',PROT,'GET',key,{},b''),
    ):
        op=runtime.call(method,bucket,target,query,data=data)
        good, observed=verify_version(runtime,PROT,key,ver,body,until)
        status='REFUSED' if op.status==403 and op.code=='AccessDenied' and good else 'ALLOWED' if 200<=op.status<300 else 'INCONCLUSIVE'
        checkpoint(name,status=='REFUSED',outcome=status,mutation=op.summary(),**observed)
    if DEFAULT_ONLY:
        for label,mode in (('wrong_initial_mode','GOVERNANCE'),('explicit_short_retention','COMPLIANCE')):
            res=runtime.call('PUT',PROT,'probe/'+label,headers={'x-amz-object-lock-mode':mode,'x-amz-object-lock-retain-until-date':shorter},data=body)
            checkpoint(label,res.status==403 and res.code=='AccessDenied',mutation=res.summary())
        res=runtime.call('POST','',headers={'content-type':'application/x-www-form-urlencoded'},data=b'Action=CreateAccessKey&UserName=rgwq110-admin&Version=2010-05-08',service='iam')
        checkpoint('runtime_admin_key_creation',res.status==403 and res.code in ('AccessDenied','AccessDeniedException'),mutation=res.summary())
    if STORAGE=='seaweed':
        # Credentials are scoped outside the protected bucket as well as within it.
        # A legal-hold write changes controls on an existing version and is not a C04 permission.
        hold=runtime.call('PUT',PROT,key,q|{'legal-hold':''},data=xml('LegalHold','<Status>ON</Status>'))
        good, observed=verify_version(runtime,PROT,key,ver,body,until)
        checkpoint('runtime_cannot_change_legal_hold',hold.status==403 and hold.code=='AccessDenied' and good,mutation=hold.summary(),**observed)
    for i in range(6):
        race_key=f'races/empty-{i}'
        barrier=threading.Barrier(32)
        def writer(n):
            data=f'writer {n} {uuid.uuid4().hex}\n'.encode()
            barrier.wait(timeout=10)
            result=runtime.call('PUT',PROT,race_key,headers=hdr|{'if-none-match':'*'},data=data)
            return dict(writer=n,expected_sha256=digest(data),**result.summary())
        with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
            results=list(executor.map(writer,range(32)))
        listed=runtime.call('GET',PROT,query={'versions':'','prefix':race_key})
        versions=[]
        if listed.status==200:
            for node in ET.fromstring(listed.raw):
                if node.tag.split('}')[-1]=='Version':
                    elem={n.tag.split('}')[-1]:n.text for n in node}
                    if elem.get('Key')==race_key: versions.append(elem['VersionId'])
        winners=[r for r in results if 200<=r['status']<300]
        ver=winners[0]['version_id'] if len(winners)==1 else None
        reread=runtime.call('GET',PROT,race_key,{'versionId':ver}) if ver else None
        checkpoint(f'conditional_create_32_round_{i}',len(winners)==1 and versions==[ver] and reread is not None and reread.status==200 and digest(reread.raw)==winners[0]['expected_sha256'] and all(r['status'] in (200,409,412) for r in results),attempts=results,version_ids=versions,version_list=listed.summary(),winner_readback=reread.summary() if reread else None)
    if DEFAULT_ONLY:
        return 0 if all(c['passed'] for c in checks) else 2
    opts=os.environ.copy()
    opts.update(CHARTER_RETENTION_PROBE_OPT_IN='I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB',CHARTER_RETENTION_PROBE_ENDPOINT=ORIGIN,CHARTER_RETENTION_PROBE_REGION='us-east-1',CHARTER_RETENTION_PROBE_PROTECTED_BUCKET=PROT,CHARTER_RETENTION_PROBE_UNPROTECTED_BUCKET=PLAIN,CHARTER_RETENTION_PROBE_CONTROL_BUCKET=CONTROL,CHARTER_RETENTION_RUNTIME_ACCESS_KEY=runtime.access,CHARTER_RETENTION_RUNTIME_SECRET_KEY=runtime.secret,CHARTER_RETENTION_ADMIN_ACCESS_KEY=admin.access,CHARTER_RETENTION_ADMIN_SECRET_KEY=admin.secret)
    import subprocess
    proc=subprocess.run(['/mnt/rgw-payload/charter-retention-probe','--execute'],env=opts,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
    clean=proc.stdout.decode(errors='replace')
    for sensitive in (admin.access,admin.secret,runtime.access,runtime.secret): clean=clean.replace(sensitive,'[redacted]')
    OUT.with_suffix('.charter-probe.log').write_text(clean)
    checkpoint('exact_head_charter_native_cli',proc.returncode==0,exit_code=proc.returncode)
    # There are intentionally still broader C04 qualification tests outside this probe.
    return 0 if all(c['passed'] for c in checks) else 2


if __name__=='__main__':
    raise SystemExit(main())
