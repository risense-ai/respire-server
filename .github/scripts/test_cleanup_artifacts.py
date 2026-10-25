import copy
import datetime as dt
import hashlib
import io
import json
import tarfile
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile
import cleanup_artifacts as m

REPO='risense-ai/example'
AT='2026-10-25T00:00:00Z'
NOW=dt.datetime(2026,10,25,2,tzinfo=dt.timezone.utc)
POLICY={'repository':REPO,'workflows':{'.github/workflows/build.yml':{'mode':'completed','artifacts':['payload-[a-z]+'],'consumer_workflows':['.github/workflows/build.yml']}}}
PAYLOAD={'id':1,'name':'payload-linux','size_in_bytes':10,'digest':'sha256:'+'a'*64,'created_at':AT,'expired':False,'workflow_run':{'id':10}}
RECEIPT={**PAYLOAD,'id':2,'name':m.RECEIPT}
RUN={'id':10,'repository':{'full_name':REPO},'head_repository':{'full_name':REPO},'head_sha':'b'*40,'run_attempt':1,'path':'.github/workflows/build.yml','event':'workflow_dispatch','status':'completed','conclusion':'success','created_at':AT,'updated_at':AT}
DATA={'schema':1,'policy':'consumed-actions-v1','repository':REPO,'workflow':RUN['path'],'run_id':10,'attempt':1,'head_sha':RUN['head_sha'],'mode':'completed','created_at':AT,'artifacts':[m.identity(PAYLOAD)]}

class Fake:
 def __init__(self):
  self.run=copy.deepcopy(RUN);self.artifacts={a['id']:copy.deepcopy(a) for a in (PAYLOAD,RECEIPT)};self.jobs=[{'status':'completed','conclusion':'success','completed_at':AT}];self.later=[];self.deleted=[];self.unverified=False;self.reads=0;self.race=None
 def request(self,path,method='GET',**kw):
  if path.endswith('/runs/10'):return self.run
  if '/artifacts/' in path:
   i=int(path.rsplit('/',1)[1]);self.reads+=1
   if self.race:self.race(self)
   if method=='DELETE':
    self.deleted.append(i)
    if not self.unverified:self.artifacts.pop(i,None)
   return copy.deepcopy(self.artifacts.get(i))
  raise AssertionError(path)
 def pages(self,path,key):
  if key=='artifacts':return list(self.artifacts.values())
  if key=='jobs':return self.jobs
  if key=='workflow_runs':return self.later
  raise AssertionError(path)

class CleanupTests(unittest.TestCase):
 def clean(self,api=None,data=None,policy=None,**kw):
  api=api or Fake();m.clean(api,policy or POLICY,10,RECEIPT,data or DATA,NOW,**kw);return api
 def rejected(self,api=None,data=None,policy=None,**kw):
  api=api or Fake()
  with self.assertRaises(ValueError):self.clean(api,data,policy,apply=True,**kw)
  self.assertEqual(api.deleted,[])
 def test_complete_consumers_delete_payload_then_receipt(self):self.assertEqual(self.clean(apply=True).deleted,[1,2])
 def test_default_dry_run(self):self.assertEqual(self.clean().deleted,[])
 def test_failed_or_live_parent(self):
  for k,v in [('status','in_progress'),('conclusion','failure')]:
   a=Fake();a.run[k]=v;self.rejected(a)
 def test_active_or_failed_consumer_job(self):
  for status,conclusion in [('in_progress',None),('completed','failure'),('completed','cancelled')]:
   a=Fake();a.jobs=[{'status':status,'conclusion':conclusion,'completed_at':AT}];self.rejected(a)
 def test_other_running_workflow_blocks(self):
  a=Fake();a.later=[{**RUN,'id':11,'status':'in_progress'}];self.rejected(a)
 def test_own_cleanup_runs_do_not_reset_grace_forever(self):
  a=Fake();a.later=[{**RUN,'id':11,'path':'.github/workflows/cleanup-artifacts.yml','updated_at':'2026-10-25T01:59:00Z'}];self.assertEqual(self.clean(a,apply=True).deleted,[1,2])
 def test_later_consumer_resets_grace(self):
  a=Fake();a.later=[{**RUN,'id':11,'updated_at':'2026-10-25T01:59:00Z'}];self.rejected(a)
 def test_exact_one_hour_boundary(self):
  d=copy.deepcopy(DATA);d['created_at']='2026-10-25T01:00:01Z';self.rejected(data=d)
  d['created_at']='2026-10-25T01:00:00Z';self.assertEqual(self.clean(data=d,apply=True).deleted,[1,2])
 def test_foreign_attempt_head_workflow_or_id(self):
  for k,v in [('repository','risense-ai/other'),('attempt',2),('head_sha','c'*40),('workflow','other'),('run_id',11),('schema',2),('mode','sdk')]:
   d=copy.deepcopy(DATA);d[k]=v;self.rejected(data=d)
 def test_untrusted_pull_request_not_opted_in(self):
  a=Fake();a.run['event']='pull_request';self.rejected(a)
 def test_unknown_name_and_duplicate_id(self):
  d=copy.deepcopy(DATA);d['artifacts'][0]['name']='unrelated';self.rejected(data=d)
  d=copy.deepcopy(DATA);d['artifacts']*=2;self.rejected(data=d)
 def test_artifact_identity_change(self):
  a=Fake();a.artifacts[1]['digest']='sha256:'+'e'*64;self.rejected(a)
  a=Fake();a.artifacts[1]['workflow_run']['id']=11;self.rejected(a)
 def test_new_artifact_after_snapshot(self):
  a=Fake();a.artifacts[3]={**PAYLOAD,'id':3};self.rejected(a)
 def test_missing_or_duplicate_receipt(self):
  a=Fake();a.artifacts.pop(2);self.rejected(a)
  a=Fake();a.artifacts[3]={**RECEIPT,'id':3};self.rejected(a)
 def test_already_absent_payload_not_deleted_twice(self):
  a=Fake();a.artifacts.pop(1);self.assertEqual(self.clean(a,apply=True).deleted,[2])
 def test_recheck_before_each_delete(self):
  a=Fake()
  def race(fake):
   if fake.deleted:fake.run['run_attempt']=2
  a.race=race
  with self.assertRaises(ValueError):self.clean(a,apply=True)
  self.assertEqual(a.deleted,[1])
 def test_uncertain_delete_stops_without_retry(self):
  a=Fake();a.unverified=True
  with self.assertRaises(RuntimeError):self.clean(a,apply=True)
  self.assertEqual(a.deleted,[1])
 def test_external_delivery_requires_specific_manual_ack(self):
  p=copy.deepcopy(POLICY);p['workflows'][RUN['path']]['mode']='external-delivery';d={**DATA,'mode':'external-delivery'}
  self.rejected(data=d,policy=p);self.rejected(data=d,policy=p,acknowledged=11)
  self.assertEqual(self.clean(data=d,policy=p,acknowledged=10,apply=True).deleted,[1,2])
 def test_public_delivery_drift_blocks(self):
  p=copy.deepcopy(POLICY);p['workflows'][RUN['path']]['mode']='release';d={**DATA,'mode':'release','publication':{'tag':'v1','id':1}}
  a=Fake();a.release=lambda *args:{'tag':'v1','id':2};self.rejected(a,d,p)
 def sdk_fixture(self):
  target='x86_64-unknown-linux-gnu';name='internal-core-sdk-'+target
  p=copy.deepcopy(POLICY);p['workflows'][RUN['path']].update(mode='sdk',artifacts=[name])
  a=Fake();a.artifacts[1]['name']=name
  sdk={'sdk_version':'1.0.2-dev.11','target':target,'source_revision':RUN['head_sha'],'files':[{'path':'lib/core.a','sha256':hashlib.sha256(b'public-native').hexdigest()}]}
  d={**DATA,'mode':'sdk','sdk':[sdk],'artifacts':[m.identity(a.artifacts[1])]}
  a.sdk_publication=lambda row:{'manifest':sdk,'published_at':AT,'checksum':'f'*64}
  return a,d,p,sdk
 def test_delivered_native_crate_allows_sdk_cleanup(self):
  a,d,p,s=self.sdk_fixture();self.assertEqual(self.clean(a,d,p,apply=True).deleted,[1,2])
 def test_sdk_not_public_preserves_input(self):
  a,d,p,s=self.sdk_fixture()
  def missing(*args):raise ValueError('not published')
  a.sdk_publication=missing;self.rejected(a,d,p)
 def test_sdk_different_library_preserves_input(self):
  a,d,p,s=self.sdk_fixture();other=copy.deepcopy(s);other['files'][0]['sha256']='b'*64
  a.sdk_publication=lambda row:{'manifest':other,'published_at':AT};self.rejected(a,d,p)
 def test_sdk_recent_delivery_starts_new_grace(self):
  a,d,p,s=self.sdk_fixture();a.sdk_publication=lambda row:{'manifest':s,'published_at':'2026-10-25T01:59:00Z'};self.rejected(a,d,p)
 def test_sdk_manifest_source_target_or_version_drift(self):
  for key,value in [('source_revision','c'*40),('target','foreign'),('sdk_version','1.0.2-dev.99')]:
   a,d,p,s=self.sdk_fixture();other={**s,key:value};a.sdk_publication=lambda row:{'manifest':other,'published_at':AT};self.rejected(a,d,p)
 def registry_fixture(self, bad_payload=False, unsafe=False):
  a,d,p,s=self.sdk_fixture();name='respire-core-native-'+s['target'];version=s['sdk_version'];buffer=io.BytesIO()
  with tarfile.open(fileobj=buffer,mode='w:gz') as tar:
   for relative,raw in [('native/manifest.json',json.dumps(s).encode()),('native/lib/core.a',b'corrupt' if bad_payload else b'public-native')]:
    path=f'{name}-{version}/'+relative
    if unsafe:path=f'{name}-{version}/../'+relative
    member=tarfile.TarInfo(path);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
  raw=buffer.getvalue();metadata={'version':{'num':version,'yanked':False,'checksum':hashlib.sha256(raw).hexdigest(),'created_at':AT}}
  api=m.GitHub();calls=[]
  def public(url,limit):
   calls.append(url);return json.dumps(metadata).encode() if '/api/' in url else raw
  api.public_bytes=public
  return api,s,metadata,calls
 def test_native_crate_checksum_manifest_payload_and_cache(self):
  api,s,metadata,calls=self.registry_fixture();self.assertEqual(api.sdk_publication(s)['manifest'],s);api.sdk_publication(s)
  self.assertEqual(sum('/api/' not in url for url in calls),1)
  metadata['version']['yanked']=True
  with self.assertRaises(ValueError):api.sdk_publication(s)
 def test_native_crate_wrong_checksum_or_payload_or_path(self):
  api,s,metadata,calls=self.registry_fixture();metadata['version']['checksum']='f'*64
  with self.assertRaises(ValueError):api.sdk_publication(s)
  for kwargs in [{'bad_payload':True},{'unsafe':True}]:
   api,s,metadata,calls=self.registry_fixture(**kwargs)
   with self.assertRaises(ValueError):api.sdk_publication(s)
 def test_registry_calls_send_no_authorization_header(self):
  class Response:
   def __enter__(self):return self
   def __exit__(self,*args):return False
   def read(self,limit):return b'{}'
  class Opener:
   def open(self,request,timeout):
    self.request=request;return Response()
  opener=Opener()
  with patch.object(m,'build_opener',return_value=opener):m.GitHub().public_bytes('https://crates.io/api/v1/crates/example/1',100)
  self.assertIsNone(opener.request.get_header('Authorization'))
 def test_receipt_zip_security(self):
  for name,extra in [('cleanup-ready.json',False),('../cleanup-ready.json',False),('cleanup-ready.json',True)]:
   b=io.BytesIO()
   with zipfile.ZipFile(b,'w') as z:
    z.writestr(name,json.dumps(DATA))
    if extra:z.writestr('run.sh','exit 0')
   raw=b.getvalue();api=m.GitHub();api.request=lambda *args,**kw:raw;a={**RECEIPT,'size_in_bytes':len(raw),'digest':'sha256:'+hashlib.sha256(raw).hexdigest()}
   if name=='cleanup-ready.json' and not extra:self.assertEqual(api.receipt(REPO,a),DATA)
   else:
    with self.assertRaises(ValueError):api.receipt(REPO,a)
   a['digest']='sha256:'+'f'*64
   with self.assertRaises(ValueError):api.receipt(REPO,a)
 def test_workflow_permissions_and_opt_in(self):
  root=Path(__file__).resolve().parents[2]
  if not (root/'.github/cleanup-policy.json').exists():return
  policy=json.loads((root/'.github/cleanup-policy.json').read_text());self.assertTrue(policy['repository'].startswith('risense-ai/'))
  workflow=(root/'.github/workflows/cleanup-artifacts.yml').read_text();self.assertEqual(workflow.count('actions: write'),1);self.assertNotIn('write-all',workflow);self.assertIn('default: true',workflow);self.assertIn('persist-credentials: false',workflow);self.assertIn('github.event.repository.default_branch',workflow)

if __name__=='__main__':unittest.main()
