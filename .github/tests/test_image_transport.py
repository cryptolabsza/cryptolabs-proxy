"""Public image artifact boundary: real recipe shapes and package visibility continuity."""
import importlib.util,json,sys,unittest,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
class ImageBoundary(unittest.TestCase):
 def module(self):
  p=ROOT/'.github/image-publisher';sys.path.insert(0,str(p));spec=importlib.util.spec_from_file_location('public_image_transport',p/'transport.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 def test_real_producer_exports_complete_oci_images_without_authority(self):
  p=ROOT/'.github/workflows/ci-image-build-recipe.yml';self.assertTrue(p.exists());d=yaml.safe_load(p.read_text());job=d['jobs']['build'];self.assertEqual(job['runs-on']['group'],'ci-build-public-ephemeral');self.assertEqual(job['permissions'],{'contents':'read'});self.assertNotIn('secrets.',p.read_text())
  builds=[s for s in job['steps'] if s.get('uses','').startswith('docker/build-push-action@')];self.assertEqual(len(builds),3 if ROOT.name.startswith('dc-overview') else 1)
  for s in builds:self.assertIs(s['with']['push'],False);self.assertIs(s['with']['provenance'],False);self.assertIn('type=oci,',s['with']['outputs'])
  if len(builds)==3:self.assertEqual([s['with']['context'] for s in builds],['.','./runpod-exporter','./vastai-exporter']);self.assertIn('Verify packaged RunPod health contract',str(job));self.assertIn('Test Vast dashboards',str(job));self.assertIn('Verify RunPod exporter health and alert contract',str(job))
 def package(self,visibility='public',id=12):return {'id':id,'name':'sample','package_type':'container','owner':{'login':'cryptolabsza'},'visibility':visibility}
 def test_existing_visibility_and_id_are_preserved_for_all_visibility_modes(self):
  m=self.module()
  for visibility in ['public','private','internal']:
   before=m.package_identity('sample',200,self.package(visibility));self.assertEqual(m.package_identity('sample',200,self.package(visibility),after=True,previous=before),before)
   for mutation in [self.package(visibility,13),self.package('private' if visibility!='private' else 'public')]:
    with self.assertRaises(m.Held):m.package_identity('sample',200,mutation,after=True,previous=before)
 def test_actual_403_shapes_are_not_absence_and_new_package_stays_private(self):
  m=self.module()
  for code in [401,403,500]:
   with self.assertRaises(m.Held):m.package_identity('sample',code,{'message':'You need at least read:packages scope to get a package.'})
  self.assertIsNone(m.package_identity('sample',404,{'message':'Not Found','status':'404'}))
  self.assertEqual(m.package_identity('sample',200,self.package('private'),after=True,previous=None),{'id':12,'visibility':'private'})
  with self.assertRaises(m.Held):m.package_identity('sample',200,self.package('public'),after=True,previous=None)
 def test_metadata_main_guard_reuses_frozen_tag_policy(self):
  if ROOT.name.startswith('ipmi-monitor'):return
  import base64,os,tempfile
  from unittest.mock import patch
  m=self.module();name='dc-overview' if ROOT.name.startswith('dc-overview') else 'cryptolabs-proxy'
  class Policy:repository='cryptolabsza/'+name
  data=('[project]\nname="'+name+'"\nversion="1.2.3"\n').encode();api=lambda path:{'encoding':'base64','path':'pyproject.toml','size':len(data),'content':base64.b64encode(data).decode()}
  with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'GITHUB_SHA':'a'*40,'RUNNER_TEMP':td,'GITHUB_OUTPUT':td+'/output'}):
   receipt=m.metadata(Policy(),'preflight',api);self.assertEqual((receipt['status'],receipt['build'],receipt['channel']),('discovery',True,'main'));self.assertEqual(receipt['release']['version'],'1.2.3');self.assertEqual(receipt['operations'],[])
 def test_partial_promotion_retains_exact_operations_and_always_upload(self):
  if ROOT.name.startswith('ipmi-monitor'):return
  import os,tempfile
  from unittest.mock import patch
  m=self.module();import image_promotion as promotion
  name='dc-overview' if ROOT.name.startswith('dc-overview') else 'cryptolabs-proxy';sha='a'*40
  class Policy:repository='cryptolabsza/'+name
  class Client:
   def release_commit(self,*args):return sha
  receipt={'status':'partial','targets':[{'repository':'target'}],'operations':[{'alias':'latest','before_digest':'sha256:old','after_digest':'sha256:new'}],'error_code':'alias_readback_mismatch'}
  api=lambda path: {'protected':True,'commit':{'sha':sha}} if '/branches/' in path else {'status':'identical','merge_base_commit':{'sha':sha}}
  with tempfile.TemporaryDirectory() as td,patch.dict(os.environ,{'RUNNER_TEMP':td}),patch.object(m,'source_version',return_value='1.2.3'),patch.object(m,'package_gate',return_value={}),patch.object(promotion,'Client',return_value=Client()),patch.object(promotion,'promote',return_value=receipt):
   try:m.promote(Policy(),[name],'v1.2.3',sha,{name:'sha256:'+'b'*64},api)
   except m.Held:pass
   saved=Path(td)/'promotion-receipt.json';self.assertTrue(saved.exists(),'partial alias mutation must retain its exact receipt');self.assertEqual(json.loads(saved.read_text()),receipt)
  leaf=yaml.safe_load((ROOT/'.github/workflows/ci-image-promote-recipe.yml').read_text())['jobs']['promote'];upload=next(s for s in leaf['steps'] if s.get('uses','').startswith('actions/upload-artifact@'));self.assertEqual(upload['if'],'always()');self.assertEqual(upload['with']['name'],'image-promotion-receipt');self.assertEqual(upload['with']['retention-days'],90)
 def test_immutable_publisher_has_only_literal_helpers_and_no_application_execution(self):
  p=ROOT/'.github/workflows/ci-image-publish-recipe.yml';self.assertTrue(p.exists());d=yaml.safe_load(p.read_text())
  for name,j in d['jobs'].items():
   self.assertEqual(j['runs-on']['group'],'ci-publish-ephemeral');self.assertIn("github.ref == 'refs/heads/main'",j['if']);self.assertIn('github.ref_protected == true',j['if']);checkout=j['steps'][0];self.assertRegex(checkout['with']['ref'],r'^[0-9a-f]{40}$');self.assertFalse(checkout['with']['persist-credentials']);self.assertFalse(checkout['with']['sparse-checkout-cone-mode']);self.assertTrue(all(x.startswith('/.github/image-publisher/') for x in checkout['with']['sparse-checkout'].splitlines()))
   for forbidden in ['docker build','pip install','scripts/image_promotion.py','secrets.CR_PAT','secrets: inherit']:self.assertNotIn(forbidden,str(j))
 def test_numeric_publisher_pins_reviewed_helpers_and_uses_only_its_job_registry_token(self):
  leaf=yaml.safe_load((ROOT/'.github/workflows/ci-image-publish-recipe.yml').read_text())
  job=leaf['jobs']['publish']
  self.assertEqual(job['steps'][0]['with']['ref'],'e71ede75c2c8bedb070e3b60ff84b5906517d9ba')
  publish=next(step for step in job['steps'] if step['name']=='Verify actual producer and publish exact artifact bytes')
  self.assertEqual(publish['env'],{'GH_TOKEN':'${{ github.token }}','GHCR_USER':'${{ github.actor }}','GHCR_TOKEN':'${{ github.token }}','PRODUCER_RUN_ID':'${{ inputs.producer_run_id }}','PRODUCER_ATTEMPT':'${{ inputs.producer_attempt }}','ARTIFACT_ID':'${{ inputs.artifact_id }}'})
  self.assertNotIn('secrets',leaf.get('on',leaf.get(True))['workflow_call'])
  self.assertEqual(set(leaf.get('on',leaf.get(True))['workflow_call']['inputs']),{'producer_run_id','producer_attempt','artifact_id'})

class NumericReleaseTransport(unittest.TestCase):
 module=ImageBoundary.module
 def fixture(self,directory):
  import base64,hashlib,io,tarfile
  root=Path(directory);sha='a'*40;version='1.2.3';repository='cryptolabsza/cryptolabs-proxy'
  encode=lambda value:json.dumps(value,separators=(',',':')).encode()
  digest=lambda data:'sha256:'+hashlib.sha256(data).hexdigest()
  config=encode({'os':'linux','architecture':'amd64','config':{'Labels':{'org.opencontainers.image.source':'https://github.com/'+repository,'org.opencontainers.image.revision':sha,'org.opencontainers.image.version':version}}})
  manifest=encode({'schemaVersion':2,'mediaType':'application/vnd.oci.image.manifest.v1+json','config':{'mediaType':'application/vnd.oci.image.config.v1+json','digest':digest(config),'size':len(config)},'layers':[]})
  descriptor={'mediaType':'application/vnd.oci.image.manifest.v1+json','digest':digest(manifest),'size':len(manifest),'annotations':{'org.opencontainers.image.ref.name':'ghcr.io/'+repository+':'+version}}
  archive=root/'cryptolabs-proxy.tar'
  with tarfile.open(archive,'w',format=tarfile.USTAR_FORMAT) as output:
   for name,data in {'oci-layout':encode({'imageLayoutVersion':'1.0.0'}),'index.json':encode({'schemaVersion':2,'manifests':[descriptor]}),'blobs/sha256/'+digest(config)[7:]:config,'blobs/sha256/'+digest(manifest)[7:]:manifest}.items():
    item=tarfile.TarInfo(name);item.size=len(data);output.addfile(item,io.BytesIO(data))
  proof={'head_sha':sha,'branch':'main','event':'push','run_id':123,'run_attempt':1}
  context={'repository':repository,'repository_id':1140353276,'sha':sha,'branch':'main','run_id':123,'run_attempt':1}
  archive.with_suffix('.json').write_text(json.dumps({'artifact_kind':'oci-archive','expected_image':'ghcr.io/'+repository,'repository':repository,'repository_id':1140353276,'source_sha':sha,'run_id':'123','run_attempt':'1','filename':archive.name,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}))
  class Policy:pass
  policy=Policy();policy.repository=repository;policy.repository_id=1140353276
  source=('[project]\nname="cryptolabs-proxy"\nversion="'+version+'"\n').encode()
  def api(path):
   self.assertEqual(path,'/repos/'+repository+'/contents/pyproject.toml?ref='+sha)
   return {'encoding':'base64','path':'pyproject.toml','size':len(source),'content':base64.b64encode(source).decode()}
  return policy,proof,context,api,manifest,digest(manifest)
 def test_numeric_main_producer_receipt_and_oci_selection_match_publisher(self):
  import tempfile
  m=self.module()
  with tempfile.TemporaryDirectory() as td:
   policy,proof,context,api,manifest,digest=self.fixture(td)
   plans=m.prepare(policy,['cryptolabs-proxy'],Path(td),proof,context,api)
   tags=['main','sha-main-'+'a'*40,'1.2.3','v1.2.3','sha-'+'a'*40]
   self.assertEqual(plans[0]['digest'],digest)
   self.assertEqual(plans[0]['destinations'],['ghcr.io/'+policy.repository+':'+tag for tag in tags[::-1]])
   self.assertEqual(plans[0]['selection'],'ghcr.io/'+policy.repository+':1.2.3')
 def test_immutable_collisions_and_indeterminate_reads_never_write(self):
  import tempfile
  from unittest.mock import Mock,patch
  m=self.module()
  tags=['1.2.3','v1.2.3','sha-'+'a'*40,'sha-main-'+'a'*40]
  with tempfile.TemporaryDirectory() as td:
   policy,proof,context,api,manifest,digest=self.fixture(td)
   plans=[{'digest':digest,'destinations':['ghcr.io/'+policy.repository+':'+tag for tag in tags]}]
   for tag in tags:
    for error in [False,True]:
     with self.subTest(tag=tag,error=error):
      client=Mock();registry=Mock()
      def lookup(repo,ref,missing=False):
       if ref==tag:
        if error:raise RuntimeError('registry_request_failed')
        return b'different manifest','application/vnd.oci.image.manifest.v1+json'
       return None
      client.manifest.side_effect=lookup
      with patch.object(m.frozen,'publish') as publish:
       with self.assertRaises((m.Held,RuntimeError)):
        m.publish_verified(plans,policy,proof,registry,api,client)
       publish.assert_not_called();self.assertEqual(registry.mock_calls,[])
 def test_absent_and_identical_immutable_tags_allow_exact_artifact_retry(self):
  import tempfile
  from unittest.mock import Mock,patch
  m=self.module();tags=['1.2.3','v1.2.3','sha-'+'a'*40,'sha-main-'+'a'*40]
  with tempfile.TemporaryDirectory() as td:
   policy,proof,context,api,manifest,digest=self.fixture(td)
   plans=[{'digest':digest,'destinations':['ghcr.io/'+policy.repository+':'+tag for tag in tags]}]
   for existing in [None,(manifest,'application/vnd.oci.image.manifest.v1+json')]:
    client=Mock();client.manifest.return_value=existing;registry=Mock()
    with patch.object(m.frozen,'publish',return_value='published') as publish:
     self.assertEqual(m.publish_verified(plans,policy,proof,registry,api,client),'published')
     self.assertEqual([call.args[1] for call in client.manifest.call_args_list],tags)
     self.assertTrue(all(call.kwargs=={'missing':True} for call in client.manifest.call_args_list))
     publish.assert_called_once_with(plans,registry)

if __name__=='__main__':unittest.main()
