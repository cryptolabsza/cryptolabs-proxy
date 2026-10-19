"""Immutable local build recipe changes only artifact transport steps."""
import copy,hashlib,json,subprocess,unittest,yaml
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
BH='fb8f7a1386204489ba70f2cfeedb6e184ab5de75'
BH_BASE='df630185be901f29e4dcfc2bf1464475050e9db6'
class LocalBuildRecipeTests(unittest.TestCase):
 def test_build_recipe_pins_actual_producer_and_only_uploads_tiny_manifest(self):
  path='.github/workflows/ci-image-build-recipe.yml';recipe=yaml.safe_load((ROOT/path).read_text());job=recipe['jobs']['build'];steps=job['steps']
  checkout=next(s for s in steps if s['name']=='Checkout immutable local image producer')
  self.assertEqual(checkout['with']['ref'],BH);self.assertEqual(checkout['with']['repository'],'cryptolabsza/cryptolabs-proxy');self.assertFalse(checkout['with']['persist-credentials']);self.assertEqual(checkout['with']['path'],'.local-image-producer')
  self.assertEqual(checkout['with']['sparse-checkout'].splitlines(),['/.github/image-publisher/local_handoff.py','/.github/image-publisher/local_artifacts/'])
  verify=next(s for s in steps if s['name']=='Verify immutable local producer bytes')
  for name in ['local_handoff.py','local_artifacts/local_artifact.py','local_artifacts/local_artifact_routes.py','local_artifacts/verify_artifact.py']:
   raw=subprocess.check_output(['git','show',BH+':.github/image-publisher/'+name],cwd=ROOT);self.assertIn(hashlib.sha256(raw).hexdigest()+'  .local-image-producer/.github/image-publisher/'+name,verify['run'])
  handoff=next(s for s in steps if s['name']=='Upload fixed image bundle to local store');self.assertEqual(handoff['run'],'python3 .local-image-producer/.github/image-publisher/local_handoff.py');self.assertNotIn('env',handoff)
  upload=next(s for s in steps if s.get('id')=='upload');self.assertEqual(upload['with']['path'],'${{ runner.temp }}/image-local-manifest/manifest.json');self.assertEqual(upload['with']['compression-level'],0);self.assertEqual(upload['with']['retention-days'],7)
  baseline=yaml.safe_load(subprocess.check_output(['git','show',BH_BASE+':'+path],cwd=ROOT));normal=copy.deepcopy(recipe);normal['jobs']['build']['steps']=[s for s in normal['jobs']['build']['steps'] if s['name'] not in {checkout['name'],verify['name'],handoff['name']}]
  target=next(s for s in normal['jobs']['build']['steps'] if s.get('id')=='upload');target['with']=next(s for s in baseline['jobs']['build']['steps'] if s.get('id')=='upload')['with']
  self.assertEqual(normal,baseline)

PH='a1d268c29bffd8ba527ab44d4f91c3743fd47690'
PH_BASE='8d44aa3d81cd0177ae690c137cfd4f2f28299742'
class LocalPublicationRecipeTests(unittest.TestCase):
 def test_publisher_recipe_uses_exact_real_common_snapshot_without_permission_changes(self):
  path='.github/workflows/ci-image-publish-recipe.yml';actual=yaml.safe_load((ROOT/path).read_text());baseline=yaml.safe_load(subprocess.check_output(['git','show',PH_BASE+':'+path],cwd=ROOT));normal=copy.deepcopy(actual)
  for name,job in actual['jobs'].items():
   old=baseline['jobs'][name];checkout=job['steps'][0];self.assertEqual(checkout['with']['ref'],PH)
   sparse=checkout['with']['sparse-checkout'].splitlines();self.assertIn('/.github/image-publisher/local_artifact.py',sparse);self.assertIn('/.github/image-publisher/local_artifact_routes.py',sparse)
   verify=next(s for s in job['steps'] if s.get('name')=='Verify frozen upstream verifier and OCI parser');previous=next(s for s in old['steps'] if s.get('name')==verify['name'])
   oldhash='54bd08ddf7e59e755c0f21b3413699459cb837d152ff4b57716660f2ff71c7c3';newhash=hashlib.sha256(subprocess.check_output(['git','show',PH+':.github/image-publisher/verify_artifact.py'],cwd=ROOT)).hexdigest();extra=''
   for filename in ('local_artifact.py','local_artifact_routes.py'):
    raw=subprocess.check_output(['git','show',PH+':.github/image-publisher/'+filename],cwd=ROOT);extra+="echo '"+hashlib.sha256(raw).hexdigest()+'  publisher/.github/image-publisher/'+filename+"' | sha256sum --check -\n"
   self.assertEqual(verify['run'],previous['run'].replace(oldhash,newhash)+extra)
   normal['jobs'][name]['steps'][0]['with']=copy.deepcopy(old['steps'][0]['with'])
   next(s for s in normal['jobs'][name]['steps'] if s.get('name')==verify['name'])['run']=previous['run']
  self.assertEqual(normal,baseline)

P='c9cca957a75f6c95732fd96fbfc2a7d4e6094c87'
BR_REAL='ec3878ba156d8b461f90f3b0a93e65224b6214fa'
class LocalCallerTests(unittest.TestCase):
 def test_only_image_handoff_caller_pins_change_and_real_git_objects_resolve(self):
  path='.github/workflows/docker-build.yml';actual=yaml.safe_load((ROOT/path).read_text());baseline=yaml.safe_load(subprocess.check_output(['git','show',P+':'+path],cwd=ROOT));normal=copy.deepcopy(actual)
  expected={'build':('ci-image-build-recipe.yml',BR_REAL),'publish-build':('ci-image-publish-recipe.yml',P)}
  for job,(filename,sha) in expected.items():
   self.assertEqual(actual['jobs'][job]['uses'],'cryptolabsza/cryptolabs-proxy'+'/.github/workflows/'+filename+'@'+sha)
   frozen=yaml.safe_load(subprocess.check_output(['git','show',sha+':.github/workflows/'+filename],cwd=ROOT));self.assertIn('jobs',frozen)
   normal['jobs'][job]['uses']=baseline['jobs'][job]['uses']
  self.assertEqual(normal,baseline)
