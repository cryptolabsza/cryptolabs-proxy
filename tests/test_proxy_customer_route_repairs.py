"""Existing-customer setup/adoption route regressions; Docker is a boundary."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cryptolabs_proxy import auth, setup, standard_adoption as sa
from tests.test_proxy_recovery_tls_repairs import fixture, unchanged_files, old_startup, REF


@pytest.mark.parametrize('content', [b'{}', b'{"operator":', b'[]', b'{"operator":{"role":"admin"}}'])
def test_invalid_existing_identity_is_held_before_source_stop(tmp_path, monkeypatch, content):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    (data/'users.json').write_bytes(content)
    before = unchanged_files(data)
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    assert not any(c[0] == 'stop' for c in engine.calls)
    assert not any(c[0] == 'create' for c in engine.calls)
    assert engine.source['State']['Running']
    assert unchanged_files(data) == before


@pytest.mark.parametrize('candidate_failure', ['health', 'proof', 'external-drift'])
def test_source_endpoints_not_reconnected_before_restoration_and_proof(tmp_path, monkeypatch, candidate_failure):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    engine.fail_health = True
    connect = engine.connect
    reconnects = []
    def observed_connect(name, *args):
        if engine.inspect(name)['Id'] == 'source-79': reconnects.append(name)
        connect(name, *args)
    monkeypatch.setattr(engine, 'connect', observed_connect)
    if candidate_failure == 'proof':
        monkeypatch.setattr(engine, 'prove_recovery_auth', lambda *a: (_ for _ in ()).throw(sa.AdoptionError('proof_failed')))
    if candidate_failure == 'external-drift':
        engine.on_start = lambda name,obj: (data/'customer-unknown-file').write_text('external-drift') if obj['Image']=='sha256:candidate' else None
    with pytest.raises(sa.AdoptionError): adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    assert not reconnects
    assert not engine.source['State']['Running']
    if candidate_failure == 'health':
        assert engine.objects['cryptolabs-proxy']['State']['Running']
        assert engine.objects['cryptolabs-proxy']['Image'] == 'sha256:source'
    else:
        assert not engine.objects.get('cryptolabs-proxy', {}).get('State', {}).get('Running')


@pytest.mark.parametrize('running', [True, False])
@pytest.mark.parametrize('selected', [True, False])
def test_setup_existing_unadopted_customer_proxy_held_before_side_effects(tmp_path, monkeypatch, running, selected):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(setup, 'CONFIG_DIR', adoption.config_dir)
    before = unchanged_files(data)
    source = engine.source
    source['State']['Running'] = running
    calls=[]
    def run(command, **kwargs):
        calls.append(command)
        if command[:3]==['docker','inspect','cryptolabs-proxy']:
            return SimpleNamespace(returncode=0,stdout=json.dumps([source]),stderr='')
        if command[:2]==['docker','version']:
            return SimpleNamespace(returncode=0,stdout='linux/amd64',stderr='')
        raise AssertionError(command)
    monkeypatch.setattr(setup.subprocess,'run',run)
    mutated=[]
    monkeypatch.setattr(setup,'ensure_ssl_certs',lambda *a: mutated.append('ssl') or (True,'boundary cert'))
    monkeypatch.setattr(setup,'ensure_docker_network',lambda: mutated.append('network') or True)
    config = setup.ProxyConfig(settings['domain'],use_letsencrypt=False,
        release_selection_dir=Path(settings['release_selection_dir']) if selected else None)
    ok,message=setup.setup_proxy(config)
    assert not ok and 'configuration' in message and 'adopt' in message
    assert not mutated
    assert unchanged_files(data)==before
    assert source['State']['Running'] == running
    assert calls==[['docker','inspect','cryptolabs-proxy']]


def test_setup_docker_inspection_failure_is_not_absent_install(tmp_path, monkeypatch):
    monkeypatch.setattr(setup,'CONFIG_DIR',tmp_path)
    monkeypatch.setattr(setup.subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout='',stderr='Cannot connect to Docker daemon'))
    mutated=[]
    monkeypatch.setattr(setup,'ensure_ssl_certs',lambda *a:mutated.append('ssl') or (True,'boundary'))
    ok,message=setup.setup_proxy(setup.ProxyConfig('customer.example.test',use_letsencrypt=False))
    assert not ok and not mutated


@pytest.mark.parametrize('source_version', ['base', 'candidate'])
def test_new_updater_holds_actual_proxy_replacement_before_either_startup(tmp_path, monkeypatch, source_version):
    from cryptolabs_proxy import updates
    from tests.test_proxy_recovery_tls_repairs import startup
    adoption, engine, settings, data=fixture(tmp_path,monkeypatch)
    source=engine.source
    source['Image']='sha256:source' if source_version=='base' else 'sha256:candidate-source'
    source['Config']['Image']=source['Image']
    before=unchanged_files(data)
    # The source versions are real distinct auth startup modules, already
    # executing as the customer service; no updater may start either on hold.
    ready=startup(source_version,data,{'FLEET_ADMIN_USER':'operator','FLEET_ADMIN_PASS':'customer-secret-unchanged'})
    assert ready.returncode==0 and unchanged_files(data)==before
    monkeypatch.setattr(updates,'wait_ready',lambda *a,**k: False)
    result=updates.replace_container(engine,'cryptolabs-proxy',REF,'fault',timeout=0)
    assert result['state']=='blocked' and not result['success']
    assert result['reason']=='proxy_host_adoption_required'
    assert 'configuration plan --declaration' in result['message']
    assert 'configuration adopt --declaration' in result['message']
    assert not any(c[0] in ('stop','create','start','connect','rename') for c in engine.calls)
    assert unchanged_files(data)==before
    assert engine.source['State']['Running']


def test_new_updater_keeps_same_image_proxy_noop(tmp_path, monkeypatch):
    from cryptolabs_proxy import updates
    adoption,engine,settings,data=fixture(tmp_path,monkeypatch)
    before=unchanged_files(data)
    result=updates.replace_container(engine,'cryptolabs-proxy',engine.source['Image'],'noop',timeout=0)
    assert result['state']=='unchanged' and result['success']
    assert not engine.calls
    assert unchanged_files(data)==before


@pytest.mark.parametrize('selected', [False,True])
def test_bundle_proxy_hold_precedes_all_nonproxy_mutation(tmp_path, monkeypatch, selected):
    from cryptolabs_proxy import updates
    from tests.test_release_selection import SelectedEngine,proxy_selection
    from tests.test_updates import Engine,source
    if selected:
        selection_dir,ref=proxy_selection(tmp_path)
        engine=SelectedEngine(tmp_path)
        prior_image=engine.image
        def image(reference):
            if reference==ref:
                return {'Id':'sha256:proxy-new','Config':{},'RepoDigests':[ref],'Os':'linux','Architecture':'amd64'}
            return prior_image(reference)
        monkeypatch.setattr(engine,'image',image)
        engine.selection=(selection_dir/'selection.json').read_bytes()
        job=updates.submit_job('all','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=selection_dir)
        job['action']='update'
        updates.write_job(tmp_path/'jobs',job)
        engine.calls.clear()
    else:
        engine=Engine()
        proxy=source();proxy['Config']['Image']='ghcr.io/cryptolabsza/cryptolabs-proxy:latest'
        engine.containers['cryptolabs-proxy']=proxy
        monkeypatch.setattr(updates,'SERVICES',{n:updates.SERVICES[n] for n in ('prometheus','cryptolabs-proxy')})
        job={'id':'d'*32,'service':'all','branch':'main','action':'update'}
        updates.write_job(tmp_path/'jobs',job)
    pulls=[]
    monkeypatch.setattr(updates,'pull_target',lambda reference:pulls.append(reference) or True)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['state']=='blocked' and not result['success']
    assert result['reason']=='proxy_host_adoption_required'
    assert 'configuration plan' in result['message']
    assert not any(c[0] in ('stop','rename','create','start','connect') for c in engine.calls)
    assert engine.inspect('prometheus')['State']['Running']
    assert engine.inspect('cryptolabs-proxy')['State']['Running']


def test_new_updater_nonproxy_replacement_still_supported():
    from cryptolabs_proxy import updates
    from tests.test_updates import Engine
    engine=Engine()
    assert updates.replace_container(engine,'prometheus','sha256:new','normal',timeout=0)['success']
    assert ('stop','prometheus') in engine.calls


def test_additive_capabilities_getter_matches_cli_contract(capsys):
    from cryptolabs_proxy import updates
    capabilities=updates.get_capabilities()
    assert capabilities=={'selection_contract':1,'proxy_replacement_policy':'host-adoption-required-v1',
        'controller_adoption_guard':{'schema_version':1,'api':'AdoptionEngine.controller_guard',
                                     'durable_updater_exclusion':True}}
    assert type(capabilities['controller_adoption_guard']['schema_version']) is int
    assert capabilities['controller_adoption_guard']['durable_updater_exclusion'] is True
    assert updates.main(['capabilities'])==0
    assert json.loads(capsys.readouterr().out)==capabilities


@pytest.mark.parametrize('selected',[False,True])
def test_new_host_dispatcher_cannot_launch_old_proxy_replacement_helper(tmp_path,monkeypatch,selected):
    from cryptolabs_proxy import updates
    from tests.test_release_selection import SelectedEngine,proxy_selection
    from tests.test_updates import Engine,source
    if selected:
        directory,reference=proxy_selection(tmp_path)
        engine=SelectedEngine(tmp_path)
    else:
        directory=tmp_path/'no-selection'
        engine=Engine()
        proxy=source();proxy['Config']['Image']='ghcr.io/cryptolabsza/cryptolabs-proxy:latest'
        proxy['Mounts'].append({'Type':'bind','Source':str(tmp_path),'Destination':str(tmp_path),'RW':True})
        engine.containers['cryptolabs-proxy']=proxy
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert not engine.calls
    assert not (tmp_path/'jobs'/'active.json').exists()


@pytest.mark.parametrize('action',['update','pull'])
def test_selected_proxy_noop_and_pull_remain_supported(tmp_path,monkeypatch,action):
    from cryptolabs_proxy import updates
    from tests.test_release_selection import SelectedEngine,proxy_selection
    directory,reference=proxy_selection(tmp_path)
    engine=SelectedEngine(tmp_path)
    proxy=engine.containers['cryptolabs-proxy']
    proxy['Config']['Labels'][updates.WATCHTOWER_LABEL]='false'
    proxy['Image']='sha256:proxy-new' if action=='update' else 'sha256:old'
    prior_image=engine.image
    def image(ref):
        if ref==reference:
            return {'Id':'sha256:proxy-new','Config':{},'RepoDigests':[reference],'Os':'linux','Architecture':'amd64'}
        return prior_image(ref)
    monkeypatch.setattr(engine,'image',image)
    engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('cryptolabs-proxy','main',action,directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    engine.calls.clear()
    monkeypatch.setattr(updates,'pull_target',lambda ref:ref==reference)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['success']
    assert result['results']['cryptolabs-proxy']['state']==('unchanged' if action=='update' else 'checked')
    assert not engine.calls


def live_selection_engine(tmp_path,monkeypatch):
    from tests.test_release_selection import SelectedEngine,proxy_selection
    directory,reference=proxy_selection(tmp_path)
    engine=SelectedEngine(tmp_path)
    engine.containers['cryptolabs-proxy']['Config']['Labels']['com.centurylinklabs.watchtower.enable']='false'
    engine.containers['cryptolabs-proxy']['Config']['Image']='ghcr.io/cryptolabsza/cryptolabs-proxy:latest'
    prior=engine.image
    monkeypatch.setattr(engine,'image',lambda ref: {'Id':'sha256:old','Config':{},'RepoDigests':[reference],'Os':'linux','Architecture':'amd64'} if ref==reference else prior(ref))
    engine.selection=(directory/'selection.json').read_bytes()
    return directory,engine


@pytest.mark.parametrize('service,action',[('all','update'),('all','pull'),('prometheus','update')])
@pytest.mark.parametrize('capability',[None,{},[],{'selection_contract':True,'proxy_replacement_policy':'host-adoption-required-v1'}, {'selection_contract':1.0,'proxy_replacement_policy':'host-adoption-required-v1'}, {'selection_contract':1,'proxy_replacement_policy':'unknown'}, {'selection_contract':'1','proxy_replacement_policy':'host-adoption-required-v1'}])
def test_selected_dispatch_requires_live_capability_before_job_publication(tmp_path,monkeypatch,service,action,capability):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    queried=[]
    engine.updater_capabilities=lambda source_id:queried.append(source_id) or capability
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job(service,'main',action,directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert queried==[engine.inspect('cryptolabs-proxy')['Id']]
    assert not engine.calls
    assert not list((tmp_path/'jobs').glob('*.json'))


def test_selected_dispatch_daemon_failure_is_actionable_hold(tmp_path,monkeypatch):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    engine.updater_capabilities=lambda source_id:(_ for _ in ()).throw(RuntimeError('private daemon body'))
    with pytest.raises(updates.UpdateError,match='configuration adopt --declaration') as error:
        updates.submit_job('all','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert 'private daemon body' not in str(error.value)
    assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))


@pytest.mark.parametrize('version',['base','candidate'])
def test_selected_dispatch_queries_actual_old_and_current_updater_modules(tmp_path,monkeypatch,version):
    import subprocess,sys,os,shutil,hashlib
    from cryptolabs_proxy import updates
    from tests.test_proxy_recovery_tls_repairs import ROOT,BASE
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    tree=tmp_path/'runtime';shutil.copytree(ROOT/'src',tree/'src')
    if version=='base':
        raw=subprocess.run(['git','show',BASE+':src/cryptolabs_proxy/updates.py'],cwd=ROOT,capture_output=True,check=True).stdout
        (tree/'src/cryptolabs_proxy/updates.py').write_bytes(raw)
    print('ACTUAL_UPDATER',version,hashlib.sha256((tree/'src/cryptolabs_proxy/updates.py').read_bytes()).hexdigest())
    queried=[]
    def shipped(source_id):
        queried.append(source_id)
        result=subprocess.run([sys.executable,'-m','cryptolabs_proxy.updates','capabilities'],env={**os.environ,'PYTHONPATH':str(tree/'src')},capture_output=True,text=True,timeout=10)
        print('ACTUAL_UPDATER_CAPABILITIES',version,result.returncode,result.stdout.strip())
        return json.loads(result.stdout) if result.returncode==0 else None
    engine.updater_capabilities=shipped
    if version=='base':
        with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
            updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
        assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))
    else:
        assert updates.submit_job('all','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)['state']=='queued'
    assert queried==[engine.inspect('cryptolabs-proxy')['Id']]


@pytest.mark.parametrize('response',[SimpleNamespace(returncode=1,stdout=b'',stderr=b'private'),SimpleNamespace(returncode=0,stdout=b'not-json',stderr=b''),SimpleNamespace(returncode=0,stdout=b'[]',stderr=b''),SimpleNamespace(returncode=0,stdout=b' '*4097,stderr=b'')])
def test_live_capability_docker_boundary_rejects_bad_output(monkeypatch,response):
    from cryptolabs_proxy import updates
    monkeypatch.setattr(updates.subprocess,'run',lambda *a,**kw:response)
    with pytest.raises(updates.UpdateError): updates.UpdateEngine().updater_capabilities('source-id')


def test_live_capability_docker_boundary_uses_pinned_source_id(monkeypatch):
    from cryptolabs_proxy import updates
    calls=[]
    def run(command,**kwargs):
        calls.append((command,kwargs))
        return SimpleNamespace(returncode=0,stdout=json.dumps(updates.get_capabilities()).encode(),stderr=b'')
    monkeypatch.setattr(updates.subprocess,'run',run)
    assert updates.UpdateEngine().updater_capabilities('source-id')==updates.get_capabilities()
    assert calls==[(['docker','exec','source-id','env','PYTHONPATH=/app/src','python3','-m','cryptolabs_proxy.updates','capabilities'],{'capture_output':True,'timeout':15})]


def test_live_capability_probe_imports_shipped_source_in_clean_child(tmp_path,monkeypatch):
    import os,subprocess,sys
    from cryptolabs_proxy import updates
    runtime_source=Path(__file__).parents[1]/'src'
    source_id='a'*64
    # Model Docker's fresh exec environment and the image's /app/src mapping.
    # Execute the real module in a child; do not inherit pytest's sys.path.
    docker=tmp_path/'docker'
    docker.write_text(f'''#!{sys.executable}
import os,sys
assert sys.argv[1:3]==['exec',{source_id!r}]
command=[item.replace('PYTHONPATH=/app/src','PYTHONPATH='+{str(runtime_source)!r}) for item in sys.argv[3:]]
os.execvpe(command[0],command,{{'PATH':{str(Path(sys.executable).parent)+os.pathsep+os.defpath!r}}})
''')
    docker.chmod(0o755)
    monkeypatch.setenv('PATH',str(tmp_path)+os.pathsep+os.environ['PATH'])
    monkeypatch.chdir(tmp_path)
    without_path=subprocess.run(['docker','exec',source_id,'python3','-m',
        'cryptolabs_proxy.updates','capabilities'],capture_output=True,timeout=10)
    assert without_path.returncode!=0
    assert b"No module named 'cryptolabs_proxy'" in without_path.stderr
    print('WITHOUT_MODULE_PATH',without_path.returncode,without_path.stderr.decode().strip())
    actual=updates.UpdateEngine().updater_capabilities(source_id)
    assert actual==updates.get_capabilities()
    print('SHIPPED_CHILD_CAPABILITIES',json.dumps(actual,sort_keys=True))


def test_actual_old_worker_ignores_selected_noop_but_new_dispatch_refuses_it(tmp_path,monkeypatch):
    import importlib.util,subprocess
    from cryptolabs_proxy import updates
    from tests.test_proxy_recovery_tls_repairs import ROOT,BASE
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    old_file=tmp_path/'old-updates.py'
    prior=engine.image
    monkeypatch.setattr(engine,'image',lambda ref:{'Id':'sha256:new','Config':{},'Os':'linux','Architecture':'amd64'} if ref=='ghcr.io/cryptolabsza/cryptolabs-proxy:latest' else prior(ref))
    old_file.write_bytes(subprocess.run(['git','show',BASE+':src/cryptolabs_proxy/updates.py'],cwd=ROOT,capture_output=True,check=True).stdout)
    spec=importlib.util.spec_from_file_location('cryptolabs_proxy.old_updates_fixture',old_file)
    old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
    monkeypatch.setattr(old,'SERVICES',{name:old.SERVICES[name] for name in ('prometheus','cryptolabs-proxy')})
    monkeypatch.setattr(old,'pull_target',lambda reference:True)
    job={'id':'f'*32,'service':'all','branch':'main','action':'update','selection_snapshot':updates.installed_selection(directory)}
    old.write_job(tmp_path/'old-jobs',job)
    result=old.run_job(tmp_path/'old-jobs',job['id'],engine=engine)
    print('ACTUAL_OLD_IGNORED_SELECTION',result['state'],engine.calls)
    assert ('stop','cryptolabs-proxy') in engine.calls
    assert engine.inspect('cryptolabs-proxy')['Image']=='sha256:new'
    directory,safe=live_selection_engine(tmp_path/'safe',monkeypatch)
    safe.updater_capabilities=lambda source_id:None
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job('all','main','update',directory=tmp_path/'safe/jobs',engine=safe,selection_directory=directory)
    assert not safe.calls and not list((tmp_path/'safe/jobs').glob('*.json'))


def test_selected_dispatch_rechecks_capability_source_identity(tmp_path,monkeypatch):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    def changed(source_id):
        engine.containers['cryptolabs-proxy']['Id']='replacement-source'
        return updates.get_capabilities()
    engine.updater_capabilities=changed
    with pytest.raises(updates.UpdateError,match='configuration adopt --declaration'):
        updates.submit_job('prometheus','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))


def test_selected_dispatch_missing_live_boundary_holds(tmp_path,monkeypatch):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    monkeypatch.delattr(type(engine),'updater_capabilities')
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job('prometheus','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))


def test_selected_dispatch_rejects_policy_lookalike_object(tmp_path,monkeypatch):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    class PolicyLookalike(str): pass
    engine.updater_capabilities=lambda source_id:{'selection_contract':1,'proxy_replacement_policy':PolicyLookalike(updates.PROXY_REPLACEMENT_POLICY)}
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job('prometheus','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))


def test_selected_dispatch_checks_source_after_noop_image_inspection(tmp_path,monkeypatch):
    from cryptolabs_proxy import updates
    directory,engine=live_selection_engine(tmp_path,monkeypatch)
    prior=engine.image
    def drift(reference):
        if '@sha256:' in reference and reference.startswith('ghcr.io/cryptolabsza/cryptolabs-proxy'):
            engine.containers['cryptolabs-proxy']['Id']='drifted-source'
        return prior(reference)
    monkeypatch.setattr(engine,'image',drift)
    engine.updater_capabilities=lambda source_id:updates.get_capabilities()
    with pytest.raises(updates.UpdateError,match='configuration plan --declaration'):
        updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    assert not engine.calls and not list((tmp_path/'jobs').glob('*.json'))
