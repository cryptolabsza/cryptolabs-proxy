# TRACEWEAVER: file-role=verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Synthetic standard adoption: production render and compensated switch path."""
import hashlib
import json
from copy import deepcopy
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from click.testing import CliRunner
import pytest
from cryptolabs_proxy.config import generate_nginx_config
from cryptolabs_proxy.services import DEFAULT_SERVICES, ServiceRegistry

REF = 'ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:' + 'a'*64
KNOWN = ['ipmi-monitor','dc-overview','grafana','prometheus','vastai-exporter','runpod-exporter','vast-price-manager']


def declaration(tmp_path):
    directory=tmp_path/'releases'; (directory/'manifests').mkdir(parents=True)
    manifest={'schema_version':1,'selection_contract':1,'baseline_id':'synthetic', 'components':{
        'cryptolabs-proxy':{'release':'synthetic','owner':'proxy-updater','artifacts':{'linux/amd64':{'kind':'oci','reference':REF}}}}}
    raw=json.dumps(manifest).encode(); digest=hashlib.sha256(raw).hexdigest()
    (directory/'manifests'/(digest+'.json')).write_bytes(raw)
    selection={'schema_version':1,'selection_id':'synthetic-selection','manifest_sha256':digest,'components':{'cryptolabs-proxy':{'enabled':True,'origin':'baseline'}}}
    (directory/'selection.json').write_text(json.dumps(selection))
    return {'schema_version':1,'domain':'fleet.example.test','tls':'self-signed','release_selection_dir':str(directory),'services':{
        n:{k:DEFAULT_SERVICES[n][k] for k in ('container_name','path','port')} for n in KNOWN},'obsolete_overlays':[],'obsolete_owner_labels':[]}


class Engine:
    def __init__(self, config):
        self.config=config; self.calls=[]; self.auth=auth_tar({'users.json':b'synthetic-auth-archive'}); self.new_auth=None; self.fail_health=False; self.fail_restore=False
        self.current={'Id':'old-id','Image':'sha256:old','Config':{'Image':'old-ref','Env':['AUTH_SECRET_KEY=synthetic-key','FLEET_ADMIN_PASS=synthetic-password','KEEP=synthetic'], 'Labels':{'com.centurylinklabs.watchtower.enable':'true'},'Entrypoint':['/app/entrypoint.sh'],'Cmd':None},
        'State':{'Running':True,'Health':{'Status':'healthy'}},'HostConfig':{'RestartPolicy':{'Name':'unless-stopped'},'PortBindings':{'80/tcp':[{'HostPort':'8080'}],'443/tcp':[{'HostPort':'8443'}]},'Binds':[]},
        'Mounts':[{'Type':'volume','Name':'old-auth','Destination':'/data/auth','RW':True},{'Type':'bind','Source':'/synthetic/ssl','Destination':'/etc/nginx/ssl','RW':False},{'Type':'bind','Source':'/synthetic/nginx.conf','Destination':'/etc/nginx/nginx.conf','RW':False},{'Type':'volume','Name':'certs','Destination':'/etc/letsencrypt','RW':True}],
        'NetworkSettings':{'Networks':{'cryptolabs':{'Aliases':['proxy','fleet'],'IPAMConfig':{'IPv4Address':'172.30.0.10'},'DriverOpts':{'key':'value'}}}}}
        self.containers={'cryptolabs-proxy':self.current}; self.by_id={'old-id':self.current}; self.created=0
    def inspect(self,name): return deepcopy(self.by_id.get(name,self.containers.get(name)))
    def image(self,ref): return {'Id':'sha256:new' if ref==REF else 'sha256:old','Os':'linux','Architecture':'amd64','RepoDigests':[REF] if ref==REF else [],'Config':{'Entrypoint':['/app/entrypoint.sh'],'Cmd':None}}
    def read_config(self,name): return self.config
    def artifact_file_sha256(self,*args): return hashlib.sha256((Path(__file__).parents[1]/'src/cryptolabs_proxy/auth.py').read_bytes()).hexdigest()
    def pull(self,ref): self.calls.append(('pull',ref))
    def validate(self,image,candidate,inspect,identity): self.calls.append(('validate',candidate.read_bytes()))
    def anonymous_auth(self,name,tls,domain=None): return not self.fail_health
    def archive_auth(self,name): self.calls.append(('snapshot-auth',name)); return self.auth
    @contextmanager
    def updater_guard(self,*args):
        # This fixture models the Docker boundary; real process/flock proof is
        # in test_proxy_lifecycle_review_repairs.
        yield lambda: None
    def restore_auth(self,name,data,image,identity): self.calls.append(('restore-auth',name,data)); self.auth=data
    def put_auth(self,name,data): self.calls.append(('copy-auth',name)); self.new_auth=data
    def prove_recovery_auth(self,source,expected,identity):
        # Docker/startup boundary only. Distinct actual old/candidate startup
        # and the production proof command are exercised by recovery repairs.
        self.calls.append(('prove-recovery-auth',source['Image']))
    def stop(self,name,ignore_missing=False): self.calls.append(('stop',name)); self.containers.get(name,self.by_id.get(name))['State']['Running']=False
    def disconnect(self,name,network): self.calls.append(('disconnect',name,network))
    def rename(self,old,new):
        obj=self.containers.pop(old,None) or self.by_id[old]; self.containers.pop('cryptolabs-proxy',None) if old=='old-id' else None
        self.containers[new]=obj; self.calls.append(('rename',old,new))
    def create(self,name,request):
        self.request=deepcopy(request); self.calls.append(('create',name))
        self.created+=1
        obj={'Id':'new-id' if self.created==1 else 'created-'+str(self.created),'Image':'sha256:new' if request['Config']['Image']==REF else request['Config']['Image'],'Config':deepcopy(request['Config']),'HostConfig':deepcopy(request['HostConfig']), 'State':{'Running':False,'Health':{'Status':'healthy'}},'NetworkSettings':{'Networks':deepcopy(request['NetworkingConfig']['EndpointsConfig'])},'Mounts':[{'Type':m['Type'],'Name':m['Source'] if m['Type']=='volume' else None,'Source':m['Source'],'Destination':m['Target'],'RW':not m['ReadOnly']} for m in request['HostConfig']['Mounts']]}
        self.containers[name]=obj; self.by_id[obj['Id']]=obj
    def start(self,name):
        self.calls.append(('start',name)); self.containers[name]['State']['Running']=True
        if self.containers[name]['Image']=='sha256:new': self.config=Path(next(m['Source'] for m in self.containers[name]['HostConfig']['Mounts'] if m['Target']=='/etc/nginx/nginx.conf')).read_bytes()
    def connect(self,name,network,endpoint): self.calls.append(('connect',name,network,endpoint))
    def remove(self,name,ignore_missing=False): self.calls.append(('remove',name)); self.containers.pop(name,None)


def system(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import StandardAdoption
    settings=declaration(tmp_path); directory=tmp_path/'config'; directory.mkdir()
    generate_nginx_config(directory,settings['domain'],False,{n:DEFAULT_SERVICES[n] for n in KNOWN})
    config=(directory/'nginx.conf').read_bytes()
    reg=ServiceRegistry(directory); reg.config={'custom_config':{'mode':'vpm-managed','baseline_path':'private-old','baseline_sha256':'b'*64}}; reg.services={'vast-price-manager':DEFAULT_SERVICES['vast-price-manager']}; reg.save()
    engine=Engine(config); adoption=StandardAdoption(directory,engine=engine)
    monkeypatch.setattr('cryptolabs_proxy.standard_adoption.os', SimpleNamespace(geteuid=lambda: 0))
    return adoption,engine,settings,directory


def test_generated_standard_covers_existing_product_routes(tmp_path):
    generate_nginx_config(tmp_path,'fleet.example.test',False,{n:DEFAULT_SERVICES[n] for n in KNOWN})
    text=(tmp_path/'nginx.conf').read_text()
    for route in ['/api/build-info','/api/versions','/api/update-settings','/api/update','/api/pull','/assets/','= /servers','= /settings','~ ^/ipmi/api/(.*)$','~ ^/dc/(.*)$']:
        assert 'location '+route+' {' in text
    assert 'proxy_pass $upstream_dc/$1$is_args$args;' in text
    assert 'proxy_pass $upstream_vastai/metrics;' in text
    assert 'auth_request /_exporter_admin;' in text


def test_inspect_sanitized_and_plan_deterministic_readonly(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    before={p.name:p.read_bytes() for p in directory.iterdir()}
    info=adoption.inspect(); plan=adoption.plan(settings)
    assert plan==adoption.plan(settings)
    for _ in engine.current['Mounts']:
        mounts=engine.current['Mounts']
        engine.current['Mounts']=mounts[1:]+mounts[:1]
        expected=deepcopy(engine.current)
        assert plan==adoption.plan(settings)
        assert engine.current==expected
    assert 'synthetic-password' not in json.dumps([info,plan]) and 'synthetic-key' not in json.dumps([info,plan])
    assert info['routes'] and info['tls']['certificates']==['/etc/nginx/ssl/server.crt']
    assert plan['image']==REF and plan['selection_id']=='synthetic-selection'
    assert engine.calls==[] and before=={p.name:p.read_bytes() for p in directory.iterdir()}


@pytest.mark.parametrize('change',['route','directive','service','port','path','credential','collision','tls'])
def test_plan_rejects_unsupported_without_mutation(tmp_path,monkeypatch,change):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    if change=='route': engine.config=engine.config.replace(b'location /assets/',b'location /unknown/')
    if change=='directive': engine.config=engine.config.replace(b'keepalive_timeout 65;',b'keepalive_timeout 66;')
    if change=='service': del settings['services']['dc-overview']
    if change=='port': settings['services']['grafana']['port']=70000
    if change=='path': settings['services']['grafana']['path']='/grafana/; return 200'
    if change=='credential': settings['password']='synthetic-password'
    if change=='collision': settings['services']['custom']=dict(settings['services']['grafana'])
    if change=='tls': settings['tls']='letsencrypt'
    with pytest.raises(AdoptionError): adoption.plan(settings)
    assert engine.calls==[] and ServiceRegistry(directory).config['custom_config']


@pytest.mark.parametrize('change',['source','config','selection','digest','validation','mount-source','mount-rw','mount-option','mount-add','mount-remove','env-order'])
def test_adopt_preflight_denial_stops_nothing(tmp_path,monkeypatch,change):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    if change=='source': engine.current['Config']['Env'].append('NEW=drift')
    if change=='config': engine.config+=b'\n# drift'
    if change=='selection': (Path(settings['release_selection_dir'])/'selection.json').write_text('{}')
    if change=='digest': monkeypatch.setattr(engine,'image',lambda ref:{'Id':'sha256:new','Os':'linux','Architecture':'amd64','RepoDigests':[],'Config':{}})
    if change=='validation': monkeypatch.setattr(engine,'validate',lambda *a:(_ for _ in ()).throw(AdoptionError('candidate validation denied')))
    if change=='mount-source': engine.current['Mounts'][1]['Source']='/different/ssl'
    if change=='mount-rw': engine.current['Mounts'][1]['RW']=True
    if change=='mount-option': engine.current['Mounts'][1]['Propagation']='rshared'
    if change=='mount-add': engine.current['Mounts'].append({'Type':'bind','Source':'/extra','Destination':'/extra','RW':False})
    if change=='mount-remove': engine.current['Mounts'].pop()
    if change=='env-order': engine.current['Config']['Env'].reverse()
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert not [c for c in engine.calls if c[0]=='stop']
    assert ServiceRegistry(directory).config['custom_config']


def test_adopt_preserves_private_identity_tls_networks_and_repeat(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    inspect=engine.inspect
    from itertools import count
    inspections=count()
    def rotating_mounts(name):
        observed=inspect(name)
        if observed and observed.get('Mounts'):
            mounts=observed['Mounts']; offset=next(inspections)%len(mounts)
            observed['Mounts']=mounts[offset:]+mounts[:offset]
        return observed
    monkeypatch.setattr(engine,'inspect',rotating_mounts)
    plan=adoption.plan(settings)
    outcome=adoption.adopt(settings,plan['plan_id']); assert outcome['state']=='adopted'
    request=engine.request
    assert request['Config']['Env'][:3]==engine.current['Config']['Env']
    assert request['Config']['Labels']['com.centurylinklabs.watchtower.enable']=='false'
    assert request['NetworkingConfig']['EndpointsConfig']['cryptolabs']['IPAMConfig']=={'IPv4Address':'172.30.0.10'}
    mounts=request['HostConfig']['Mounts']
    assert any(m['Target']=='/etc/cryptolabs/releases' and m['ReadOnly'] for m in mounts)
    assert any(m['Target']=='/etc/letsencrypt' and m['Source']=='certs' for m in mounts)
    assert next(m['Source'] for m in mounts if m['Target']=='/data/auth')=='old-auth'
    assert engine.auth==auth_tar({'users.json':b'synthetic-auth-archive'})
    snapshots=[i for i,call in enumerate(engine.calls) if call==('snapshot-auth','old-id')]
    assert snapshots[0]<engine.calls.index(('stop','old-id'))<snapshots[1]
    assert 'custom_config' not in ServiceRegistry(directory).config
    assert set(ServiceRegistry(directory).services)==set(KNOWN)
    calls=len(engine.calls); assert adoption.adopt(settings,plan['plan_id'])['state']=='already_adopted'; assert len(engine.calls)==calls


def test_late_health_failure_restores_files_and_consistent_source_auth(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    before={p.name:p.read_bytes() for p in directory.iterdir()}; engine.fail_health=True
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert engine.containers['cryptolabs-proxy']['Image']=='sha256:old' and engine.containers['cryptolabs-proxy']['State']['Running']
    assert 'FLEET_ADMIN_PASS=' in engine.containers['cryptolabs-proxy']['Config']['Env']
    assert not engine.current['State']['Running']
    assert engine.auth==auth_tar({'users.json':b'synthetic-auth-archive'})
    assert all((directory/p).read_bytes()==b for p,b in before.items())
    assert ServiceRegistry(directory).config['custom_config']


def test_cli_public_group_is_additive(monkeypatch,tmp_path):
    import cryptolabs_proxy.cli as cli
    result=CliRunner().invoke(cli.main,['configuration','--help'])
    assert result.exit_code==0 and all(word in result.output for word in ['inspect','plan','adopt'])


def test_candidate_probe_uses_public_404_boundary(monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionEngine
    from unittest.mock import Mock
    calls=[]
    monkeypatch.setattr('subprocess.run',lambda cmd,**kw:(calls.append(cmd) or Mock(returncode=0)))
    assert AdoptionEngine().anonymous_auth('cryptolabs-proxy','self-signed')
    assert "status==404" in calls[0][-1]


def test_python_module_cli_includes_configuration_group():
    import subprocess,sys,os
    result=subprocess.run([sys.executable,'-m','cryptolabs_proxy.cli','--help'],capture_output=True,text=True,env={**os.environ,'PYTHONPATH':str(Path(__file__).parents[1]/'src')})
    assert result.returncode==0 and 'configuration' in result.stdout


def test_normal_setup_delegates_adopted_state_preserving_path(tmp_path,monkeypatch):
    import cryptolabs_proxy.setup as setup
    from cryptolabs_proxy.standard_adoption import StandardAdoption
    from unittest.mock import Mock
    registry=ServiceRegistry(tmp_path); registry.config={'standard_adoption':{'plan_id':'synthetic'},'release_selection_dir':'/synthetic'}; registry.save()
    monkeypatch.setattr(setup,'CONFIG_DIR',tmp_path)
    called=Mock(return_value=(True,'preserved'))
    monkeypatch.setattr(StandardAdoption,'reconfigure',called,raising=False)
    monkeypatch.setattr(setup,'ensure_ssl_certs',lambda *a:(_ for _ in ()).throw(AssertionError('must not mutate before state-preserving setup')))
    config=setup.ProxyConfig('fleet.example.test',fleet_admin_pass='synthetic-password',auth_secret='must-preserve-current-key')
    assert setup.setup_proxy(config)==(True,'preserved'); called.assert_called_once_with(config)


def test_candidate_validation_preserves_letsencrypt_and_certbot_mounts(tmp_path,monkeypatch):
    from cryptolabs_proxy.migration import CustomConfigMigrator
    from unittest.mock import Mock
    calls=[]
    monkeypatch.setattr('cryptolabs_proxy.migration.subprocess.run',lambda cmd,**kw:(calls.append(cmd) or Mock(returncode=0)))
    inspect={'Mounts':[{'Type':'bind','Source':'/ssl','Destination':'/etc/nginx/ssl','RW':False},{'Type':'volume','Name':'synthetic-le','Source':'/engine/le','Destination':'/etc/letsencrypt','RW':True},{'Type':'volume','Name':'synthetic-acme','Source':'/engine/acme','Destination':'/var/www/certbot','RW':True}]}
    CustomConfigMigrator(tmp_path,tmp_path)._validate_candidate(REF,tmp_path/'candidate',inspect,'synthetic')
    assert 'synthetic-le:/etc/letsencrypt:ro' in calls[0]
    assert 'synthetic-acme:/var/www/certbot:ro' in calls[0]


def test_custom_declarative_route_rewrites_prefix_and_preserves_query(tmp_path):
    generate_nginx_config(tmp_path,'fleet.example.test',False,{'custom':{'container_name':'custom-app','path':'/custom/','port':8089}})
    text=(tmp_path/'nginx.conf').read_text()
    assert 'location ~ ^/custom/(?<custom_custom>.*)$' in text
    assert 'proxy_pass $upstream_custom/$custom_custom$is_args$args;' in text


def test_candidate_creation_failure_restores_source(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    create=engine.create
    def denied(name,request):
        if request['Config']['Image']==REF: raise AdoptionError('candidate_create_failed')
        create(name,request)
    monkeypatch.setattr(engine,'create',denied)
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert ('start','cryptolabs-proxy') in engine.calls
    assert engine.containers['cryptolabs-proxy']['Image']=='sha256:old' and engine.containers['cryptolabs-proxy']['State']['Running']
    assert not engine.current['State']['Running']


def test_actual_module_help_lists_configuration_command():
    import subprocess,sys,os
    result=subprocess.run([sys.executable,'-m','cryptolabs_proxy.cli','--help'],capture_output=True,text=True,env={**os.environ,'PYTHONPATH':str(Path(__file__).parents[1]/'src')})
    assert '  configuration ' in result.stdout


def test_reconfigure_preserves_key_mounts_and_noop_repeat(tmp_path,monkeypatch):
    from cryptolabs_proxy.setup import ProxyConfig
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings); adoption.adopt(settings,plan['plan_id'])
    config=ProxyConfig(settings['domain'],use_letsencrypt=False,fleet_admin_pass='changed-synthetic',auth_secret='new-key-must-not-rotate')
    ok,reason=adoption.reconfigure(config); assert ok,reason
    assert 'AUTH_SECRET_KEY=synthetic-key' in engine.request['Config']['Env']
    assert 'FLEET_ADMIN_PASS=changed-synthetic' in engine.request['Config']['Env']
    assert any(m['Target']=='/etc/letsencrypt' and m['Source']=='certs' for m in engine.request['HostConfig']['Mounts'])
    calls=len(engine.calls); assert adoption.reconfigure(config)[0]; assert len(engine.calls)==calls
    assert 'custom_config' not in ServiceRegistry(directory).config


def test_known_released_bootstrap_profile_has_full_required_coverage(tmp_path,monkeypatch):
    from cryptolabs_proxy.custom_config import render_managed_vpm_config
    from cryptolabs_proxy.config import get_jinja_env
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    legacy=get_jinja_env().loader.get_source(get_jinja_env(),'legacy-bootstrap-nginx.conf')[0].encode()
    engine.config=render_managed_vpm_config(legacy,True)
    assert adoption.plan(settings)['source_profile']=='released-bootstrap-1.2.0'


def test_letsencrypt_profile_stays_explicit_and_cert_mount_is_preserved(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    settings['tls']='letsencrypt'
    generate_nginx_config(directory,settings['domain'],True,{n:DEFAULT_SERVICES[n] for n in KNOWN})
    engine.config=(directory/'nginx.conf').read_bytes()
    plan=adoption.plan(settings); assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    assert ('ssl_certificate /etc/letsencrypt/live/'+settings['domain']+'/fullchain.pem;').encode() in (directory/'nginx.conf').read_bytes()


def test_registry_save_failure_retains_proven_candidate_for_forward_repair(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    monkeypatch.setattr(ServiceRegistry,'save',lambda self:(_ for _ in ()).throw(OSError('synthetic denial')))
    result=adoption.adopt(settings,plan['plan_id'])
    assert result['state']=='candidate_retained' and result['reason']=='registry_forward_repair_required'
    assert engine.containers['cryptolabs-proxy']['Id']=='new-id'
    assert (directory/'standard-adoptions'/plan['plan_id']/'auth.tar').stat().st_mode & 0o777==0o600


def test_explicit_overlay_retirement_binds_source_artifact_and_review_evidence(tmp_path,monkeypatch):
    import cryptolabs_proxy.auth as auth
    from cryptolabs_proxy.standard_adoption import AUTH_OVERLAY
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    replacement=hashlib.sha256(Path(auth.__file__).read_bytes()).hexdigest(); old=b'synthetic reviewed predecessor'
    settings['obsolete_overlays']=[{'destination':AUTH_OVERLAY,'sha256':hashlib.sha256(old).hexdigest(),'replacement_sha256':replacement,'equivalence_evidence_sha256':'e'*64}]
    engine.current['Mounts'].append({'Type':'bind','Source':'/synthetic/override.py','Destination':AUTH_OVERLAY,'RW':False})
    monkeypatch.setattr(engine,'overlay_bytes',lambda target:old,raising=False)
    monkeypatch.setattr(engine,'artifact_file_sha256',lambda *a:replacement,raising=False)
    plan=adoption.plan(settings); assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'
    assert not any(m['Target']==AUTH_OVERLAY for m in engine.request['HostConfig']['Mounts'])
    assert (directory/'standard-adoptions'/plan['plan_id']/'retired-auth.py').read_bytes()==old


@pytest.mark.parametrize('proof',['source','replacement','evidence','artifact'])
def test_overlay_retirement_missing_or_mismatched_proof_blocks_before_stop(tmp_path,monkeypatch,proof):
    import cryptolabs_proxy.auth as auth
    from cryptolabs_proxy.standard_adoption import AUTH_OVERLAY, AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    replacement=hashlib.sha256(Path(auth.__file__).read_bytes()).hexdigest(); old=b'synthetic reviewed predecessor'
    settings['obsolete_overlays']=[{'destination':AUTH_OVERLAY,'sha256':hashlib.sha256(old).hexdigest(),'replacement_sha256':replacement,'equivalence_evidence_sha256':'e'*64}]
    engine.current['Mounts'].append({'Type':'bind','Source':'/synthetic/override.py','Destination':AUTH_OVERLAY,'RW':False})
    monkeypatch.setattr(engine,'overlay_bytes',lambda target:old,raising=False)
    monkeypatch.setattr(engine,'artifact_file_sha256',lambda *a:replacement if proof!='artifact' else 'b'*64,raising=False)
    if proof=='source': settings['obsolete_overlays'][0]['sha256']='0'*64
    if proof=='replacement': settings['obsolete_overlays'][0]['replacement_sha256']='0'*64
    if proof=='evidence': del settings['obsolete_overlays'][0]['equivalence_evidence_sha256']
    with pytest.raises(AdoptionError):
        plan=adoption.plan(settings); adoption.adopt(settings,plan['plan_id'])
    assert not [c for c in engine.calls if c[0]=='stop']


def test_auth_snapshot_failure_restarts_source_after_stop(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    monkeypatch.setattr(engine,'archive_auth',lambda *a:(_ for _ in ()).throw(OSError('synthetic failure')))
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert engine.containers['cryptolabs-proxy']['State']['Running']
    assert engine.containers['cryptolabs-proxy']['Id']=='old-id'


def test_undeclared_executable_runtime_command_blocks(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    engine.current['Config']['Entrypoint']=['/synthetic/custom-executable']
    with pytest.raises(AdoptionError): adoption.plan(settings)


def test_duplicate_declaration_keys_rejected(tmp_path):
    from cryptolabs_proxy.cli import _adoption_declaration
    from cryptolabs_proxy.standard_adoption import AdoptionError
    p=tmp_path/'declaration.json'; p.write_text('{"domain":"safe","domain":"unsafe"}')
    with pytest.raises(AdoptionError): _adoption_declaration(p)


def test_rollback_restores_shared_auth_before_old_image_start(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    start=engine.start
    def mutate(name):
        start(name)
        if engine.containers[name]['Id']=='new-id': engine.auth=auth_tar({'users.json':b'synthetic-new-schema'})
        else: assert engine.auth==auth_tar({'users.json':b'synthetic-auth-archive'})
    monkeypatch.setattr(engine,'start',mutate); engine.fail_health=True
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    restored=[c for c in engine.calls if c[0]=='restore-auth']
    assert restored and restored[0][2]==auth_tar({'users.json':b'synthetic-auth-archive'})
    restored_index=engine.calls.index(restored[0])
    proof_index=next(i for i,c in enumerate(engine.calls) if c[0]=='prove-recovery-auth')
    recovery_start=max(i for i,c in enumerate(engine.calls) if c[0]=='start')
    assert restored_index<proof_index<recovery_start
    assert engine.auth==auth_tar({'users.json':b'synthetic-auth-archive'})


def auth_tar(files):
    import io,tarfile
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w') as archive:
        for name,value in files.items():
            if name=='users.json':
                # Real account-schema bytes; fixture markers model owned
                # schema changes without introducing an invalid authority.
                value=json.dumps({'operator':{'password_hash':'synthetic-password-hash',
                    'role':'admin','enabled':True,'require_password_change':True,
                    'fixture_marker':value.decode()}}).encode()
            info=tarfile.TarInfo('auth/'+name); info.size=len(value); info.mode=0o600
            archive.addfile(info,io.BytesIO(value))
    return output.getvalue()


def test_auth_recovery_restores_owned_files_and_guards_external_changes():
    from cryptolabs_proxy.standard_adoption import auth_state, owned_auth_archive, AdoptionError
    import tarfile,io
    before=auth_tar({'users.json':b'synthetic-old','settings.json':b'old','internal-api-token':b'synthetic-shared','external.json':b'external','update-jobs/done.json':b'{"state":"success"}'})
    changed=auth_tar({'users.json':b'synthetic-new','settings.json':b'new','internal-api-token':b'synthetic-shared','external.json':b'external','update-jobs/done.json':b'{"state":"success"}'})
    assert auth_state(before)['external']==auth_state(changed)['external']
    with tarfile.open(fileobj=io.BytesIO(owned_auth_archive(before))) as archive:
        assert set(m.name for m in archive)=={'auth/users.json','auth/settings.json'}
    active=auth_tar({'users.json':b'old','update-jobs/running.json':b'{"state":"running"}'})
    with pytest.raises(AdoptionError): auth_state(active)


def test_external_shared_store_change_holds_old_image_restore(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); engine.auth=auth_tar({'users.json':b'old','external.json':b'old'})
    plan=adoption.plan(settings); start=engine.start
    def mutate(name):
        start(name)
        if engine.containers[name]['Id']=='new-id': engine.auth=auth_tar({'users.json':b'new','external.json':b'concurrent-write'})
    monkeypatch.setattr(engine,'start',mutate); engine.fail_health=True
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert not [c for c in engine.calls if c[0]=='restore-auth']
    assert json.loads((directory/'standard-adoptions'/plan['plan_id']/'outcome.json').read_text())['state']=='forward_repair_required'


def test_inspect_reports_active_upstreams_and_safe_unmapped_directive_context(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    info=adoption.inspect()
    assert any('dc-overview:5001' in value for value in info['upstreams'])
    engine.config=engine.config.replace(b'keepalive_timeout 65;',b'keepalive_timeout 66;')
    with pytest.raises(AdoptionError,match='keepalive_timeout'): adoption.plan(settings)


def test_restore_verification_failure_never_starts_old_image(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings); engine.fail_health=True
    monkeypatch.setattr(engine,'restore_auth',lambda *a:(_ for _ in ()).throw(AdoptionError('auth_restore_identity_mismatch')))
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert not engine.containers['cryptolabs-proxy']['State']['Running']
    assert json.loads((directory/'standard-adoptions'/plan['plan_id']/'outcome.json').read_text())['state']=='forward_repair_required'


def test_source_health_failure_recovers_candidate_with_its_auth_schema(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings); start=engine.start
    probes=[]
    def ready(*args): probes.append(True); return len(probes)>1
    def mutate(name):
        start(name)
        if engine.containers[name]['Id']=='new-id': engine.auth=auth_tar({'users.json':b'candidate-schema'})
        else: engine.containers[name]['State']['Health']['Status']='unhealthy'
    monkeypatch.setattr(engine,'anonymous_auth',ready); monkeypatch.setattr(engine,'start',mutate)
    assert adoption.adopt(settings,plan['plan_id'])['state']=='candidate_retained'
    assert engine.containers['cryptolabs-proxy']['Id']=='new-id' and engine.auth==auth_tar({'users.json':b'candidate-schema'})
    assert [c[2] for c in engine.calls if c[0]=='restore-auth']==[auth_tar({'users.json':b'synthetic-auth-archive'}),auth_tar({'users.json':b'candidate-schema'})]


def test_interactive_setup_reuses_adopted_path_before_prompts(tmp_path,monkeypatch):
    import cryptolabs_proxy.cli as cli
    from cryptolabs_proxy.standard_adoption import StandardAdoption
    from unittest.mock import Mock
    registry=ServiceRegistry(tmp_path); registry.config={'standard_adoption':{'plan_id':'synthetic'}}; registry.save()
    monkeypatch.setattr(cli,'CONFIG_DIR',tmp_path); monkeypatch.setattr(cli,'check_root',lambda:None)
    monkeypatch.setattr(cli,'check_docker_installed',lambda:(_ for _ in ()).throw(AssertionError('must use adopted workflow')))
    repeat=Mock(return_value=(True,'preserved')); monkeypatch.setattr(StandardAdoption,'repeat_setup',repeat,raising=False)
    result=CliRunner().invoke(cli.main,['setup'])
    assert result.exit_code==0,result.output
    repeat.assert_called_once_with()


def test_interactive_setup_cannot_overwrite_custom_mode(tmp_path,monkeypatch):
    import cryptolabs_proxy.cli as cli
    registry=ServiceRegistry(tmp_path); registry.config={'custom_config':{'mode':'vpm-managed'}}; registry.save()
    monkeypatch.setattr(cli,'CONFIG_DIR',tmp_path); monkeypatch.setattr(cli,'check_root',lambda:None)
    monkeypatch.setattr(cli,'check_docker_installed',lambda:(_ for _ in ()).throw(AssertionError('must block before wizard')))
    result=CliRunner().invoke(cli.main,['setup'])
    assert result.exit_code!=0 and 'configuration plan' in result.output
    assert ServiceRegistry(tmp_path).config['custom_config']


def test_selected_image_must_have_normal_auth_module_even_without_overlay(tmp_path,monkeypatch):
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch); plan=adoption.plan(settings)
    monkeypatch.setattr(engine,'artifact_file_sha256',lambda *args:'0'*64,raising=False)
    with pytest.raises(AdoptionError): adoption.adopt(settings,plan['plan_id'])
    assert not [c for c in engine.calls if c[0]=='stop']


def test_proposed_selection_plan_is_pure_and_revalidates_exact_bytes(tmp_path, monkeypatch):
    from cryptolabs_proxy import release_selection
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    releases = Path(settings['release_selection_dir'])
    before = {str(p):p.read_bytes() for p in releases.rglob('*') if p.is_file()}
    old = release_selection.load(releases)
    manifest = json.loads(old['manifest_bytes'])
    manifest['components']['cryptolabs-proxy']['artifacts']['linux/amd64']['reference'] = REF.replace('a'*64, 'b'*64)
    manifest_raw = json.dumps(manifest).encode()
    selected = json.loads(old['selection_bytes'])
    selected['manifest_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
    proposed = release_selection.validate(json.dumps(selected).encode(), manifest_raw)
    preview = adoption.plan(settings, proposed_selection=proposed)
    assert preview['image'].endswith('b'*64)
    assert preview['selection_sha256'] == proposed['selection_sha256']
    assert {str(p):p.read_bytes() for p in releases.rglob('*') if p.is_file()} == before
    assert engine.calls == []
    proposed['selection_sha256'] = '0'*64
    with pytest.raises(ValueError): adoption.plan(settings, proposed_selection=proposed)


def test_recover_adoption_reports_retained_success_only_with_live_identity(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    plan = adoption.plan(settings)
    result = adoption.adopt(settings, plan['plan_id'])
    assert result['state'] == 'adopted'
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os, 'getuid', __import__('os').getuid, raising=False)
    assert adoption.recover_adoption(plan['plan_id'])['state'] == 'completed'
    engine.current['Config']['Env'].append('UNRELATED=drift')
    # Installed serving object, not a stale source pointer.
    engine.containers['cryptolabs-proxy']['Config']['Env'].append('DRIFT=true')
    assert adoption.recover_adoption(plan['plan_id'])['state'] == 'recovery-required'


def test_previous_standard_profile_is_exact_and_adoptable(tmp_path,monkeypatch):
    import subprocess
    from cryptolabs_proxy.config import get_jinja_env
    from cryptolabs_proxy.standard_adoption import AdoptionError
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    raw=(Path(__file__).parents[1]/'src/cryptolabs_proxy/templates/previous-standard-nginx-444d7c0.conf.j2').read_bytes()
    assert hashlib.sha256(raw).hexdigest()=='f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de'
    template=raw.decode()
    old=get_jinja_env().from_string(template).render(domain=settings['domain'],letsencrypt=False,services=settings['services'],host_forward_groups=[],acme_challenge=None,hostname_policy=None,http_policy=None).encode()
    engine.config=old
    plan=adoption.plan(settings)
    assert plan['source_profile']=='standard-444d7c0'
    engine.config=old.replace(b'keepalive_timeout 65;',b'keepalive_timeout 66;')
    with pytest.raises(AdoptionError):adoption.plan(settings)
    engine.config=old
    assert adoption.adopt(settings,plan['plan_id'])['state']=='adopted'


@pytest.mark.parametrize('enabled',[True,False,'true'])
def test_real_compose_renderer_preserves_validated_broker_flag(tmp_path,enabled):
    from cryptolabs_proxy.config import generate_docker_compose
    registry=ServiceRegistry(tmp_path);registry.config={'domain':'fleet.example.test','release_broker_enabled':enabled};registry.save()
    if type(enabled) is not bool:
        with pytest.raises(ValueError):generate_docker_compose(tmp_path)
        assert not (tmp_path/'docker-compose.yml').exists()
    else:
        generate_docker_compose(tmp_path)
        assert ('/run/dc-overview-release-broker.sock:' in (tmp_path/'docker-compose.yml').read_text()) is enabled


def test_fixed_recovery_restores_stopped_source_before_auth_archive_gap(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);stop=engine.stop
    def die(name,ignore_missing=False):
        stop(name,ignore_missing)
        raise KeyboardInterrupt('owner died immediately after stop')
    engine.stop=die
    with pytest.raises(KeyboardInterrupt):adoption.adopt(settings,plan['plan_id'])
    assert not engine.inspect('cryptolabs-proxy')['State']['Running']
    engine.stop=stop
    recovered=adoption.recover_adoption(plan['plan_id'])
    assert recovered['state']=='failed-restored'
    serving=engine.inspect('cryptolabs-proxy')
    assert serving['State']['Running'] and serving['Image']=='sha256:old'
    assert 'FLEET_ADMIN_PASS=' in serving['Config']['Env']
    assert engine.auth==auth_tar({'users.json':b'synthetic-auth-archive'})
    assert adoption.recover_adoption(plan['plan_id'])['state']=='failed-restored'


def test_recovery_recognizes_actual_sanitized_rollback_identity(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);engine.fail_health=True
    with pytest.raises(owner.AdoptionError):adoption.adopt(settings,plan['plan_id'])
    assert engine.inspect('cryptolabs-proxy')['Id']!=plan['container_id']
    assert adoption.recover_adoption(plan['plan_id'])['state']=='failed-restored'
    engine.auth=auth_tar({'users.json':b'changed-authority'})
    assert adoption.recover_adoption(plan['plan_id'])['state']=='recovery-required'


def test_fixed_recovery_never_replays_candidate_start_or_overwrites_new_auth(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);start=engine.start
    def die(name):
        start(name)
        if engine.inspect(name)['Image']=='sha256:new':
            engine.auth=auth_tar({'users.json':b'new-authority'})
            raise KeyboardInterrupt('owner died after candidate start')
    engine.start=die
    with pytest.raises(KeyboardInterrupt):adoption.adopt(settings,plan['plan_id'])
    archive=engine.auth;calls=list(engine.calls)
    assert adoption.recover_adoption(plan['plan_id'])['state']=='recovery-required'
    assert engine.auth==archive and engine.calls==calls


@pytest.mark.parametrize("startup_preserves_auth",[True,False])
def test_fixed_recovery_preserves_latest_quiescent_auth_after_stop(tmp_path,monkeypatch,startup_preserves_auth):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);stop=engine.stop
    def die(name,ignore_missing=False):
        stop(name,ignore_missing)
        raise KeyboardInterrupt('after stop')
    engine.stop=die
    with pytest.raises(KeyboardInterrupt):adoption.adopt(settings,plan['plan_id'])
    engine.stop=stop;engine.auth=auth_tar({'users.json':b'concurrent-authority'})
    latest=engine.auth
    if not startup_preserves_auth:
        def reject(*args):
            raise owner.AdoptionError('source_auth_startup_unverified')
        engine.prove_recovery_auth=reject
    assert adoption.recover_adoption(plan['plan_id'])['state']==('failed-restored' if startup_preserves_auth else 'recovery-required')
    assert engine.inspect('cryptolabs-proxy')['State']['Running'] is startup_preserves_auth
    assert engine.auth==latest
    assert not [call for call in engine.calls if call[0]=='restore-auth']
    if startup_preserves_auth:
        assert adoption.recover_adoption(plan['plan_id'])['state']=='failed-restored'
        phase=json.loads((adoption.backup_root/plan['plan_id']/'phase.json').read_text())
        assert phase['prestop_auth_match'] is False and phase['restoration_auth']!=phase['prestop_auth']


def test_verified_restoration_receipt_survives_missing_final_outcome(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);engine.fail_health=True
    with pytest.raises(owner.AdoptionError):adoption.adopt(settings,plan['plan_id'])
    (adoption.backup_root/plan['plan_id']/'outcome.json').unlink()
    assert adoption.recover_adoption(plan['plan_id'])['state']=='failed-restored'


@pytest.mark.parametrize('owned',[True,False])
def test_finished_owner_reclaims_only_exact_orphan_guard(tmp_path,monkeypatch,owned):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);adoption.adopt(settings,plan['plan_id'])
    path=adoption.backup_root/plan['plan_id']/'phase.json';journal=json.loads(path.read_text())
    journal['guard_id']='guard-id';path.write_text(json.dumps(journal))
    name='cryptolabs-adoption-lock-'+plan['plan_id']
    auth=next(m for m in engine.current['Mounts'] if m['Destination']=='/data/auth')
    helper={'Id':'guard-id','Image':journal['candidate_image_id'],'Config':{
        'Entrypoint':['python3'],'Cmd':['-c','fixed-lock-script','/data/auth/update-jobs','/tmp/updater-held'],
        'Labels':{'io.cryptolabs.adoption.guard':plan['plan_id'] if owned else 'another-plan'}},'Mounts':[deepcopy(auth)]}
    engine.containers[name]=helper;engine.by_id['guard-id']=helper
    removed=[];remove=engine.remove
    def remove_id(identifier,ignore_missing=False):
        removed.append(identifier)
        found=next((n for n,v in engine.containers.items() if v.get('Id')==identifier),identifier)
        remove(found,ignore_missing)
    engine.remove=remove_id
    assert adoption.recover_adoption(plan['plan_id'])['state']==('completed' if owned else 'recovery-required')
    assert removed==(['guard-id'] if owned else [])


def test_fixed_recovery_preserves_external_registry_change_after_owner_death(tmp_path,monkeypatch):
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    import cryptolabs_proxy.standard_adoption as owner
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);stop=engine.stop
    def die(name,ignore_missing=False):
        stop(name,ignore_missing);raise KeyboardInterrupt('after stop')
    engine.stop=die
    with pytest.raises(KeyboardInterrupt):adoption.adopt(settings,plan['plan_id'])
    engine.stop=stop
    path=directory/'services.yaml';changed=path.read_bytes()+b'\n# external owner change\n';path.write_bytes(changed)
    assert adoption.recover_adoption(plan['plan_id'])['state']=='recovery-required'
    assert path.read_bytes()==changed and not engine.inspect('cryptolabs-proxy')['State']['Running']
    assert not [call for call in engine.calls if call[0]=='prove-recovery-auth']


def test_inprocess_latest_auth_restoration_reconciles_repeat_without_archive_restore(tmp_path,monkeypatch):
    import cryptolabs_proxy.standard_adoption as owner
    adoption,engine,settings,directory=system(tmp_path,monkeypatch)
    monkeypatch.setattr(owner.os,'getuid',__import__('os').getuid,raising=False)
    plan=adoption.plan(settings);stop=engine.stop
    latest=auth_tar({'users.json':b'latest-authority','sessions.json':b'latest-session'})
    def changed_stop(name,ignore_missing=False):
        stop(name,ignore_missing)
        if name==plan['container_id']:engine.auth=latest
    engine.stop=changed_stop
    with pytest.raises(owner.AdoptionError):adoption.adopt(settings,plan['plan_id'])
    assert engine.inspect('cryptolabs-proxy')['State']['Running']
    assert engine.auth==latest
    for _ in range(2):
        assert adoption.recover_adoption(plan['plan_id'])['state']=='failed-restored'
        assert engine.auth==latest
    assert not [call for call in engine.calls if call[0]=='restore-auth']
    journal=json.loads((adoption.backup_root/plan['plan_id']/'phase.json').read_text())
    assert journal['restoration_auth']!=journal['prestop_auth']
