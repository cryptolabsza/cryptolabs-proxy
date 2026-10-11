"""Synthetic contract1 selection/update authority regressions."""
import hashlib
import importlib.util
import io
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptolabs_proxy import updates
from tests.test_updates import Engine, source

DIGEST = 'a' * 64
REF = 'prom/prometheus@sha256:' + DIGEST


def selection_files(tmp_path, *, origin='baseline', pin=None):
    directory = tmp_path / 'releases'
    (directory / 'manifests').mkdir(parents=True)
    manifest = {'schema_version': 1, 'selection_contract': 1, 'baseline_id': 'synthetic-1',
                'components': {'prometheus': {'release': 'synthetic-1', 'owner': 'proxy-updater',
                  'artifacts': {'linux/amd64': {'kind': 'oci', 'reference': REF}}}}}
    raw = json.dumps(manifest).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (directory / 'manifests' / (digest + '.json')).write_bytes(raw)
    entry = {'origin': origin, 'enabled': True}
    if pin:
        entry['pin'] = pin
    selection = {'schema_version': 1, 'selection_id': 'synthetic-selection',
                 'manifest_sha256': digest, 'components': {'prometheus': entry}}
    data = json.dumps(selection).encode()
    (directory / 'selection.json').write_bytes(data)
    return directory, hashlib.sha256(data).hexdigest()


class SelectedEngine(Engine):
    def __init__(self, directory):
        super().__init__()
        self.directory = directory
        self.containers['cryptolabs-proxy'] = deepcopy(self.current)
        self.current['Config']['Image'] = 'prom/prometheus@sha256:' + 'b' * 64
        self.current['Config']['Labels']['com.centurylinklabs.watchtower.enable'] = 'true'
        self.containers['cryptolabs-proxy']['Mounts'].append({'Type': 'volume', 'Name': 'auth', 'Destination': str(directory), 'RW': True})
        self.selection = None
    def image(self, ref):
        return {'Id': 'sha256:new' if ref == REF else 'sha256:old', 'Os': 'linux', 'Architecture': 'amd64',
                'RepoDigests': [REF] if ref == REF else ['prom/prometheus@sha256:' + 'b' * 64], 'Config': {}}
    def selection_bytes(self):
        return self.selection
    def updater_capabilities(self, source_id):
        assert source_id == self.containers['cryptolabs-proxy']['Id']
        return {'selection_contract': 1, 'proxy_replacement_policy': 'host-adoption-required-v1'}
    def manifest_bytes(self, digest):
        return (self.directory / 'releases/manifests' / (digest + '.json')).read_bytes()


def test_capabilities_contract1_is_machine_readable(capsys):
    assert updates.main(['capabilities']) == 0
    assert json.loads(capsys.readouterr().out)['selection_contract'] == 1


@pytest.mark.parametrize('failure', ['hash', 'owner', 'command', 'repository', 'platform', 'pin', 'unmanaged'])
def test_invalid_selection_blocks_before_helper_mutation(tmp_path, failure):
    directory, digest = selection_files(tmp_path, origin='customer-pin' if failure == 'pin' else 'unmanaged' if failure == 'unmanaged' else 'baseline',
                                         pin='prom/prometheus@sha256:' + 'c' * 64 if failure == 'pin' else None)
    manifest_path = next((directory / 'manifests').iterdir())
    if failure in ['owner', 'command', 'repository', 'platform']:
        manifest=json.loads(manifest_path.read_text())
        component=manifest['components']['prometheus']
        if failure == 'owner': component['owner']='host-cli'
        if failure == 'command': component['command']='execute-untrusted'
        if failure == 'repository': component['artifacts']['linux/amd64']['reference']='evil.example/prometheus@sha256:' + DIGEST
        if failure == 'platform': component['artifacts']={'linux/arm64': component['artifacts']['linux/amd64']}
        data=json.dumps(manifest).encode(); sha=hashlib.sha256(data).hexdigest()
        (directory/'manifests'/(sha+'.json')).write_bytes(data)
        select=json.loads((directory/'selection.json').read_text()); select['manifest_sha256']=sha
        data=json.dumps(select).encode(); (directory/'selection.json').write_bytes(data); digest=hashlib.sha256(data).hexdigest()
    if failure == 'hash': digest='0'*64
    engine=SelectedEngine(tmp_path)
    with pytest.raises(updates.UpdateError):
        updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,
            selection_id='synthetic-selection', selection_sha256=digest, selection_directory=directory)
    assert engine.calls == []


def test_baseline_snapshot_survives_helper_restart_and_upgrades_immutable_origin(tmp_path, monkeypatch):
    directory,digest=selection_files(tmp_path)
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,
                          selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory)
    assert job['selection_sha256']==digest and job['scope']=='proxy-updater'
    assert job['selection_snapshot']['selection_bytes'] == engine.selection.decode()
    monkeypatch.setattr(updates,'pull_target',lambda target: target==REF)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['success'] is True
    assert result['suite_complete'] is False
    assert result['results']['prometheus']['desired']==REF
    assert result['results']['prometheus']['origin']=='baseline'
    assert engine.inspect('prometheus')['Config']['Labels']['com.centurylinklabs.watchtower.enable']=='false'
    assert updates.run_job(tmp_path/'jobs',job['id'],engine=engine)==result


@pytest.mark.parametrize('failure', ['changed-selection','digest','platform','missing'])
def test_staged_preflight_failure_has_no_container_stop(tmp_path,monkeypatch,failure):
    directory,digest=selection_files(tmp_path)
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,
                          selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory)
    engine.calls.clear()
    if failure=='changed-selection': engine.selection += b' '
    if failure in ['digest','platform']:
        original=engine.image
        def image(ref):
            value=original(ref)
            if ref==REF:
                value['RepoDigests']=[] if failure=='digest' else [REF]
                value['Architecture']='arm64' if failure=='platform' else 'amd64'
            return value
        engine.image=image
    if failure=='missing': engine.containers.pop('prometheus')
    monkeypatch.setattr(updates,'pull_target',lambda target: True)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['success'] is False and result['state']=='blocked'
    assert not any(c[0] in ['stop','rename','create'] for c in engine.calls)


def test_configured_missing_selection_cannot_fall_back_to_channel(tmp_path,monkeypatch):
    monkeypatch.setenv('RELEASE_SELECTION_REQUIRED','true')
    engine=SelectedEngine(tmp_path)
    with pytest.raises(updates.UpdateError):
        updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,selection_directory=tmp_path/'absent')
    assert engine.calls==[]


def test_api_passes_selection_pair_and_keeps_202_envelope(monkeypatch):
    path=Path(__file__).parents[1]/'scripts/health-api.py'
    spec=importlib.util.spec_from_file_location('health_selection',path); api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    data={'service':'all','selection_id':'synthetic-selection','selection_sha256':'a'*64}
    body=json.dumps(data).encode(); handler=object.__new__(api.HealthHandler)
    handler.path='/api/update'; handler.headers={'Content-Length':str(len(body))}; handler.rfile=io.BytesIO(body)
    response=[]; handler.send_json=lambda value,status=200: response.append((value,status))
    submit=Mock(return_value={'id':'job'}); monkeypatch.setattr(api,'submit_update_job',submit)
    handler.do_POST()
    assert submit.call_args.kwargs=={'selection_id':data['selection_id'],'selection_sha256':data['selection_sha256']}
    assert response==[({'success':True,'job':{'id':'job'}},202)]


def test_setup_config_adds_supported_selection_directory():
    from cryptolabs_proxy.setup import ProxyConfig
    config=ProxyConfig('fleet.example.test',release_selection_dir=Path('/synthetic/releases'))
    assert config.release_selection_dir==Path('/synthetic/releases')


def proxy_selection(tmp_path):
    directory,digest=selection_files(tmp_path)
    select=json.loads((directory/'selection.json').read_text())
    manifest=json.loads(next((directory/'manifests').iterdir()).read_text())
    manifest['components']['cryptolabs-proxy']={'release':'synthetic-1','owner':'proxy-updater','artifacts':{'linux/amd64':{'kind':'oci','reference':'ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:'+'d'*64}}}
    select['components']['cryptolabs-proxy']={'origin':'baseline','enabled':True}
    raw=json.dumps(manifest).encode(); sha=hashlib.sha256(raw).hexdigest(); (directory/'manifests'/(sha+'.json')).write_bytes(raw)
    select['manifest_sha256']=sha; (directory/'selection.json').write_text(json.dumps(select))
    return directory,manifest['components']['cryptolabs-proxy']['artifacts']['linux/amd64']['reference']


def test_repeat_setup_and_credentials_hold_unadopted_baseline_without_replacement(monkeypatch,tmp_path):
    from cryptolabs_proxy import setup
    from cryptolabs_proxy.services import ServiceRegistry
    directory,ref=proxy_selection(tmp_path)
    config_dir=tmp_path/'config'; config_dir.mkdir()
    registry=ServiceRegistry(config_dir); registry.config={'domain':'fleet.example.test','letsencrypt':False,'release_selection_dir':str(directory)}; registry.save()
    monkeypatch.setattr(setup,'CONFIG_DIR',config_dir)
    monkeypatch.setattr(setup,'ensure_ssl_certs',lambda config:(True,'synthetic cert'))
    monkeypatch.setattr(setup,'ensure_docker_network',lambda:True)
    monkeypatch.setattr(setup,'_free_ports_80_443',lambda:None)
    monkeypatch.setattr(setup,'_save_internal_token',lambda token:None)
    monkeypatch.setattr(setup,'wait_for_container_healthy',lambda *a,**kw:True)
    monkeypatch.setattr(setup,'is_proxy_running',lambda:True)
    monkeypatch.setattr(setup,'get_proxy_config',lambda:{'FLEET_ADMIN_USER':'admin','FLEET_ADMIN_PASS':'synthetic','RELEASE_SELECTION_REQUIRED':'true'})
    commands=[]
    def run(command,**kwargs):
        commands.append(command)
        stdout=''
        if command[:2]==['docker','version']: stdout='linux/amd64'
        elif command[:3]==['docker','image','inspect']: stdout=json.dumps([{'Os':'linux','Architecture':'amd64','RepoDigests':[ref]}])
        elif command[:3]==['docker','inspect','cryptolabs-proxy']: stdout=json.dumps([{'Config':{'Labels':{'com.centurylinklabs.watchtower.enable':'true'}},'Mounts':[]}])
        return type('Result',(),{'returncode':0,'stdout':stdout,'stderr':''})()
    monkeypatch.setattr(setup.subprocess,'run',run)
    for invoke in [lambda:setup.setup_proxy(setup.ProxyConfig('fleet.example.test',fleet_admin_pass='synthetic')),
                   lambda:setup.update_proxy_credentials('admin','synthetic-new-password')]:
        commands.clear()
        ok,message=invoke()
        assert not ok and 'configuration plan --declaration' in message
        assert 'configuration adopt --declaration' in message
        started=[cmd for cmd in commands if cmd[:3]==['docker','run','-d']]
        assert not started
        assert not any(cmd[:3]==['docker','rm','-f'] for cmd in commands)
        assert not (config_dir/'nginx.conf').exists()


def test_selection_helper_checks_changed_manifest_before_mutation(tmp_path,monkeypatch):
    directory,digest=selection_files(tmp_path)
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,
                          selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory)
    engine.manifest_bytes=lambda digest:b'changed manifest'
    engine.calls.clear(); monkeypatch.setattr(updates,'pull_target',lambda target:True)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['state']=='blocked' and result['success'] is False
    assert engine.calls==[]


@pytest.mark.parametrize('origin', ['baseline', 'customer-pin'])
def test_compose_baseline_uses_exact_image_mount_and_permanent_label(tmp_path, origin):
    from cryptolabs_proxy.config import generate_docker_compose
    directory,reference=proxy_selection(tmp_path)
    selected = json.loads((directory / 'selection.json').read_text())
    selected['components']['cryptolabs-proxy']['origin'] = origin
    if origin == 'customer-pin':
        selected['components']['cryptolabs-proxy']['pin'] = reference
    (directory / 'selection.json').write_text(json.dumps(selected))
    generate_docker_compose(tmp_path,release_selection_dir=directory,platform='linux/amd64')
    import yaml
    proxy=yaml.safe_load((tmp_path/'docker-compose.yml').read_text())['services']['cryptolabs-proxy']
    assert proxy['image']==reference
    assert proxy['labels']['com.centurylinklabs.watchtower.enable']=='false'
    assert proxy['labels']['io.cryptolabs.update.origin'] == origin
    assert str(directory)+':/etc/cryptolabs/releases:ro' in proxy['volumes']
    assert 'RELEASE_SELECTION_REQUIRED=true' in proxy['environment']
    assert 'fleet-auth-data:/data/auth' in proxy['volumes']


def test_baseline_status_reports_identity_and_unknown_candidate(tmp_path):
    directory,digest=selection_files(tmp_path)
    engine=SelectedEngine(tmp_path)
    result=updates.update_status('prometheus','main',engine=engine,selection_directory=directory)
    assert result['desired']==REF and result['origin']=='baseline' and result['observed']=='sha256:old'
    assert result['update_available'] is True
    original=engine.image
    engine.image=lambda ref: original(ref) if ref!=''+REF else (_ for _ in ()).throw(RuntimeError())
    result=updates.update_status('prometheus','main',engine=engine,selection_directory=directory)
    assert result['update_available'] is None and result['reason']=='identity_unavailable'


def test_missing_required_service_and_explicit_dev_reject_before_queue(tmp_path):
    directory,digest=selection_files(tmp_path)
    for failure in ['missing','dev']:
        engine=SelectedEngine(tmp_path)
        if failure=='missing': engine.containers.pop('prometheus')
        with pytest.raises(updates.UpdateError):
            updates.submit_job('all','dev' if failure=='dev' else 'main','update',directory=tmp_path/'jobs',engine=engine,
                selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory)
        assert engine.calls==[]
        assert not (tmp_path/'jobs').exists()


def test_customer_pin_exact_match_and_external_owner_outcomes(tmp_path,monkeypatch):
    directory,digest=selection_files(tmp_path,origin='customer-pin',pin=REF)
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('all','main','pull',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    monkeypatch.setattr(updates,'pull_target',lambda ref:ref==REF)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['success'] is True and result['results']['prometheus']['origin']=='customer-pin'
    assert not any(c[0]=='stop' for c in engine.calls)


def test_parser_duplicate_fields_and_unknown_schema_rejected(tmp_path):
    from cryptolabs_proxy.release_selection import SelectionError, validate
    directory,digest=selection_files(tmp_path)
    raw=(directory/'selection.json').read_bytes(); manifest=next((directory/'manifests').iterdir()).read_bytes()
    with pytest.raises(SelectionError): validate(raw.replace(b'"schema_version": 1',b'"schema_version": 1, "schema_version": 1'),manifest)
    with pytest.raises(SelectionError): validate(raw.replace(b'"schema_version": 1',b'"schema_version": true'),manifest)


def test_baseline_setup_refuses_custom_nginx_before_any_mutation(monkeypatch,tmp_path):
    from cryptolabs_proxy import setup
    from cryptolabs_proxy.services import ServiceRegistry
    directory,reference=proxy_selection(tmp_path)
    config_dir=tmp_path/'config'; config_dir.mkdir()
    registry=ServiceRegistry(config_dir); registry.config={'release_selection_dir':str(directory),'custom_config':{'mode':'vpm-managed'}}; registry.save()
    (config_dir/'nginx.conf').write_text('preserved customer routes')
    monkeypatch.setattr(setup,'CONFIG_DIR',config_dir)
    mutated=Mock(); monkeypatch.setattr(setup,'ensure_ssl_certs',mutated)
    result=setup.setup_proxy(setup.ProxyConfig('fleet.example.test',release_selection_dir=directory))
    assert result[0] is False and 'custom' in result[1].lower()
    mutated.assert_not_called()
    assert (config_dir/'nginx.conf').read_text()=='preserved customer routes'


def test_baseline_status_mismatched_candidate_identity_is_unknown(tmp_path):
    directory,digest=selection_files(tmp_path); engine=SelectedEngine(tmp_path)
    original=engine.image
    def image(reference):
        value=original(reference)
        if reference==REF: value['RepoDigests']=[]
        return value
    engine.image=image
    result=updates.update_status('prometheus','main',engine=engine,selection_directory=directory)
    assert result['update_available'] is None and result['reason']=='artifact_identity_mismatch'


def test_api_cannot_upload_policy_paths_or_images(monkeypatch):
    spec=importlib.util.spec_from_file_location('health_reject_upload',Path(__file__).parents[1]/'scripts/health-api.py')
    api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
    handler=object.__new__(api.HealthHandler); body=json.dumps({'manifest_path':'/unapproved/policy','image':'evil.example/image'}).encode()
    handler.path='/api/update'; handler.headers={'Content-Length':str(len(body))}; handler.rfile=io.BytesIO(body)
    response=[]; handler.send_json=lambda value,status=200:response.append((value,status))
    submit=Mock(); monkeypatch.setattr(api,'submit_update_job',submit)
    handler.do_POST(); submit.assert_not_called()
    assert response[0][1]==400


def test_external_owner_is_reported_and_never_executed_by_proxy(tmp_path,monkeypatch):
    directory,digest=selection_files(tmp_path)
    manifest=json.loads(next((directory/'manifests').iterdir()).read_text())
    manifest['components']['vast-price-manager']={'release':'synthetic-1','owner':'dc-vpm','artifacts':{'linux/amd64':{'kind':'oci','reference':'ghcr.io/cryptolabsza/vast-price-manager@sha256:'+'d'*64}}}
    data=json.dumps(manifest).encode(); sha=hashlib.sha256(data).hexdigest(); (directory/'manifests'/(sha+'.json')).write_bytes(data)
    selected=json.loads((directory/'selection.json').read_text()); selected['manifest_sha256']=sha
    selected['components']['vast-price-manager']={'origin':'baseline','enabled':True}
    (directory/'selection.json').write_text(json.dumps(selected))
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job=updates.submit_job('all','main','update',directory=tmp_path/'jobs',engine=engine,selection_directory=directory)
    pulls=[]; monkeypatch.setattr(updates,'pull_target',lambda ref:pulls.append(ref) or True)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert pulls==[REF]
    assert result['success'] is True and result['suite_complete'] is False
    assert result['external_owners']==['dc-vpm']
    assert result['results']['vast-price-manager']['reason']=='external_owner_required'
    assert result['results']['vast-price-manager']['success'] is False


def test_queued_legacy_job_cannot_bypass_new_baseline_policy(tmp_path,monkeypatch):
    directory,digest=selection_files(tmp_path)
    engine=SelectedEngine(tmp_path); engine.selection=(directory/'selection.json').read_bytes()
    job={'id':'a'*32,'service':'all','branch':'main','action':'update'}
    updates.write_job(tmp_path/'jobs',job)
    pulled=Mock(return_value=True); monkeypatch.setattr(updates,'pull_target',pulled)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['state']=='blocked' and result['success'] is False
    pulled.assert_not_called()
    assert not engine.calls
