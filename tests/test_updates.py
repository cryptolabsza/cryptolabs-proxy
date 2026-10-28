# TRACEWEAVER: file-role=verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Updater failures must not destroy existing runtime state or conceal outcomes."""
import importlib.util
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from cryptolabs_proxy import updates


def source():
    return {
        'Id': 'a' * 64, 'Name': '/prometheus', 'Image': 'sha256:old',
        'Config': {
            'Image': 'prom/prometheus:latest', 'Env': ['GIT_COMMIT=old', 'SECRET=keep', 'PATH=/old'],
            'Labels': {'org.opencontainers.image.revision': 'old', 'custom': 'keep'},
            'Cmd': ['--web.route-prefix=/prometheus/', '--storage.tsdb.retention.time=90d'],
            'Entrypoint': ['/custom-entrypoint'], 'User': '123',
            'Healthcheck': {'Test': ['CMD', 'probe'], 'Interval': 10},
        },
        'HostConfig': {'Binds': [], 'RestartPolicy': {'Name': 'on-failure', 'MaximumRetryCount': 3},
                       'PortBindings': {'999/udp': [{'HostIp': '127.0.0.1', 'HostPort': '999'}]},
                       'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m'}}},
        'Mounts': [{'Type': 'volume', 'Name': 'metrics', 'Destination': '/prometheus', 'RW': False},
                   {'Type': 'bind', 'Source': '/site/nginx.conf', 'Destination': '/etc/nginx/nginx.conf', 'RW': False}],
        'NetworkSettings': {'Networks': {'cryptolabs': {
            'Aliases': ['prometheus', 'a' * 12], 'IPAMConfig': {'IPv4Address': '172.30.0.10'},
            'IPAddress': '172.30.0.10', 'EndpointID': 'runtime',
        }}},
        'State': {'Running': True, 'Health': {'Status': 'healthy'}},
    }


def test_clone_preserves_runtime_but_refreshes_image_defaults():
    original = source()
    old = {'Config': {'Env': ['GIT_COMMIT=old', 'PATH=/old'], 'Cmd': ['default'],
                      'Entrypoint': ['/image-entrypoint'], 'Labels': {'org.opencontainers.image.revision': 'old'}}}
    new = {'Id': 'sha256:new', 'Config': {'Env': ['GIT_COMMIT=new', 'PATH=/new'],
           'Labels': {'org.opencontainers.image.revision': 'new'}, 'Cmd': ['new-default']}}
    request = updates.build_update_request(original, old, new)
    assert original == source()
    assert request['Config']['Image'] == 'sha256:new'
    assert request['Config']['Env'] == ['GIT_COMMIT=new', 'PATH=/new', 'SECRET=keep']
    assert request['Config']['Labels'] == {'org.opencontainers.image.revision': 'new', 'custom': 'keep'}
    for key in ('Cmd', 'Entrypoint', 'User', 'Healthcheck'):
        assert request['Config'][key] == original['Config'][key]
    assert request['HostConfig']['RestartPolicy'] == original['HostConfig']['RestartPolicy']
    assert request['HostConfig']['PortBindings'] == original['HostConfig']['PortBindings']
    assert request['HostConfig']['Mounts'][0]['Source'] == 'metrics'
    assert request['HostConfig']['Mounts'][0]['ReadOnly'] is True
    endpoint = request['NetworkingConfig']['EndpointsConfig']['cryptolabs']
    assert endpoint['IPAMConfig']['IPv4Address'] == '172.30.0.10'
    assert endpoint['Aliases'] == ['prometheus']
    assert 'EndpointID' not in endpoint


def test_image_defaults_change_without_losing_custom_overrides():
    original = source()
    original['Config']['Cmd'] = ['old-default']
    old = {'Config': {'Cmd': ['old-default']}}
    new = {'Id': 'sha256:new', 'Config': {'Cmd': ['new-default']}}
    assert updates.build_update_request(original, old, new)['Config']['Cmd'] == ['new-default']


@pytest.mark.parametrize('reference', ['sha256:123', 'repo@sha256:123', 'prom/prometheus:v3.2', 'custom/prometheus:latest'])
def test_pinned_and_custom_images_are_never_silently_retargeted(reference):
    current = source()
    current['Config']['Image'] = reference
    assert updates.target_for('prometheus', current, 'dev') is None


def test_channel_only_changes_first_party_images():
    assert updates.target_for('prometheus', source(), 'dev') == 'prom/prometheus:latest'
    current = source()
    current['Config']['Image'] = 'ghcr.io/cryptolabsza/dc-overview:latest'
    assert updates.target_for('dc-overview', current, 'dev').endswith(':dev')
    assert updates.target_for('vast-price-manager', current, 'main') is None


class Engine:
    def __init__(self, failure=None):
        self.current = source()
        self.containers = {'prometheus': self.current}
        self.calls = []
        self.failure = failure

    def inspect(self, name):
        if self.failure == 'inspect':
            raise RuntimeError('private detail')
        if name not in self.containers:
            raise updates.MigrationError('Docker Engine GET returned HTTP 404')
        return deepcopy(self.containers[name])

    def image(self, image):
        return {'Id': 'sha256:old' if image == 'sha256:old' else 'sha256:new', 'Config': {}}

    def stop(self, name, **kwargs):
        self.calls.append(('stop', name))
        self.containers[name]['State']['Running'] = False

    def disconnect(self, name, network):
        self.calls.append(('disconnect', name, network))

    def connect(self, name, network, endpoint):
        self.calls.append(('connect', name, network))

    def rename(self, name, new):
        self.calls.append(('rename', name, new))
        self.containers[new] = self.containers.pop(name)

    def create(self, name, request):
        self.calls.append(('create', name))
        if self.failure == 'create':
            raise RuntimeError('private detail')
        self.containers[name] = deepcopy(source())
        self.containers[name]['Config'] = request['Config']
        self.containers[name]['Image'] = request['Config']['Image']

    def start(self, name):
        self.calls.append(('start', name))
        current = self.containers[name]
        current['State']['Running'] = True
        if self.failure == 'health' and current['Image'] == 'sha256:new':
            current['State']['Health']['Status'] = 'unhealthy'

    def remove(self, name, **kwargs):
        self.calls.append(('remove', name))
        self.containers.pop(name, None)


@pytest.mark.parametrize('failure', ['create', 'health'])
def test_failed_update_restores_original_and_reports_failure(failure):
    engine = Engine(failure)
    result = updates.replace_container(engine, 'prometheus', 'sha256:new', 'job', timeout=0)
    assert result['success'] is False
    assert result['state'] == 'rolled_back'
    assert engine.inspect('prometheus')['Image'] == 'sha256:old'
    assert engine.inspect('prometheus')['State']['Running'] is True
    assert 'private detail' not in json.dumps(result)


def test_inspection_failure_never_stops_original():
    engine = Engine('inspect')
    result = updates.replace_container(engine, 'prometheus', 'sha256:new', 'job', timeout=0)
    assert result['success'] is False
    assert not engine.calls


def test_success_retains_old_container_and_verifies_new_identity():
    engine = Engine()
    result = updates.replace_container(engine, 'prometheus', 'sha256:new', 'job', timeout=0)
    assert result['state'] == 'completed'
    assert result['image_id'] == 'sha256:new'
    assert engine.inspect('prometheus.rollback-job')['Image'] == 'sha256:old'
    assert not engine.inspect('prometheus.rollback-job')['State']['Running']


def test_same_tag_image_identity_detects_update_and_unknown_is_not_current():
    engine = Engine()
    status = updates.update_status('prometheus', 'main', engine=engine)
    assert status['update_available'] is True
    engine.image = lambda image: {'Id': 'sha256:old'}
    assert updates.update_status('prometheus', 'main', engine=engine)['update_available'] is False
    engine.image = lambda image: (_ for _ in ()).throw(RuntimeError())
    assert updates.update_status('prometheus', 'main', engine=engine)['update_available'] is None


def test_worker_does_not_touch_stopped_pinned_or_vpm(monkeypatch, tmp_path):
    engine = Engine()
    engine.current['State']['Running'] = False
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus'],
                                            'vast-price-manager': updates.SERVICES['vast-price-manager']})
    job = {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'update'}
    updates.write_job(tmp_path, job)
    result = updates.run_job(tmp_path, job['id'], engine=engine)
    assert not engine.calls
    assert result['results']['prometheus']['state'] == 'skipped'
    assert 'vast-price-manager' not in result['results']


def test_helper_runs_independently_with_persistent_state_and_no_copied_secrets():
    current = source()
    current['Mounts'].append({'Type': 'volume', 'Name': 'fleet-data', 'Destination': '/data', 'RW': True})
    request = updates.helper_request(current, Path('/data/auth/update-jobs'), 'a' * 32)
    assert request['Config']['Image'] == 'sha256:old'
    assert request['Config']['Entrypoint'] == ['python3']
    assert request['Config']['Cmd'][:2] == ['-m', 'cryptolabs_proxy.updates']
    assert request['HostConfig']['NetworkMode'] == 'host'
    assert request['Config']['Env'] == ['PYTHONPATH=/app/src']
    assert any(m.get('Source') == 'fleet-data' for m in request['HostConfig']['Mounts'])
    assert request['Config']['Healthcheck'] == {'Test': ['NONE']}


def test_update_api_queues_job_instead_of_mutating_docker(monkeypatch, app, logged_in_admin):
    app.config['RELEASE_PUBLIC_ORIGIN']='http://localhost'
    token=logged_in_admin.get('/api/releases/session').json['csrf_token']
    monkeypatch.setattr(updates,'installed_selection',lambda:None)
    monkeypatch.setattr(updates,'submit_job',lambda *args,**kwargs:{'id':'job','state':'queued'})
    response=logged_in_admin.post('/api/update',json={'service':'prometheus','branch':'main'},
        headers={'Origin':'http://localhost','X-CSRF-Token':token})
    assert response.status_code==202
    assert response.json=={'success':True,'job':{'id':'job','state':'queued'}}


def test_cli_submit_and_status_return_machine_readable_jobs(monkeypatch, capsys):
    monkeypatch.setattr(updates, 'submit_job', lambda *args, **kwargs: {'id': 'a' * 32, 'state': 'queued'})
    assert updates.main(['submit', '--branch', 'dev']) == 0
    assert json.loads(capsys.readouterr().out)['state'] == 'queued'
    monkeypatch.setattr(updates, 'job_status', lambda *args, **kwargs: {'id': 'a' * 32, 'state': 'failed', 'success': False})
    assert updates.main(['status', 'a' * 32]) == 0
    assert json.loads(capsys.readouterr().out)['success'] is False


def test_bulk_missing_service_is_skipped_and_partial_failure_is_reported(monkeypatch, tmp_path):
    engine = Engine()
    monkeypatch.setattr(updates, 'pull_target', lambda target: False)
    monkeypatch.setattr(updates, 'SERVICES', {name: updates.SERVICES[name] for name in ['prometheus', 'runpod-exporter']})
    job = {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'update'}
    updates.write_job(tmp_path, job)
    result = updates.run_job(tmp_path, job['id'], engine=engine)
    assert result['success'] is False
    assert result['results']['prometheus']['success'] is False
    assert result['results']['runpod-exporter']['state'] == 'skipped'
    assert not engine.calls


def test_new_managed_image_is_not_misclassified_as_pinned():
    engine = Engine()
    result = updates.replace_container(engine, 'prometheus', 'prom/prometheus:latest', 'job', timeout=0)
    assert result['success'] is True
    assert updates.target_for('prometheus', engine.inspect('prometheus'), 'main') == 'prom/prometheus:latest'


def test_no_healthcheck_requires_real_application_probe(monkeypatch):
    engine = Engine()
    engine.current['State'].pop('Health')
    monkeypatch.setattr(updates, '_probe', lambda *args: False)
    assert updates.wait_ready(engine, 'prometheus', 'sha256:old', timeout=0) is False


def test_duplicate_submission_does_not_launch_second_helper(monkeypatch, tmp_path):
    engine = Engine()
    job = {'id': 'a' * 32, 'state': 'running', 'helper': 'prometheus'}
    updates.write_job(tmp_path, job)
    (tmp_path / 'active.json').write_text(json.dumps({'id': job['id']}))
    with pytest.raises(updates.UpdateBusy):
        updates.submit_job('all', 'main', 'update', directory=tmp_path, engine=engine)
    assert not engine.calls


def test_missing_helper_is_recorded_as_interrupted_not_left_active(tmp_path):
    job = {'id': 'a' * 32, 'state': 'running', 'helper': 'missing-helper'}
    updates.write_job(tmp_path, job)
    result = updates.job_status(job['id'], directory=tmp_path, engine=Engine())
    assert result['state'] == 'interrupted'
    assert result['success'] is False
    assert 'stopped before completion' in result['message']
    assert updates.read_job(tmp_path, job['id'])['state'] == 'interrupted'


def test_submit_recovers_a_missing_previous_helper(tmp_path):
    engine = Engine()
    engine.current['Mounts'].append({
        'Type': 'volume', 'Name': 'fleet-data', 'Destination': str(tmp_path.parent), 'RW': True,
    })
    engine.containers['cryptolabs-proxy'] = engine.current
    previous = {'id': 'a' * 32, 'state': 'running', 'helper': 'missing-helper'}
    updates.write_job(tmp_path, previous)
    (tmp_path / 'active.json').write_text(json.dumps({'id': previous['id']}))

    submitted = updates.submit_job('all', 'main', 'pull', directory=tmp_path, engine=engine)

    assert submitted['id'] != previous['id']
    assert updates.read_job(tmp_path, previous['id'])['state'] == 'interrupted'
    assert ('create', submitted['helper']) in engine.calls


def test_submit_keeps_job_busy_when_docker_cannot_confirm_helper_state(tmp_path):
    previous = {'id': 'a' * 32, 'state': 'running', 'helper': 'missing-helper'}
    updates.write_job(tmp_path, previous)
    (tmp_path / 'active.json').write_text(json.dumps({'id': previous['id']}))

    with pytest.raises(updates.UpdateBusy):
        updates.submit_job('all', 'main', 'pull', directory=tmp_path, engine=Engine('inspect'))


def test_update_engine_uses_docker_29_compatible_api(monkeypatch):
    calls = []

    def request(self, method, path, payload=None, allowed=(200, 201, 204)):
        calls.append((method, path, payload, allowed))
        return b'{}'

    monkeypatch.setattr(updates.DockerEngine, '_request', request)
    updates.UpdateEngine()._request('GET', '/containers/example/json')
    assert calls[0][1] == '/v1.45/containers/example/json'


def landing_script():
    html = (Path(__file__).parents[1] / 'landing-page/index.html').read_text()
    return html.rsplit('<script>', 1)[1].split('// Initial load', 1)[0]


def test_landing_defers_sites_and_services_navigation():
    html = (Path(__file__).parents[1] / 'landing-page/index.html').read_text()
    assert '/dc/integrations' not in html


def test_landing_uses_image_identity_and_keeps_pinned_services_disabled():
    script = landing_script() + '''
    loadWatchdogStatus = () => {};
    const grid = {innerHTML: ''};
    const button = {style: {}};
    globalThis.document = {
        getElementById: id => id === 'versionsGrid' ? grid : id === 'targetBranch' ? {value: 'main'} : null,
        querySelector: () => button,
    };
    globalThis.fetch = async () => ({ok: true, json: async () => ({
        'dc-overview': {running: true, tag: 'latest', update_available: true},
        'vastai-exporter': {running: true, tag: 'latest', pinned: true},
    })});
    loadVersions().then(() => console.log(JSON.stringify({html: grid.innerHTML, disabled: button.disabled})));
    '''
    run = subprocess.run(['node'], input=script, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert "updateService('dc-overview')" in result['html']
    assert "updateService('vastai-exporter')" not in result['html']
    assert result['disabled'] is False


def test_landing_renders_partial_failure_as_error():
    script = landing_script() + '''
    let observed;
    showUpdateStatus = (kind, message) => {observed = {kind, message};};
    loadVersions = () => {};
    loadServices = () => {};
    globalThis.localStorage = {removeItem: () => {}};
    globalThis.fetch = async () => ({ok: true, json: async () => ({
        id: 'job', state: 'failed', success: false,
        results: {'prometheus': {success: false, state: 'rolled_back', message: 'Original restored'}}
    })});
    pollUpdateJob('job').then(() => console.log(JSON.stringify(observed)));
    '''
    run = subprocess.run(['node'], input=script, capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    result = json.loads(run.stdout)
    assert result['kind'] == 'error'
    assert 'Original restored' in result['message']


def test_release_operation_replays_terminal_job_and_rejects_changed_fingerprint(tmp_path):
    from tests.test_release_selection import selection_files, SelectedEngine
    directory, digest = selection_files(tmp_path)
    engine = SelectedEngine(tmp_path)
    engine.updater_capabilities = lambda source_id: updates.get_capabilities()
    operation = '12345678-1234-4234-8234-123456789abc'
    options = dict(directory=tmp_path/'jobs', engine=engine, selection_id='synthetic-selection',
                   selection_sha256=digest, selection_directory=directory,
                   components=['prometheus'], operation_id=operation, request_fingerprint='a'*64)
    job = updates.submit_job('prometheus', 'main', 'update', **options)
    assert job['components'] == ['prometheus'] and set(job['targets']) == {'prometheus'}
    job.update(state='completed', success=True)
    updates.write_job(tmp_path/'jobs', job)
    engine.calls.clear()
    assert updates.submit_job('prometheus', 'main', 'update', **options) == job
    assert engine.calls == []
    options['request_fingerprint'] = 'b'*64
    with pytest.raises(updates.UpdateError, match='operation_conflict'):
        updates.submit_job('prometheus', 'main', 'update', **options)


def test_release_operation_lost_create_reply_keeps_same_helper_and_recovery_hold(tmp_path):
    from tests.test_release_selection import selection_files, SelectedEngine
    directory, digest = selection_files(tmp_path)
    engine = SelectedEngine(tmp_path)
    engine.updater_capabilities = lambda source_id: updates.get_capabilities()
    def uncertain_create(name, request):
        engine.calls.append(('create', name))
        raise OSError('reply lost after helper creation')
    engine.create = uncertain_create
    operation = '12345678-1234-4234-8234-123456789abc'
    options = dict(directory=tmp_path/'jobs', engine=engine, selection_id='synthetic-selection',
                   selection_sha256=digest, selection_directory=directory,
                   components=['prometheus'], operation_id=operation, request_fingerprint='a'*64)
    first = updates.submit_job('prometheus', 'main', 'update', **options)
    second = updates.submit_job('prometheus', 'main', 'update', **options)
    assert first['id'] == second['id']
    assert second['state'] == 'recovery-required'
    assert len([call for call in engine.calls if call[0] == 'create']) == 1


def test_landing_reload_ignores_stale_operation_response():
    script = landing_script() + '''
    let observed = [];
    showUpdateStatus = (kind,message) => observed.push({kind,message});
    loadVersions = () => {}; loadServices = () => {};
    globalThis.localStorage = {setItem:()=>{},removeItem:()=>{}};
    globalThis.fetch = async () => ({ok:true,json:async()=>({id:'old',state:'completed',success:true})});
    activeUpdateJob = 'new';
    pollUpdateJob('old',0,'old').then(()=>console.log(JSON.stringify({active:activeUpdateJob,observed})));
    '''
    run = subprocess.run(['node'],input=script,capture_output=True,text=True)
    assert run.returncode == 0,run.stderr
    result=json.loads(run.stdout)
    assert result == {'active':'new','observed':[]}


def test_lost_helper_start_reply_does_not_overwrite_worker_terminal_result(tmp_path):
    from tests.test_release_selection import selection_files, SelectedEngine
    directory, digest = selection_files(tmp_path)
    engine = SelectedEngine(tmp_path)
    engine.updater_capabilities = lambda source_id: updates.get_capabilities()
    def completed_before_lost_reply(name):
        active=json.loads((tmp_path/'jobs/active.json').read_text())
        job=updates.read_job(tmp_path/'jobs',active['id'])
        job.update(state='completed',success=True)
        updates.write_job(tmp_path/'jobs',job)
        raise OSError('start response lost after worker completed')
    engine.start=completed_before_lost_reply
    result=updates.submit_job('prometheus','main','update',directory=tmp_path/'jobs',engine=engine,
        selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory,
        components=['prometheus'],operation_id='12345678-1234-4234-8234-123456789abc',request_fingerprint='a'*64)
    assert result['state']=='completed' and result['success'] is True


def test_explicit_component_group_preserves_unscoped_missing_service(tmp_path,monkeypatch):
    from tests.test_release_selection import selection_files, SelectedEngine, REF
    directory,_=selection_files(tmp_path)
    manifest=json.loads(next((directory/'manifests').iterdir()).read_text())
    for name,repository in [('grafana','grafana/grafana'),('ipmi-monitor','ghcr.io/cryptolabsza/ipmi-monitor')]:
        manifest['components'][name]={'owner':'proxy-updater','release':'synthetic-1','artifacts':{'linux/amd64':{'kind':'oci','reference':repository+'@sha256:'+'a'*64}}}
    raw=json.dumps(manifest).encode();digest=__import__('hashlib').sha256(raw).hexdigest()
    (directory/'manifests'/(digest+'.json')).write_bytes(raw)
    selection=json.loads((directory/'selection.json').read_text());selection['manifest_sha256']=digest
    for name in ['grafana','ipmi-monitor']:selection['components'][name]={'enabled':True,'origin':'baseline'}
    raw=json.dumps(selection).encode();(directory/'selection.json').write_bytes(raw)
    engine=SelectedEngine(tmp_path);engine.selection=raw
    engine.containers['grafana']=deepcopy(engine.current)
    engine.containers['grafana']['Id']='c'*64
    engine.updater_capabilities=lambda source_id:updates.get_capabilities()
    old_image=engine.image
    def image(reference):
        result=old_image(reference)
        if '@sha256:' in reference:result['RepoDigests']=[reference]
        return result
    engine.image=image
    job=updates.submit_job('prometheus','main','pull',directory=tmp_path/'jobs',engine=engine,
        selection_id='synthetic-selection',selection_sha256=__import__('hashlib').sha256(raw).hexdigest(),selection_directory=directory,
        components=['prometheus','grafana'],operation_id='12345678-1234-4234-8234-123456789abc',request_fingerprint='a'*64)
    assert set(job['targets'])=={'prometheus','grafana'}
    assert 'ipmi-monitor' not in job['sources']
    monkeypatch.setattr(updates,'pull_target',lambda reference:True)
    result=updates.run_job(tmp_path/'jobs',job['id'],engine=engine)
    assert result['success'] is True and set(result['results'])=={'prometheus','grafana'}
    assert not [call for call in engine.calls if call[0]=='stop']


@pytest.mark.parametrize('kind,name,source_path',[
    ('volume','fleet-auth-data','/var/lib/docker/volumes/fleet-auth-data/_data'),
    ('bind',None,'/srv/fleet/auth'),
])
def test_host_job_store_maps_to_same_backing_worker_namespace(kind,name,source_path):
    source={'Image':'sha256:source','Mounts':[
        {'Type':'volume','Name':'anonymous-data','Source':'/var/lib/docker/volumes/anonymous-data/_data','Destination':'/data','RW':True},
        {'Type':kind,'Name':name,'Source':source_path,'Destination':'/data/auth','RW':True}]}
    request=updates.helper_request(source,Path(source_path)/'update-jobs','a'*32)
    assert request['Config']['Cmd'][-1]=='/data/auth/update-jobs'
    assert request['HostConfig']['Mounts'][0]['Source']==(name if kind=='volume' else source_path)
    assert request['HostConfig']['Mounts'][0]['Target']=='/data/auth'
    if kind=='volume':
        source['Mounts'].append({'Type':'bind','Source':'/shadow/operations','Destination':'/data/auth/update-jobs/operations','RW':True})
        with pytest.raises(updates.UpdateError):updates.helper_request(source,Path(source_path)/'update-jobs','a'*32)
        source['Mounts'].pop()
    source['Mounts'].append({'Type':'bind','Source':source_path,'Destination':'/other','RW':True})
    with pytest.raises(updates.UpdateError):updates.helper_request(source,Path(source_path)/'update-jobs','a'*32)


def test_status_cannot_interrupt_dispatch_before_helper_start(tmp_path,monkeypatch):
    from tests.test_release_selection import selection_files,SelectedEngine
    directory,digest=selection_files(tmp_path);engine=SelectedEngine(tmp_path)
    engine.updater_capabilities=lambda _:updates.get_capabilities()
    observations=[];operation='12345678-1234-4234-8234-123456789abc'
    original_create=engine.create
    def create(name,request):
        observations.append(updates.operation_status(operation,directory=tmp_path/'jobs',engine=engine)['state'])
        original_create(name,request)
    engine.create=create
    result=updates.submit_job('prometheus','main','pull',directory=tmp_path/'jobs',engine=engine,
        selection_id='synthetic-selection',selection_sha256=digest,selection_directory=directory,
        components=['prometheus'],operation_id=operation,request_fingerprint='a'*64)
    assert observations==['queued'] and result['state']=='queued'
    monkeypatch.setattr(updates,'pull_target',lambda _:True)
    engine.selection=(directory/'selection.json').read_bytes()
    assert updates.run_job(tmp_path/'jobs',result['id'],engine=engine)['state']=='completed'
