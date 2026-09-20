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


def test_update_api_queues_job_instead_of_mutating_docker(monkeypatch):
    path = Path(__file__).parents[1] / 'scripts' / 'health-api.py'
    spec = importlib.util.spec_from_file_location('health_api_updates', path)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
    import io
    body = json.dumps({'service': 'prometheus', 'branch': 'main'}).encode()
    handler = object.__new__(api.HealthHandler)
    handler.path = '/api/update'
    handler.headers = {'Content-Length': str(len(body))}
    handler.rfile = io.BytesIO(body)
    replies = []
    handler.send_json = lambda result, status=200: replies.append((result, status))
    monkeypatch.setattr(api, 'submit_update_job', lambda *args, **kwargs: {'id': 'job', 'state': 'queued'})
    handler.do_POST()
    assert replies == [({'success': True, 'job': {'id': 'job', 'state': 'queued'}}, 202)]


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
