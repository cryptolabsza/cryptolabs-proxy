"""Latest is a verified channel comparison, independent of update permission."""
import importlib.util
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from cryptolabs_proxy import updates
from tests.test_updates import Engine, landing_script, source


def health_api():
    spec = importlib.util.spec_from_file_location('health_api_latest', Path(__file__).parents[1] / 'scripts/health-api.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('reference,expected', [
    ('ghcr.io/cryptolabsza/dc-overview@sha256:' + 'a' * 64, 'Pinned'),
    ('registry.example:5000/team/image', 'latest'),
    ('ghcr.io/cryptolabsza/dc-overview:1.6.4', '1.6.4'),
])
def test_version_reference_parsing_and_label_inspection(monkeypatch, reference, expected):
    api = health_api()
    def run(args, **kwargs):
        assert args[-1] == 'dc-overview', 'Every container inspection needs a target'
        fmt = args[3]
        output = reference if fmt == '{{.Config.Image}}' else '1.6.4||abc123||2026-10-20' if '.Config.Labels' in fmt else ''
        return SimpleNamespace(returncode=0, stdout=output)
    monkeypatch.setattr(api.subprocess, 'run', run)
    result = api.get_container_version('dc-overview')
    assert result['tag'] == expected
    assert result['version'] == '1.6.4'


@pytest.mark.parametrize('name,reference,target', [
    ('prometheus', 'prom/prometheus@sha256:abc', 'prom/prometheus:latest'),
    ('prometheus', 'prom/prometheus:v3.2', 'prom/prometheus:latest'),
    ('dc-overview', 'ghcr.io/cryptolabsza/dc-overview@sha256:abc', 'ghcr.io/cryptolabsza/dc-overview:dev'),
    ('vast-price-manager', 'ghcr.io/cryptolabsza/vast-price-manager@sha256:abc', 'ghcr.io/cryptolabsza/vast-price-manager:dev'),
])
def test_checks_include_pinned_and_separately_managed_services(monkeypatch, tmp_path, name, reference, target):
    engine = Engine()
    current = source()
    current['Config']['Image'] = reference
    engine.containers = {updates.SERVICES[name]['container']: current}
    monkeypatch.setattr(updates, 'SERVICES', {name: updates.SERVICES[name]})
    pulled = []
    monkeypatch.setattr(updates, 'pull_target', lambda value: pulled.append(value) or True)
    job = {'id': 'a' * 32, 'service': 'all', 'branch': 'dev', 'action': 'pull'}
    updates.write_job(tmp_path, job)
    result = updates.run_job(tmp_path, job['id'], engine=engine)
    assert result['results'][name]['state'] == 'checked'
    assert pulled == [target]
    assert not engine.calls
    assert updates.target_for(name, current, 'dev') is None
    status = updates.update_status(name, 'dev', engine=engine, directory=tmp_path)
    assert status['latest_status'] == 'update_available'
    engine.containers[updates.SERVICES[name]['container']]['Image'] = 'sha256:new'
    assert updates.update_status(name, 'dev', engine=engine, directory=tmp_path)['latest_status'] == 'latest'
    assert updates.update_status(name, 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'


def test_local_image_match_is_not_proof_of_latest_and_failed_check_clears_success(monkeypatch, tmp_path):
    engine = Engine()
    engine.image = lambda image: {'Id': 'sha256:old'}
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus']})
    assert updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    for job_id, expected in [('a' * 32, 'latest'), ('b' * 32, 'unknown')]:
        updates.write_job(tmp_path, {'id': job_id, 'service': 'all', 'branch': 'main', 'action': 'pull'})
        updates.run_job(tmp_path, job_id, engine=engine)
        status = updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)
        assert status['latest_status'] == expected
        monkeypatch.setattr(updates, 'pull_target', lambda target: False)


def test_expired_or_unreadable_checks_are_unknown(monkeypatch, tmp_path):
    engine = Engine()
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus']})
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    updates.write_job(tmp_path, {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    updates.run_job(tmp_path, 'a' * 32, engine=engine)
    now = updates.time.time()
    monkeypatch.setattr(updates.time, 'time', lambda: now + 86400)
    assert updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'


def test_custom_images_cannot_be_marked_latest(monkeypatch, tmp_path):
    engine = Engine()
    engine.current['Config']['Image'] = 'custom/prometheus:latest'
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus']})
    monkeypatch.setattr(updates, 'pull_target', lambda target: pytest.fail('Custom images must not be pulled'))
    updates.write_job(tmp_path, {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    updates.run_job(tmp_path, 'a' * 32, engine=engine)
    assert updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'


def test_successful_update_refreshes_the_checked_image(monkeypatch, tmp_path):
    engine = Engine()
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus']})
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    engine.image = lambda image: {'Id': 'sha256:old', 'Config': {}}
    updates.write_job(tmp_path, {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    updates.run_job(tmp_path, 'a' * 32, engine=engine)
    engine.image = lambda image: {'Id': 'sha256:old' if image == 'sha256:old' else 'sha256:new',
                                  'Config': {}, 'RepoTags': ['prom/prometheus:latest']}
    updates.write_job(tmp_path, {'id': 'b' * 32, 'service': 'all', 'branch': 'main', 'action': 'update'})
    result = updates.run_job(tmp_path, 'b' * 32, engine=engine)
    assert result['success']
    assert updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'latest'


def test_interrupted_check_invalidates_services_not_yet_reached(monkeypatch, tmp_path):
    engine = Engine()
    engine.containers['grafana'] = source()
    engine.containers['grafana']['Config']['Image'] = 'grafana/grafana:latest'
    engine.image = lambda image: {'Id': 'sha256:old'}
    monkeypatch.setattr(updates, 'SERVICES', {name: updates.SERVICES[name] for name in ('prometheus', 'grafana')})
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    updates.write_job(tmp_path, {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    updates.run_job(tmp_path, 'a' * 32, engine=engine)
    assert updates.update_status('grafana', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'latest'
    monkeypatch.setattr(updates, 'pull_target', lambda target: (_ for _ in ()).throw(KeyboardInterrupt()))
    updates.write_job(tmp_path, {'id': 'b' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    with pytest.raises(KeyboardInterrupt):
        updates.run_job(tmp_path, 'b' * 32, engine=engine)
    assert updates.update_status('grafana', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'


def test_failed_helper_launch_invalidates_previous_check(monkeypatch, tmp_path):
    engine = Engine('create')
    engine.image = lambda image: {'Id': 'sha256:old'}
    engine.containers['cryptolabs-proxy'] = engine.current
    engine.current['Mounts'].append({'Type': 'volume', 'Name': 'fleet-data', 'Destination': str(tmp_path.parent), 'RW': True})
    monkeypatch.setattr(updates, 'SERVICES', {'prometheus': updates.SERVICES['prometheus']})
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    updates.write_job(tmp_path, {'id': 'a' * 32, 'service': 'all', 'branch': 'main', 'action': 'pull'})
    updates.run_job(tmp_path, 'a' * 32, engine=engine)
    with pytest.raises(updates.UpdateError):
        updates.submit_job('all', 'main', 'pull', directory=tmp_path, engine=engine)
    assert updates.update_status('prometheus', 'main', engine=engine, directory=tmp_path)['latest_status'] == 'unknown'


@pytest.mark.parametrize('metadata,expected', [
    ({'RepoDigests': ['prom/prometheus@sha256:abc']}, 'prom/prometheus:latest'),
    ({'RepoTags': ['prom/prometheus:v3.2']}, 'prom/prometheus:latest'),
    ({'RepoTags': ['custom/prometheus:latest']}, None),
])
def test_sha256_only_images_require_official_repository_identity(metadata, expected):
    engine = Engine()
    current = source()
    current['Config']['Image'] = 'sha256:old'
    engine.image = lambda image: metadata
    assert updates.check_target('prometheus', current, 'main', engine) == expected


def test_latest_ui_keeps_pins_and_escapes_versions():
    script = landing_script() + '''
    loadWatchdogStatus = () => {};
    const grid = {innerHTML: ''};
    const button = {style: {}};
    globalThis.document = {
        getElementById: id => id === 'versionsGrid' ? grid : id === 'targetBranch' ? {value: 'main'} : null,
        querySelector: () => button,
    };
    globalThis.fetch = async () => ({ok: true, json: async () => ({
        'prometheus': {running: true, tag: 'Pinned', version: '3.2', pinned: true, latest_status: 'latest'},
        'dc-overview': {running: true, tag: 'latest', latest_status: 'unknown', update_available: false},
        'grafana': {running: true, tag: 'latest', latest_status: 'update_available', update_available: true},
        'runpod-exporter': {running: true, tag: '<img src=x onerror=alert(1)>', latest_status: 'unknown'},
    })});
    loadVersions().then(() => console.log(JSON.stringify({html: grid.innerHTML, disabled: button.disabled})));
    '''
    result = subprocess.run(['node'], input=script, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    html = json.loads(result.stdout)['html']
    assert html.count('✓ Latest') == 1
    assert 'Unable to verify' in html
    assert 'Update available' in html
    assert "updateService('prometheus')" not in html
    assert '<img' not in html
    assert 'Pinned' in html


@pytest.mark.parametrize('status', ['latest', 'update_available', 'unknown'])
@pytest.mark.parametrize('version', [
    'd4307244' + 'a' * 56,
    'd4307244' + 'a' * 32,
    'sha256:d4307244' + 'a' * 56,
    'ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:d4307244' + 'a' * 56,
])
def test_version_hashes_stay_short_in_every_status(status, version):
    info = {'running': True, 'version': version, 'tag': 'Pinned', 'pinned': True,
            'latest_status': status}
    script = landing_script() + '''
    loadWatchdogStatus = () => {};
    const grid = {innerHTML: ''};
    globalThis.document = {
        getElementById: id => id === 'versionsGrid' ? grid : id === 'targetBranch' ? {value: 'main'} : null,
        querySelector: () => ({style: {}}),
    };
    globalThis.fetch = async () => ({ok: true, json: async () => ({'cryptolabs-proxy': INFO})});
    loadVersions().then(() => console.log(grid.innerHTML));
    '''.replace('INFO', json.dumps(info))
    result = subprocess.run(['node'], input=script, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'd4307244' in result.stdout
    assert 'd4307244' + 'a' * 32 not in result.stdout
    assert 'ghcr.io/' not in result.stdout
    assert ('✓ Latest' in result.stdout) == (status == 'latest')
    assert ('Update available' in result.stdout) == (status == 'update_available')


def test_selected_check_reports_channel_latest_without_changing_pin(monkeypatch, tmp_path):
    from tests.test_release_selection import SelectedEngine, selection_files, REF
    directory, digest = selection_files(tmp_path, origin='customer-pin', pin=REF)
    engine = SelectedEngine(tmp_path)
    engine.selection = (directory / 'selection.json').read_bytes()
    pulled = []
    monkeypatch.setattr(updates, 'pull_target', lambda target: pulled.append(target) or True)
    job = updates.submit_job('all', 'main', 'pull', directory=tmp_path / 'jobs', engine=engine,
                             selection_directory=directory, selection_id='synthetic-selection', selection_sha256=digest)
    engine.calls.clear()
    result = updates.run_job(tmp_path / 'jobs', job['id'], engine=engine)
    assert result['success']
    assert 'prom/prometheus:latest' in pulled
    assert not engine.calls
    status = updates.update_status('prometheus', 'main', engine=engine,
                                   selection_directory=directory, directory=tmp_path / 'jobs')
    assert status['latest_status'] == 'latest'
    assert status['pinned']
    assert status['target_image'] == REF


def test_selected_check_survives_absent_external_service(monkeypatch, tmp_path):
    import hashlib
    from tests.test_release_selection import SelectedEngine, selection_files
    directory, _ = selection_files(tmp_path)
    manifest_path = next((directory / 'manifests').iterdir())
    manifest = json.loads(manifest_path.read_text())
    manifest['components']['vast-price-manager'] = {'release': 'synthetic-1', 'owner': 'dc-vpm',
        'artifacts': {'linux/amd64': {'kind': 'oci',
            'reference': 'ghcr.io/cryptolabsza/vast-price-manager@sha256:' + 'd' * 64}}}
    raw = json.dumps(manifest).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (directory / 'manifests' / (digest + '.json')).write_bytes(raw)
    selected = json.loads((directory / 'selection.json').read_text())
    selected['manifest_sha256'] = digest
    selected['components']['vast-price-manager'] = {'origin': 'baseline', 'enabled': True}
    (directory / 'selection.json').write_text(json.dumps(selected))
    engine = SelectedEngine(tmp_path)
    engine.selection = (directory / 'selection.json').read_bytes()
    monkeypatch.setattr(updates, 'pull_target', lambda target: True)
    job = updates.submit_job('all', 'main', 'pull', directory=tmp_path / 'jobs', engine=engine,
                             selection_directory=directory)
    result = updates.run_job(tmp_path / 'jobs', job['id'], engine=engine)
    assert result['success']
    assert result['results']['vast-price-manager']['reason'] == 'external_owner_required'
    assert updates.update_status('prometheus', 'main', engine=engine,
        selection_directory=directory, directory=tmp_path / 'jobs')['latest_status'] == 'latest'
