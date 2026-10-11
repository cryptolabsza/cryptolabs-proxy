"""Customer lifecycle regressions; real auth, renderer, switch, and file locks."""
from contextlib import contextmanager
from copy import deepcopy
import fcntl
import io
import json
import os
from pathlib import Path
import tarfile
from types import SimpleNamespace
import pytest
from werkzeug.security import check_password_hash
from cryptolabs_proxy import auth, setup, standard_adoption as sa, updates
from tests.test_standard_adoption import Engine, REF, system


def archive(directory):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as bundle:
        bundle.add(directory, arcname='auth')
    return output.getvalue()


class LocalCoordinator(sa.AdoptionEngine):
    """Execute the unchanged production guard command with local namespace maps.

    Docker create/start/archive/remove are the only translated boundary. The
    production script runs as a real child and locks actual updater files.
    """
    def __init__(self, directory):
        self.directory = directory
        self.timeout = 5
        self.process = None
        self.marker = directory.parent / 'updater-held'

    def create(self, name, request):
        self.request = deepcopy(request)
        assert request['HostConfig']['NetworkMode'] == 'none'
        assert len(request['HostConfig']['Mounts']) == 1
        assert 'Env' not in request['Config']

    def start(self, name):
        import subprocess, sys
        cmd = self.request['Config']['Cmd']
        assert cmd[2:] == ['/data/auth/update-jobs', '/tmp/updater-held']
        self.marker.unlink(missing_ok=True)
        self.process = subprocess.Popen([sys.executable, *cmd[:2],
            str(self.directory / 'update-jobs'), str(self.marker)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def inspect(self, name):
        return {'State': {'Running': self.process.poll() is None}}

    def _file_bytes(self, name, path):
        try:
            return self.marker.read_bytes()
        except FileNotFoundError:
            raise sa.AdoptionError('marker_not_ready') from None

    def remove(self, name, **kwargs):
        if self.process and self.process.poll() is None:
            self.process.terminate()
        if self.process:
            self.process.wait(timeout=5)
        self.marker.unlink(missing_ok=True)


def lifecycle(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    data = tmp_path / 'auth'
    data.mkdir()
    monkeypatch.setattr(auth, 'DATA_DIR', data)
    auth.create_user('admin', 'customer-current-password', 'admin')
    auth.create_user('viewer', 'customer-viewer-password', 'readonly')
    engine.current['Mounts'][0] = {'Type': 'bind', 'Source': str(data), 'Destination': '/data/auth', 'RW': True}
    engine.current['Config']['Env'].extend(['FLEET_ADMIN_USER=admin', 'FLEET_ADMIN_PASS=obsolete-install-password'])
    monkeypatch.setattr(engine, 'archive_auth', lambda name: archive(data))
    coordinator = LocalCoordinator(data)
    monkeypatch.setattr(engine, 'updater_guard', coordinator.updater_guard)
    original_start = engine.start
    def start(name):
        original_start(name)
        for value in engine.containers[name]['Config']['Env']:
            key, value = value.split('=', 1)
            monkeypatch.setenv(key, value)
        auth.ensure_default_user()  # Same startup call as scripts/auth-server.py.
    monkeypatch.setattr(engine, 'start', start)
    return adoption, engine, settings, data


def test_adoption_real_initializer_preserves_current_customer_password(tmp_path, monkeypatch):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    before = (data / 'users.json').read_bytes()
    plan = adoption.plan(settings)
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    assert (data / 'users.json').read_bytes() == before
    stored = json.loads(before)['admin']['password_hash']
    assert check_password_hash(stored, 'customer-current-password')
    assert not check_password_hash(stored, 'obsolete-install-password')
    assert auth.verify_user('viewer', 'customer-viewer-password')


def test_initializer_fresh_install_bootstraps_and_restart_preserves(monkeypatch, tmp_path):
    monkeypatch.setenv('FLEET_ADMIN_USER', 'new-admin')
    monkeypatch.setenv('FLEET_ADMIN_PASS', 'bootstrap-password')
    assert auth.ensure_default_user()
    before = (auth.DATA_DIR / 'users.json').read_bytes()
    monkeypatch.setenv('FLEET_ADMIN_PASS', 'obsolete-password')
    assert not auth.ensure_default_user()
    assert (auth.DATA_DIR / 'users.json').read_bytes() == before
    assert auth.verify_user('new-admin', 'bootstrap-password')


@pytest.mark.parametrize('directive', [
    'proxy_pass http://synthetic-user:synthetic-password@backend:8080/private;',
    'set $backend https://synthetic-user:synthetic-password@backend:8443;',
    'proxy_pass "https://synthetic-user:synthetic-password@backend:8443/private";',
    'set $backend http://synthetic-user:synthetic%2Dpassword@[::1]:8080;',
])
def test_configuration_inspection_redacts_upstream_userinfo(tmp_path, monkeypatch, directive):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    engine.config = ('events {} http { server { listen 80; location /private/ { ' + directive + ' } } }').encode()
    report = adoption.inspect()
    serialized = json.dumps(report)
    assert 'synthetic-user' not in serialized
    assert 'synthetic-password' not in serialized
    assert 'synthetic%2Dpassword' not in serialized
    assert report['upstreams']


def test_configuration_inspection_keeps_noncredential_target(tmp_path, monkeypatch):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    engine.config = b'events {} http { server { location /dc/ { proxy_pass http://backend:8080; } } }'
    assert adoption.inspect()['upstreams'] == ['http://backend:8080']


def baseline_setup(tmp_path, monkeypatch, *, validate_success=True, letsencrypt=True):
    adoption, engine, settings, directory = system(tmp_path, monkeypatch)
    calls = []
    freed = []
    def run(args, **kwargs):
        calls.append(args)
        if args[:2] == ['docker', 'version']:
            return SimpleNamespace(returncode=0, stdout='linux/amd64', stderr='')
        if args[:3] == ['docker', 'image', 'inspect']:
            return SimpleNamespace(returncode=0, stdout=json.dumps([{'RepoDigests': [REF], 'Os': 'linux', 'Architecture': 'amd64'}]), stderr='')
        if args[:2] == ['docker', 'inspect']:
            return SimpleNamespace(returncode=1, stdout='', stderr='Error: No such object: cryptolabs-proxy')
        if args[:3] == ['docker', 'run', '--rm']:
            return SimpleNamespace(returncode=0 if validate_success else 1, stdout='', stderr='synthetic validation failure')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(setup, 'CONFIG_DIR', directory)
    monkeypatch.setattr(setup, 'ensure_ssl_certs', lambda config: (True, 'synthetic issued cert'))
    monkeypatch.setattr(setup, 'ensure_docker_network', lambda: True)
    monkeypatch.setattr(setup, 'get_proxy_config', lambda: None)
    monkeypatch.setattr(setup, '_free_ports_80_443', lambda: freed.append(True))
    monkeypatch.setattr(setup, '_save_internal_token', lambda token: None)
    monkeypatch.setattr(setup, 'wait_for_container_healthy', lambda *args, **kwargs: True)
    monkeypatch.setattr(setup.subprocess, 'run', run)
    # This represents normal setup, so discard the adoption fixture's registry mode.
    from cryptolabs_proxy.services import ServiceRegistry
    registry = ServiceRegistry(directory)
    registry.config = {}
    registry.save()
    config = setup.ProxyConfig('fleet.example.test', use_letsencrypt=letsencrypt,
        fleet_admin_pass='synthetic-install', release_selection_dir=Path(settings['release_selection_dir']))
    result = setup.setup_proxy(config)
    return result, calls, freed, directory


def mounts(command):
    return [command[index + 1] for index, value in enumerate(command) if value == '-v']


def test_baseline_letsencrypt_paths_have_matching_validated_runtime_mounts(tmp_path, monkeypatch):
    result, calls, freed, directory = baseline_setup(tmp_path, monkeypatch)
    assert result[0], result[1]
    start = next(cmd for cmd in calls if cmd[:3] == ['docker', 'run', '-d'])
    assert '/etc/letsencrypt:/etc/letsencrypt:ro' in mounts(start)
    assert any(':/var/www/certbot:ro' in mount for mount in mounts(start))
    validator = next(cmd for cmd in calls if cmd[:3] == ['docker', 'run', '--rm'])
    assert validator[-3:] == [REF, 'nginx', '-t']
    assert {mount.split(':', 1)[1] for mount in mounts(validator)} == {mount.split(':', 1)[1] for mount in mounts(start)
        if mount.endswith(':/etc/nginx/ssl:ro') or mount.endswith(':/etc/nginx/nginx.conf:ro')
        or mount.endswith(':/etc/letsencrypt:ro') or mount.endswith(':/var/www/certbot:ro')}
    assert calls.index(validator) < calls.index(start)
    assert '/etc/letsencrypt/live/fleet.example.test/fullchain.pem' in (directory / 'nginx.conf').read_text()
    assert freed == [True]


def test_baseline_nginx_validation_failure_stops_no_existing_service(tmp_path, monkeypatch):
    result, calls, freed, directory = baseline_setup(tmp_path, monkeypatch, validate_success=False)
    assert not result[0]
    assert not freed
    assert not any(cmd[:3] == ['docker', 'run', '-d'] or cmd[:3] == ['docker', 'rm', '-f'] for cmd in calls)


def test_production_ensure_ssl_certs_copies_existing_certificate(tmp_path, monkeypatch):
    certificate, key = tmp_path / 'fullchain.pem', tmp_path / 'privkey.pem'
    certificate.write_bytes(b'synthetic-certificate')
    key.write_bytes(b'synthetic-key')
    directory = tmp_path / 'config'
    monkeypatch.setattr(setup, 'CONFIG_DIR', directory)
    monkeypatch.setattr(setup, 'check_existing_letsencrypt_cert', lambda domain: (True, certificate, key))
    monkeypatch.setattr(setup, '_setup_renewal_hook', lambda domain: None)
    assert setup.ensure_ssl_certs(setup.ProxyConfig('fleet.example.test', use_letsencrypt=True))[0]
    assert (directory / 'ssl' / 'server.crt').read_bytes() == certificate.read_bytes()
    assert (directory / 'ssl' / 'server.key').read_bytes() == key.read_bytes()


@pytest.mark.parametrize('state', ['queued', 'running'])
def test_active_updater_job_is_rejected_before_proxy_stop(tmp_path, monkeypatch, state):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    updates.write_job(data / 'update-jobs', {'id': 'b' * 32, 'state': state})
    plan = adoption.plan(settings)
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, plan['plan_id'])
    assert not any(call[0] == 'stop' for call in engine.calls)
    assert engine.current['State']['Running']


@pytest.mark.parametrize('lock', ['dispatch.lock', 'operation.lock'])
def test_updater_lock_is_rejected_before_proxy_stop(tmp_path, monkeypatch, lock):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    plan = adoption.plan(settings)
    with updates._lock(data / 'update-jobs', lock):
        with pytest.raises(sa.AdoptionError):
            adoption.adopt(settings, plan['plan_id'])
    assert not any(call[0] == 'stop' for call in engine.calls)


def test_job_drift_at_stop_is_held_and_source_restarted(tmp_path, monkeypatch):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    stop = engine.stop
    def drift(name, **kwargs):
        stop(name, **kwargs)
        if name == 'old-id':
            # An uncoordinated writer must not evade the held-job check.
            updates.write_job(data / 'update-jobs', {'id': 'c' * 32, 'state': 'running'})
    monkeypatch.setattr(engine, 'stop', drift)
    plan = adoption.plan(settings)
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, plan['plan_id'])
    assert not any(call[0] == 'start' and call[1] == 'old-id' for call in engine.calls)
    assert engine.containers['cryptolabs-proxy']['Image'] == 'sha256:old'
    assert engine.containers['cryptolabs-proxy']['State']['Running']
    assert 'FLEET_ADMIN_PASS=' in engine.containers['cryptolabs-proxy']['Config']['Env']
    assert not engine.current['State']['Running']


def test_dispatch_and_operation_are_excluded_through_candidate_start(tmp_path, monkeypatch):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    start = engine.start
    checked = []
    def check_locks(name):
        if engine.containers[name]['Id'] == 'new-id':
            for lock in ('dispatch.lock', 'operation.lock'):
                with (data / 'update-jobs' / lock).open('a+') as stream:
                    with pytest.raises(BlockingIOError):
                        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                checked.append(lock)
        start(name)
    monkeypatch.setattr(engine, 'start', check_locks)
    plan = adoption.plan(settings)
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    assert checked == ['dispatch.lock', 'operation.lock']
    for lock in checked:
        with (data / 'update-jobs' / lock).open('a+') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_completed_updater_jobs_allow_preserving_adoption(tmp_path, monkeypatch):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    updates.write_job(data / 'update-jobs', {'id': 'd' * 32, 'state': 'completed'})
    job_before = (data / 'update-jobs' / ('d' * 32 + '.json')).read_bytes()
    plan = adoption.plan(settings)
    assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    assert (data / 'update-jobs' / ('d' * 32 + '.json')).read_bytes() == job_before


def test_actual_submit_cannot_queue_during_adoption(tmp_path, monkeypatch):
    import threading
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    monkeypatch.setattr(updates, 'installed_selection', lambda *args, **kwargs: None)
    queued = []
    attempted = threading.Event()
    finished = threading.Event()
    real_lock = updates._lock
    @contextmanager
    def observed_lock(directory, name):
        attempted.set()
        with real_lock(directory, name):
            yield
    monkeypatch.setattr(updates, '_lock', observed_lock)
    class SubmitEngine:
        def inspect(self, name):
            source = deepcopy(engine.current)
            source['Mounts'][0]['Destination'] = str(data)  # Docker namespace map.
            return source
        def create(self, name, request):
            pass
        def start(self, name):
            pass
    def submit():
        try:
            queued.append(updates.submit_job('all', 'main', 'pull', directory=data / 'update-jobs', engine=SubmitEngine()))
        except Exception as error:
            queued.append(error)
        finally:
            finished.set()
    thread = threading.Thread(target=submit)
    start = engine.start
    def candidate_start(name):
        if engine.containers[name]['Id'] == 'new-id':
            thread.start()
            assert attempted.wait(2)
            assert not finished.wait(.1)
            assert not (data / 'update-jobs' / 'active.json').exists()
        start(name)
    monkeypatch.setattr(engine, 'start', candidate_start)
    plan = adoption.plan(settings)
    try:
        assert adoption.adopt(settings, plan['plan_id'])['state'] == 'adopted'
    finally:
        if thread.ident:
            thread.join(timeout=5)
    assert finished.is_set()
    assert len(queued) == 1 and isinstance(queued[0], dict), queued
    assert queued[0]['state'] == 'queued'


def test_same_store_drift_is_held_before_candidate_creation(tmp_path, monkeypatch):
    adoption, engine, settings, data = lifecycle(tmp_path, monkeypatch)
    stop = engine.stop
    def drift(name, **kwargs):
        stop(name, **kwargs)
        if name == 'old-id':
            (data / 'external.json').write_text('{"changed":true}')
    monkeypatch.setattr(engine, 'stop', drift)
    plan = adoption.plan(settings)
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, plan['plan_id'])
    assert not any(call[0] == 'start' and call[1] == 'old-id' for call in engine.calls)
    assert engine.containers['cryptolabs-proxy']['Image'] == 'sha256:old'
    assert engine.containers['cryptolabs-proxy']['State']['Running']
    assert 'FLEET_ADMIN_PASS=' in engine.containers['cryptolabs-proxy']['Config']['Env']
    assert not engine.current['State']['Running']
    assert (data / 'external.json').read_text() == '{"changed":true}'
