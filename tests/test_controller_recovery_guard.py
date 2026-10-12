"""Synthetic auth custody, real flock exclusion and process-crash recovery."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid
from copy import deepcopy

import pytest

from cryptolabs_proxy import updates
from cryptolabs_proxy.standard_adoption import AdoptionEngine, AdoptionError

CAPABILITY = {'schema_version': 1, 'api': 'AdoptionEngine.controller_guard',
              'durable_updater_exclusion': True}


def recovery_module():
    from cryptolabs_proxy import controller_recovery
    return controller_recovery


class LocalEngine(AdoptionEngine):
    """Replace only Docker transport; execute shipped helper in a real process."""
    def __init__(self, tmp_path):
        self.timeout = 1
        self.root = tmp_path
        self.auth = tmp_path / 'auth'
        self.auth.mkdir(exist_ok=True)
        self.jobs = self.auth / 'update-jobs'
        self.source = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
            'Mounts': [{'Type': 'bind', 'Source': str(self.auth),
                        'Destination': '/data/auth', 'RW': True}],
            'State': {'Running': True}}
        self.requests = {}
        self.processes = {}
        self.ids = {}
        self.rpc_calls = []
        self.socket_paths = {}
        self.lease = None

    def create(self, name, request):
        self.requests[name] = deepcopy(request)
        self.ids[name] = 'helper-' + str(len(self.ids))
        self.socket_paths[name] = str(Path('/tmp').resolve() / ('cg-' + uuid.uuid4().hex + '.sock'))

    def start(self, name):
        request = self.requests[name]
        command = request['Config']['Cmd'][:]
        if self.lease is not None:
            command[1] = command[1].replace('GUARD_IDLE_SECONDS = 300', 'GUARD_IDLE_SECONDS = ' + str(self.lease))
        command = [str(self.jobs) if arg == '/data/auth/update-jobs' else
                   self.socket_paths[name] if arg == '/tmp/controller-guard.sock' else arg
                   for arg in command]
        self.processes[name] = subprocess.Popen([sys.executable, *command],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def inspect(self, name):
        if name == self.source['Id'] or name == 'cryptolabs-proxy':
            return deepcopy(self.source)
        name = next((n for n, i in self.ids.items() if i == name), name)
        process = self.processes.get(name)
        return {'Id': self.ids[name], 'Image': self.requests[name]['Config']['Image'],
                'Config': self.requests[name]['Config'],
                'State': {'Running': bool(process and process.poll() is None)}}

    def _controller_guard_rpc(self, helper_id, owner, action):
        self.rpc_calls.append((helper_id, action))
        name = next(n for n, i in self.ids.items() if i == helper_id)
        return recovery_module().request(self.socket_paths[name], owner, action, .3)

    def remove(self, name, ignore_missing=False):
        name = next((n for n, i in self.ids.items() if i == name), name)
        process = self.processes.get(name)
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
        Path(self.socket_paths[name]).unlink(missing_ok=True)

    def kill_guard(self):
        process = next(iter(self.processes.values()))
        process.kill()
        process.wait(timeout=2)


def marker(engine):
    return engine.jobs / 'controller-adoption.json'


def test_capability_is_published_through_existing_updater_contract():
    assert updates.get_capabilities()['controller_adoption_guard'] == CAPABILITY


def test_guard_persists_on_exit_and_matching_recovery_completes(tmp_path):
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1') as check:
        check()
        assert marker(engine).exists()
        assert marker(engine).stat().st_mode & 0o777 == 0o600
        assert engine.jobs.stat().st_mode & 0o777 == 0o700
        for name in ('dispatch.lock', 'operation.lock'):
            with (engine.jobs / name).open('r+') as lock:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = next(iter(engine.requests.values()))
        assert request['HostConfig']['NetworkMode'] == 'none'
        assert request['HostConfig']['Mounts'][0]['Source'] == str(engine.auth)
        assert 'Env' not in request['Config']
        assert len(request['HostConfig']['Mounts']) == 1
    assert marker(engine).exists()
    with pytest.raises(AdoptionError):
        with engine.controller_guard(engine.source, engine.source['Image'], 'op-1'): pass
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1', recover=True) as check:
        check.complete()
        check.complete()  # Explicit completion is idempotent for this live guard.
        assert not marker(engine).exists()
        with pytest.raises(AdoptionError): check()
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-2') as check:
        check.complete()


def test_helper_crash_and_exception_leave_durable_updater_hold(tmp_path, monkeypatch):
    engine = LocalEngine(tmp_path)
    with pytest.raises(AdoptionError):
        with engine.controller_guard(engine.source, engine.source['Image'], 'op-1') as check:
            engine.kill_guard()
            check()
    assert marker(engine).exists()
    monkeypatch.setattr(updates, 'installed_selection', lambda *a, **k: None)
    no_engine = object()
    with pytest.raises(updates.UpdateError, match='controller_recovery_required'):
        updates.submit_job('prometheus', 'main', 'update', directory=engine.jobs, engine=no_engine)
    job = {'id': '1' * 32, 'state': 'queued', 'service': 'prometheus', 'branch': 'main', 'action': 'update'}
    updates.write_job(engine.jobs, job)
    result = updates.run_job(engine.jobs, job['id'], engine=no_engine)
    assert result['state'] == 'blocked' and result['reason'] == 'controller_recovery_required'
    assert updates.read_job(engine.jobs, job['id'])['state'] == 'blocked'
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1', recover=True) as check:
        check.complete()
    with pytest.raises(RuntimeError, match='host-crash'):
        with engine.controller_guard(engine.source, engine.source['Image'], 'op-2'):
            raise RuntimeError('host-crash')
    assert marker(engine).exists()


def test_guard_detects_replaced_lock_inode_and_marker_custody(tmp_path):
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1') as check:
        (engine.jobs / 'operation.lock').unlink()
        (engine.jobs / 'operation.lock').touch(mode=0o600)
        with pytest.raises(AdoptionError): check()
        with pytest.raises(AdoptionError): check.complete()
    assert marker(engine).exists()
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1', recover=True) as check:
        value = json.loads(marker(engine).read_bytes())
        value['owner'] = 'f' * 64
        marker(engine).write_text(json.dumps(value))
        with pytest.raises(AdoptionError): check()
        with pytest.raises(AdoptionError): check.complete()
    assert marker(engine).exists()


@pytest.mark.parametrize('change', ['operation', 'source', 'mount', 'schema', 'huge', 'symlink', 'mode', 'hardlink', 'fifo'])
def test_conflicting_or_unsafe_marker_cannot_be_recovered(tmp_path, change):
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1'): pass
    source = deepcopy(engine.source)
    operation = 'op-1'
    if change == 'operation': operation = 'op-2'
    elif change == 'source': source['Id'] = 'c' * 64
    elif change == 'mount': source['Mounts'][0]['Source'] = str(tmp_path / 'other-auth')
    elif change == 'schema': marker(engine).write_text('{}')
    elif change == 'huge': marker(engine).write_bytes(b'x' * 8192)
    elif change == 'mode': marker(engine).chmod(0o644)
    elif change == 'hardlink': os.link(marker(engine), engine.jobs / 'link')
    elif change == 'symlink':
        marker(engine).rename(engine.jobs / 'saved')
        marker(engine).symlink_to(engine.jobs / 'saved')
    elif change == 'fifo':
        marker(engine).unlink()
        os.mkfifo(marker(engine), 0o600)
    before = time.monotonic()
    with pytest.raises(AdoptionError):
        with engine.controller_guard(source, source['Image'], operation, recover=True): pass
    assert time.monotonic() - before < 3
    assert marker(engine).exists()


def test_held_real_updater_lock_returns_bounded_without_marker(tmp_path):
    engine = LocalEngine(tmp_path)
    engine.jobs.mkdir(mode=0o700)
    path = engine.jobs / 'operation.lock'
    with path.open('w') as lock:
        path.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = time.monotonic()
        with pytest.raises(AdoptionError):
            with engine.controller_guard(engine.source, engine.source['Image'], 'op-1'): pass
        assert time.monotonic() - before < 3
        assert not marker(engine).exists()


@pytest.mark.parametrize('kind', ['marker', 'parent', 'lock'])
def test_unsafe_paths_block_updater_before_engine_access(tmp_path, monkeypatch, kind):
    directory = tmp_path / 'jobs'
    directory.mkdir(mode=0o700)
    if kind == 'marker': (directory / 'controller-adoption.json').symlink_to(tmp_path / 'missing')
    elif kind == 'parent':
        directory.rename(tmp_path / 'real')
        directory.symlink_to(tmp_path / 'real', target_is_directory=True)
    else: (directory / 'dispatch.lock').symlink_to(tmp_path / 'missing')
    monkeypatch.setattr(updates, 'installed_selection', lambda *a, **k: None)
    with pytest.raises(updates.UpdateError):
        updates.submit_job('prometheus', 'main', 'update', directory=directory, engine=object())
    assert not (tmp_path / 'missing').exists()


def test_prepared_host_recovery_can_establish_positively_absent_marker(tmp_path):
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'prepared-op', recover=True) as check:
        check()
        assert marker(engine).exists()
        check.complete()
    assert not marker(engine).exists()


def test_idle_expiry_refreshes_only_live_checks_and_preserves_recovery_hold(tmp_path, monkeypatch):
    engine = LocalEngine(tmp_path)
    engine.lease = .3  # Private clock-budget injection, actual helper/process/locks.
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1') as check:
        for _ in range(8):
            time.sleep(.06)
            check()
        process = next(iter(engine.processes.values()))
        assert process.poll() is None
        process.wait(timeout=2)
        assert marker(engine).exists()
        with pytest.raises(AdoptionError): check()
        with pytest.raises(AdoptionError): check.complete()
        for name in ('dispatch.lock', 'operation.lock'):
            with (engine.jobs / name).open('r+') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        monkeypatch.setattr(updates, 'installed_selection', lambda *a, **k: None)
        with pytest.raises(updates.UpdateError, match='controller_recovery_required'):
            updates.submit_job('prometheus', 'main', 'pull', directory=engine.jobs, engine=object())
        job = {'id': '2' * 32, 'state': 'queued', 'service': 'prometheus', 'branch': 'main', 'action': 'pull'}
        updates.write_job(engine.jobs, job)
        assert updates.run_job(engine.jobs, job['id'], engine=object())['state'] == 'blocked'
    engine.lease = None
    with engine.controller_guard(engine.source, engine.source['Image'], 'op-1', recover=True) as check:
        check.complete()
    assert not marker(engine).exists()


def test_abrupt_host_process_death_expires_helper_without_losing_marker(tmp_path):
    script = """import json,os,sys
from pathlib import Path
from tests.test_controller_recovery_guard import LocalEngine
engine=LocalEngine(Path(sys.argv[1]));engine.lease=1
with engine.controller_guard(engine.source,engine.source['Image'],'host-crash') as check:
 check()
 (engine.root/'host-ready.json').write_text(json.dumps({'helper_pid':next(iter(engine.processes.values())).pid}))
 os._exit(86)
"""
    result = subprocess.run([sys.executable, '-c', script, str(tmp_path)],
        cwd=Path(__file__).parents[1], env={**os.environ, 'PYTHONPATH': str(Path(__file__).parents[1] / 'src')},
        capture_output=True, timeout=5)
    assert result.returncode == 86, result.stderr.decode()
    engine = LocalEngine(tmp_path)
    assert marker(engine).exists()
    assert (tmp_path / 'host-ready.json').exists()
    with (engine.jobs / 'operation.lock').open('r+') as stream:
        with pytest.raises(BlockingIOError):
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + 3
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                assert time.monotonic() < deadline
                time.sleep(.02)
    assert marker(engine).exists()
    with engine.controller_guard(engine.source, engine.source['Image'], 'host-crash', recover=True) as check:
        check.complete()
    assert not marker(engine).exists()


def test_fixed_engine_client_proves_actual_helper_ownership(tmp_path, monkeypatch):
    from tests.test_controller_guard_transport import EngineTransport
    engine = EngineTransport(tmp_path, monkeypatch)
    with engine.controller_guard(engine.source, engine.source['Image'], 'fixed-client') as check:
        check()
        with pytest.raises(recovery_module().RecoveryError):
            recovery_module().request(next(iter(engine.socket_paths.values())), '0' * 64, 'complete', .3)
        assert marker(engine).exists()
        check.complete()
    assert engine.transport_calls
    assert all(call[2] == engine.socket_path for call in engine.transport_calls)


@pytest.mark.parametrize('kind', ['valid', 'unknown', 'symlink', 'fifo'])
def test_normal_proxy_adoption_honors_leftover_controller_marker(tmp_path, kind):
    from tests.test_proxy_lifecycle_review_repairs import LocalCoordinator
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'controller'): pass
    if kind == 'unknown': marker(engine).write_text('{}')
    elif kind == 'symlink':
        marker(engine).rename(engine.jobs / 'saved')
        marker(engine).symlink_to(engine.jobs / 'saved')
    elif kind == 'fifo':
        marker(engine).unlink()
        os.mkfifo(marker(engine), 0o600)
    coordinator = LocalCoordinator(engine.auth)
    with pytest.raises(AdoptionError):
        with coordinator.updater_guard(engine.source, engine.source['Image'], 'proxy-adoption'):
            pass
    assert marker(engine).exists()


@pytest.mark.parametrize('invalid', ['source-id', 'recover-type'])
def test_guard_rejects_invalid_operation_custody_before_helper_create(tmp_path, invalid):
    engine = LocalEngine(tmp_path)
    if invalid == 'source-id': engine.source['Id'] = 'not-an-engine-container-id'
    with pytest.raises(AdoptionError):
        with engine.controller_guard(engine.source, engine.source['Image'], 'op',
                                     recover='yes' if invalid == 'recover-type' else False): pass
    assert engine.requests == {}
    assert not marker(engine).exists()


def test_duplicate_marker_fields_are_not_an_owned_schema(tmp_path):
    engine = LocalEngine(tmp_path)
    with engine.controller_guard(engine.source, engine.source['Image'], 'op'): pass
    record = marker(engine).read_text()
    marker(engine).write_text('{"schema_version":1,' + record[1:])
    with pytest.raises(AdoptionError):
        with engine.controller_guard(engine.source, engine.source['Image'], 'op', recover=True): pass
    assert marker(engine).exists()
