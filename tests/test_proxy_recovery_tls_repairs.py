"""Actual released/current auth startup and production TLS/recovery regressions.

Run: PYTHONPATH=src python3 -m pytest -s -q tests/test_proxy_recovery_tls_repairs.py
Only OS/Docker boundaries are translated. Released auth/server bytes come from
the pinned base Git revision, with independent SHA evidence in the raw output.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import threading
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest
from werkzeug.security import check_password_hash
from cryptolabs_proxy import auth, setup, updates
from cryptolabs_proxy import standard_adoption as sa
from cryptolabs_proxy.services import ServiceRegistry, DEFAULT_SERVICES
from cryptolabs_proxy.release_selection import load

ROOT = Path(__file__).resolve().parents[1]
BASE = '9cb692511096d87c6863873db3e8014e04881e72'


@pytest.fixture(scope='session', autouse=True)
def old_startup(tmp_path_factory):
    global OLD_TREE
    import shutil
    OLD_TREE = tmp_path_factory.mktemp('released-old-startup')
    shutil.copytree(ROOT/'src', OLD_TREE/'src')
    (OLD_TREE/'scripts').mkdir()
    for relative in ('src/cryptolabs_proxy/auth.py', 'scripts/auth-server.py'):
        result = subprocess.run(['git', 'show', BASE+':'+relative], cwd=ROOT,
            capture_output=True, check=True)
        (OLD_TREE/relative).write_bytes(result.stdout)
    print('OLD_AUTH_SHA256', hashlib.sha256((OLD_TREE/'src/cryptolabs_proxy/auth.py').read_bytes()).hexdigest())

REF = 'ghcr.io/cryptolabsza/cryptolabs-proxy@sha256:' + '4' * 64


def startup(version, directory, env):
    tree = OLD_TREE if version == 'base' else ROOT
    code = "import runpy; runpy.run_path(" + repr(str(tree / 'scripts/auth-server.py')) + ",run_name='startup_probe'); "
    code += "import cryptolabs_proxy, cryptolabs_proxy.auth as a, hashlib, json; from pathlib import Path; "
    code += "assert Path(a.__file__).resolve() == " + repr(tree/'src/cryptolabs_proxy/auth.py').replace('PosixPath(', 'Path(') + "; "
    code += "print(json.dumps({'package_version':cryptolabs_proxy.__version__, 'auth_file':a.__file__, 'auth_sha256':hashlib.sha256(Path(a.__file__).read_bytes()).hexdigest()}))"
    result = subprocess.run([sys.executable, '-c', code], env={**os.environ,
        'PYTHONPATH': str(tree / 'src'), 'AUTH_DATA_DIR': str(directory), **env},
        capture_output=True, text=True, timeout=20)
    print('ACTUAL_STARTUP', version, 'exit', result.returncode)
    print(result.stdout.strip())
    return result


def archive(directory):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as bundle:
        bundle.add(directory, arcname='auth')
    return out.getvalue()


class Guard(sa.AdoptionEngine):
    """Translate only container process/namespace boundaries for the real guard."""
    def __init__(self, directory):
        self.directory = directory
        self.timeout = 3
        self.process = None
        self.marker = directory.parent / 'guard-marker'
    def create(self, name, request):
        self.request = request
        assert request['HostConfig']['Mounts'][0]['Source'] == str(self.directory)
        assert request['HostConfig']['NetworkMode'] == 'none'
        assert 'Env' not in request['Config']
    def start(self, name):
        cmd = self.request['Config']['Cmd']
        self.process = subprocess.Popen([sys.executable, *cmd[:2], str(self.directory / 'update-jobs'), str(self.marker)])
    def inspect(self, name):
        return {'State': {'Running': self.process.poll() is None}}
    def _file_bytes(self, name, path):
        if not self.marker.exists():
            raise sa.AdoptionError('not_ready')
        return self.marker.read_bytes()
    def remove(self, name, **kw):
        if self.process and self.process.poll() is None:
            self.process.terminate()
        if self.process:
            self.process.wait(timeout=3)
        self.marker.unlink(missing_ok=True)


class Engine:
    """Docker boundary model; starts execute each image's actual auth-server."""
    def __init__(self, directory, nginx):
        self.directory, self.nginx = directory, nginx
        self.calls = []
        self.fail_health = False
        self.timeout = 3
        self.proof_processes = {}
        self.requests = {}
        self.created = 0
        self.on_start = None
        self.on_stop = None
        self.guard = Guard(directory)
        self.source = {'Id': 'source-79', 'Image': 'sha256:source', 'Config': {
            'Image': 'source-ref', 'Env': ['AUTH_SECRET_KEY=independent-session-key',
            'FLEET_ADMIN_USER=operator', 'FLEET_ADMIN_PASS=obsolete-installer-password'],
            'Labels': {'com.centurylinklabs.watchtower.enable': 'true'},
            'Entrypoint': ['/app/entrypoint.sh'], 'Cmd': None},
            'State': {'Running': True, 'Health': {'Status': 'healthy'}},
            'HostConfig': {'RestartPolicy': {'Name': 'unless-stopped'}, 'Binds': [],
                'PortBindings': {'80/tcp': [{'HostPort': '8080'}]}},
            'Mounts': [{'Type': 'bind', 'Source': str(directory), 'Destination': '/data/auth', 'RW': True},
                {'Type': 'bind', 'Source': str(directory.parent/'ssl'), 'Destination': '/etc/nginx/ssl', 'RW': False}],
            'NetworkSettings': {'Networks': {'cryptolabs': {'Aliases': ['independent-proxy'],
                'IPAMConfig': {'IPv4Address': '172.30.0.19'}}}}}
        self.objects = {'cryptolabs-proxy': self.source}
        self.ids = {self.source['Id']: self.source}
    def inspect(self, name):
        return deepcopy(self.ids.get(name, self.objects.get(name)))
    def image(self, ref):
        return {'Id': 'sha256:candidate' if ref == REF else 'sha256:source', 'Os': 'linux',
            'Architecture': 'amd64', 'RepoDigests': [REF] if ref == REF else []}
    def read_config(self, name):
        return self.nginx
    def pull(self, image):
        self.calls.append(('pull', image))
    def artifact_file_sha256(self, *args):
        return hashlib.sha256((ROOT/'src/cryptolabs_proxy/auth.py').read_bytes()).hexdigest()
    def validate(self, *args):
        self.calls.append(('validate_boundary_only',))
    def updater_guard(self, *args):
        return self.guard.updater_guard(*args)
    def prove_recovery_auth(self, *args):
        return sa.AdoptionEngine.prove_recovery_auth(self, *args)
    def _file_bytes(self, name, path):
        marker = self.directory.parent / (name+'-marker')
        if not marker.exists(): raise sa.AdoptionError('not_ready')
        return marker.read_bytes()
    def archive_auth(self, name):
        return archive(self.directory)
    def restore_auth(self, name, data, image, identity):
        # The archive writing Docker boundary is translated; only production-owned files.
        for key in sa.OWNED_AUTH_FILES:
            (self.directory/key).unlink(missing_ok=True)
        with tarfile.open(fileobj=io.BytesIO(sa.owned_auth_archive(data))) as bundle:
            for member in bundle:
                (self.directory/Path(member.name).name).write_bytes(bundle.extractfile(member).read())
        assert sa.auth_state(archive(self.directory)) == sa.auth_state(data)
    def stop(self, name, **kw):
        self.calls.append(('stop', name))
        self.ids.get(name, self.objects.get(name))['State']['Running'] = False
        if self.on_stop:
            self.on_stop(name)
    def disconnect(self, name, network):
        self.calls.append(('disconnect', name, network))
    def rename(self, old, new):
        obj = self.objects.pop(old, None) or self.ids[old]
        for key in list(self.objects):
            if self.objects[key] is obj:
                del self.objects[key]
        self.objects[new] = obj
    def create(self, name, request):
        self.calls.append(('create', name))
        self.request = deepcopy(request)
        self.requests[name] = deepcopy(request)
        self.created += 1
        obj = {'Id': 'created-'+str(self.created), 'Image': 'sha256:candidate' if request['Config']['Image'] == REF else 'sha256:source', 'Config': deepcopy(request['Config']),
            'HostConfig': deepcopy(request['HostConfig']), 'State': {'Running': False, 'Health': {'Status': 'healthy'}},
            'NetworkSettings': {'Networks': deepcopy(request['NetworkingConfig']['EndpointsConfig'])},
            'Mounts': [{'Type': m['Type'], 'Source': m['Source'], 'Destination': m['Target'],
                'RW': not m.get('ReadOnly', False)} for m in request['HostConfig']['Mounts']]}
        self.objects[name] = obj
        self.ids[obj['Id']] = obj
    def start(self, name):
        obj = self.ids.get(name, self.objects.get(name))
        self.calls.append(('start', name, obj['Id']))
        if self.on_start:
            self.on_start(name, obj)
        if name.startswith('cryptolabs-recovery-proof-'):
            request = self.requests[name]
            assert request['HostConfig']['NetworkMode'] == 'none'
            assert not request['NetworkingConfig']['EndpointsConfig']
            assert not request['HostConfig'].get('PortBindings')
            command = request['Config']['Entrypoint'][2]
            command = command.replace('/app/auth-server.py', str(OLD_TREE/'scripts/auth-server.py'))
            command = command.replace('/tmp/auth-preserved', str(self.directory.parent/(name+'-marker')))
            self.proof_processes[name] = subprocess.Popen([sys.executable, '-c', command],
                env={**os.environ, 'PYTHONPATH': str(OLD_TREE/'src'), 'AUTH_DATA_DIR': str(self.directory),
                     **dict(e.split('=', 1) for e in obj['Config']['Env'])})
            obj['State']['Running'] = True
            print('ACTUAL_OLD_PRODUCTION_PROOF', hashlib.sha256((OLD_TREE/'src/cryptolabs_proxy/auth.py').read_bytes()).hexdigest())
            return
        version = 'base' if obj['Image'] == 'sha256:source' else 'candidate'
        result = startup(version, self.directory, dict(e.split('=', 1) for e in obj['Config']['Env'])); assert result.returncode == 0, result.stderr
        obj['State']['Running'] = True
        if version == 'candidate':
            self.nginx = Path(next(m['Source'] for m in self.request['HostConfig']['Mounts'] if m['Target'] == '/etc/nginx/nginx.conf')).read_bytes()
    def connect(self, *args):
        self.calls.append(('connect', *args))
    def remove(self, name, **kw):
        process = self.proof_processes.pop(name, None)
        if process:
            process.terminate(); process.wait(timeout=3)
        self.objects.pop(name, None)
    def anonymous_auth(self, name, tls):
        return not self.fail_health  # No TLS acceptance claim; injectable late switch failure.


def fixture(tmp_path, monkeypatch):
    directory = tmp_path/'config'
    directory.mkdir()
    data = tmp_path/'auth'
    data.mkdir()
    monkeypatch.setattr(auth, 'DATA_DIR', data)
    auth.create_user('operator', 'customer-secret-unchanged', 'admin', require_password_change=True)
    auth.create_user('reader', 'reader-secret-unchanged', 'readonly', enabled=False)
    (data/'internal-token').write_text('independent-internal-token')
    (data/'customer-unknown-file').write_text('preserve-unknown')
    jobs = data/'update-jobs'
    updates.write_job(jobs, {'id': '6'*32, 'state': 'completed', 'result': 'preserve'})
    selection = tmp_path/'selection'
    (selection/'manifests').mkdir(parents=True)
    manifest = {'schema_version': 1, 'selection_contract': 1, 'baseline_id': 'independent-83',
        'components': {'cryptolabs-proxy': {'release': 'independent', 'owner': 'proxy-updater',
            'artifacts': {'linux/amd64': {'kind': 'oci', 'reference': REF}}}}}
    raw = json.dumps(manifest).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (selection/'manifests'/(digest+'.json')).write_bytes(raw)
    (selection/'selection.json').write_text(json.dumps({'schema_version': 1, 'selection_id': 'independent-83',
        'manifest_sha256': digest, 'components': {'cryptolabs-proxy': {'enabled': True, 'origin': 'baseline'}}}))
    settings = {'schema_version': 1, 'domain': 'review.example.test', 'tls': 'self-signed',
        'release_selection_dir': str(selection), 'services': {'dc-overview': {k: DEFAULT_SERVICES['dc-overview'][k]
            for k in ('container_name', 'path', 'port')}}, 'obsolete_overlays': [], 'obsolete_owner_labels': []}
    engine = Engine(data, sa.render_standard(sa._declaration(settings)))
    registry = ServiceRegistry(directory)
    registry.services = {'dc-overview': DEFAULT_SERVICES['dc-overview']}
    registry.save()
    monkeypatch.setattr(sa.os, 'geteuid', lambda: 0)
    return sa.StandardAdoption(directory, engine=engine), engine, settings, data


def unchanged_files(data):
    return {str(p.relative_to(data)): p.read_bytes() for p in data.rglob('*') if p.is_file()
        and p.name not in ('dispatch.lock', 'operation.lock')}


def test_success_restart_and_reconfigure_preserve_accounts(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    before = unchanged_files(data)
    assert adoption.adopt(settings, adoption.plan(settings)['plan_id'])['state'] == 'adopted'
    engine.start('cryptolabs-proxy')
    config = setup.ProxyConfig(settings['domain'], use_letsencrypt=False,
        fleet_admin_user='operator', fleet_admin_pass='different-obsolete-bootstrap',
        auth_secret='must-not-replace')
    assert adoption.reconfigure(config)[0]
    assert unchanged_files(data) == before
    assert 'AUTH_SECRET_KEY=independent-session-key' in engine.request['Config']['Env']
    print('SUCCESS_AND_RECONFIGURE preserved', sorted(before))


def test_failed_switch_recovery_executes_old_image_initializer(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    before = unchanged_files(data)
    engine.fail_health = True
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    after = unchanged_files(data)
    users = json.loads(after['users.json'])
    print('ROLLBACK', json.dumps({'source_running': engine.objects['cryptolabs-proxy']['State']['Running'],
        'restored_id': engine.objects['cryptolabs-proxy']['Id'], 'users_bytes_unchanged': after['users.json'] == before['users.json'],
        'obsolete_password_accepted': check_password_hash(users['operator']['password_hash'], 'obsolete-installer-password'),
        'customer_password_accepted': check_password_hash(users['operator']['password_hash'], 'customer-secret-unchanged'),
        'require_password_change': users['operator']['require_password_change']}))
    assert after == before
    restored = engine.objects['cryptolabs-proxy']
    assert restored['Image'] == engine.source['Image']
    assert 'FLEET_ADMIN_PASS=' in restored['Config']['Env']
    assert not engine.source['State']['Running']
    assert restored['Config']['Labels'] == engine.source['Config']['Labels']
    assert restored['HostConfig']['RestartPolicy'] == engine.source['HostConfig']['RestartPolicy']
    assert restored['NetworkSettings'] == engine.source['NetworkSettings']
    proof = next(i for i,c in enumerate(engine.calls) if c[0] == 'start' and c[1].startswith('cryptolabs-recovery-proof-'))
    restored_start = next(i for i,c in enumerate(engine.calls) if c[0] == 'start' and c[2] == restored['Id'])
    assert proof < restored_start


@pytest.mark.parametrize('content', [b'{}', b'{"operator":'])
def test_bootstrap_rejects_existing_empty_or_unreadable_identity(tmp_path, content):
    data = tmp_path/'existing'
    data.mkdir()
    (data/'users.json').write_bytes(content)
    result = startup('candidate', data, {'FLEET_ADMIN_USER': 'operator', 'FLEET_ADMIN_PASS': 'obsolete-installer-password'})
    assert result.returncode != 0
    print('BOOTSTRAP_EXISTING', repr(content), 'bytes_unchanged', (data/'users.json').read_bytes() == content)
    assert (data/'users.json').read_bytes() == content


def test_fresh_bootstrap_does_not_replay_on_restart(tmp_path):
    data = tmp_path/'fresh'
    startup('candidate', data, {'FLEET_ADMIN_USER': 'fresh-83', 'FLEET_ADMIN_PASS': 'initial-secret'})
    before = (data/'users.json').read_bytes()
    startup('candidate', data, {'FLEET_ADMIN_USER': 'fresh-83', 'FLEET_ADMIN_PASS': 'obsolete-secret'})
    assert (data/'users.json').read_bytes() == before


def test_existing_custom_users_without_environment_admin_remain_authoritative(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, 'DATA_DIR', tmp_path)
    auth.create_user('customer-viewer', 'viewer-authority', 'readonly', enabled=False)
    before = (tmp_path/'users.json').read_bytes()
    result = startup('candidate', tmp_path, {'FLEET_ADMIN_USER': 'missing-admin', 'FLEET_ADMIN_PASS': 'obsolete'})
    assert result.returncode == 0
    assert (tmp_path/'users.json').read_bytes() == before


def test_existing_identity_stat_failure_cannot_be_mistaken_for_fresh_install(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, 'DATA_DIR', tmp_path)
    identity = tmp_path/'users.json'
    auth.create_user('customer-operator','customer-password','admin')
    before = identity.read_bytes()
    original = Path.lstat
    def unreadable(path, *args, **kwargs):
        if path == identity: raise PermissionError('boundary permission denied')
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'lstat', unreadable)
    monkeypatch.setenv('FLEET_ADMIN_PASS','obsolete')
    with pytest.raises(RuntimeError): auth.ensure_default_user()
    assert identity.read_bytes() == before


@pytest.mark.parametrize('failure', ['proof', 'create', 'start', 'health', 'account-drift'])
def test_failed_recovery_never_restarts_original_obsolete_authority(tmp_path, monkeypatch, failure):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    before = unchanged_files(data)
    engine.fail_health = True
    if failure == 'proof':
        monkeypatch.setattr(engine, 'prove_recovery_auth', lambda *a: (_ for _ in ()).throw(sa.AdoptionError('proof_failed')))
    else:
        create, start = engine.create, engine.start
        def failed_create(name, request):
            if request['Config']['Image'] == 'sha256:source' and name == 'cryptolabs-proxy' and failure == 'create':
                raise sa.AdoptionError('create_failed')
            create(name, request)
        def failed_start(name):
            obj = engine.inspect(name)
            if name == 'cryptolabs-proxy' and obj['Image'] == 'sha256:source':
                if failure == 'start': raise sa.AdoptionError('start_failed')
                start(name)
                if failure == 'health': engine.objects[name]['State']['Health']['Status'] = 'unhealthy'
                if failure == 'account-drift': (data/'settings.json').write_text('{"require_password_change":false}')
            else: start(name)
        monkeypatch.setattr(engine, 'create', failed_create)
        monkeypatch.setattr(engine, 'start', failed_start)
    plan = adoption.plan(settings)
    with pytest.raises(sa.AdoptionError): adoption.adopt(settings, plan['plan_id'])
    assert not engine.source['State']['Running']
    assert not any(c[0] == 'start' and c[2] == 'source-79' for c in engine.calls)
    assert (data/'users.json').read_bytes() == before['users.json']
    assert (data/'customer-unknown-file').read_bytes() == before['customer-unknown-file']
    outcome = json.loads((adoption.backup_root/plan['plan_id']/'outcome.json').read_text())
    assert outcome['state'] == 'forward_repair_required'
    assert not engine.objects.get('cryptolabs-proxy', {}).get('State', {}).get('Running')


@pytest.mark.parametrize('state', ['queued', 'running'])
def test_active_jobs_rejected_before_stop(tmp_path, monkeypatch, state):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    updates.write_job(data/'update-jobs', {'id': '7'*32, 'state': state})
    before = unchanged_files(data)
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    assert not any(c[0] == 'stop' for c in engine.calls)
    assert unchanged_files(data) == before


@pytest.mark.parametrize('lock', ['dispatch.lock', 'operation.lock'])
def test_existing_real_lock_rejected_before_stop(tmp_path, monkeypatch, lock):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    with updates._lock(data/'update-jobs', lock):
        with pytest.raises(sa.AdoptionError):
            adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    assert not any(c[0] == 'stop' for c in engine.calls)


def test_actual_dispatch_and_operation_wait_until_guard_cleanup(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    directory = data/'update-jobs'
    terminal = {'id': '6'*32, 'state': 'completed'}
    finished_dispatch, finished_worker = threading.Event(), threading.Event()
    results = []
    class SubmitBoundary:
        def inspect(self, name):
            obj = engine.inspect('cryptolabs-proxy')
            obj['Mounts'][0]['Destination'] = str(data)
            return obj
        def create(self, *args): pass
        def start(self, *args): pass
    def dispatch():
        try:
            results.append(updates.submit_job('dc-overview', 'main', 'pull', directory=directory,
                selection_directory=tmp_path/'no-selection', engine=SubmitBoundary()))
        finally: finished_dispatch.set()
    def operation():
        try: results.append(updates.run_job(directory, terminal['id'], engine=SubmitBoundary()))
        finally: finished_worker.set()
    threads = [threading.Thread(target=dispatch), threading.Thread(target=operation)]
    def candidate_started(name, obj):
        if obj['Image'] == 'sha256:candidate':
            for thread in threads: thread.start()
            assert not finished_dispatch.wait(.2)
            assert not finished_worker.wait(.2)
            assert not (directory/'active.json').exists()
    engine.on_start = candidate_started
    assert adoption.adopt(settings, adoption.plan(settings)['plan_id'])['state'] == 'adopted'
    for thread in threads: thread.join(timeout=5)
    assert finished_dispatch.is_set() and finished_worker.is_set()
    assert any(r.get('state') == 'queued' for r in results)
    assert any(r.get('state') == 'completed' for r in results)
    print('REAL_UPDATER_ENTRYPOINTS blocked under guard and resumed after cleanup')


def test_uncoordinated_external_drift_preserved_and_held(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    engine.on_stop = lambda name: (data/'customer-unknown-file').write_text('external-drift') if name == 'source-79' else None
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, adoption.plan(settings)['plan_id'])
    assert not any(r['Config']['Image'] == REF for r in engine.requests.values())
    assert (data/'customer-unknown-file').read_text() == 'external-drift'
    assert engine.objects['cryptolabs-proxy']['State']['Running']
    assert not engine.source['State']['Running']


@pytest.mark.parametrize('directive', [
    'proxy_pass HTTP://review83:rawSecret83@origin.example:91;',
    'set $upstream "https://review83:encoded%3Asecret83@[::1]:443/private";',
    "proxy_pass 'http://review83:rawSecret83@origin.example:91/private';",
    'set $upstream https://review83@origin.example:443;',
])
def test_structural_upstream_redaction(tmp_path, monkeypatch, directive):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    engine.nginx = ('events {} http { server { location /test/ { '+directive+' } } }').encode()
    result = json.dumps(adoption.inspect())
    assert all(secret not in result for secret in ('review83', 'rawSecret83', 'encoded%3Asecret83'))
    assert 'credential-bearing upstream redacted' in result


@pytest.mark.parametrize('drift', ['selection', 'runtime', 'config', 'auth-mount'])
def test_cas_rejects_changed_plan_before_any_stop(tmp_path, monkeypatch, drift):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    plan = adoption.plan(settings)
    if drift == 'selection':
        path = Path(settings['release_selection_dir'])/'selection.json'
        value = json.loads(path.read_text()); value['selection_id'] = 'independent-84'
        path.write_text(json.dumps(value))
    elif drift == 'runtime':
        engine.source['Config']['Env'].append('DRIFT=changed')
    elif drift == 'config':
        engine.nginx += b'\n# changed exact bytes\n'
    else:
        engine.source['Mounts'][0]['Source'] = str(tmp_path/'different-store')
    with pytest.raises(sa.AdoptionError):
        adoption.adopt(settings, plan['plan_id'])
    assert not any(c[0] == 'stop' for c in engine.calls)


def test_customer_pin_required_policy_forwarding_acme_and_only_proxy(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    selected = Path(settings['release_selection_dir'])/'selection.json'
    value = json.loads(selected.read_text())
    value['components']['cryptolabs-proxy'].update(origin='customer-pin', pin=REF)
    selected.write_text(json.dumps(value))
    settings['host_forward_groups'] = [{'hostnames': ['console.example.test', 'metrics.example.test'],
        'http': {'origin': 'http://192.0.2.84:8181', 'read_timeout_seconds': 97, 'websocket': True},
        'https': {'origin': 'https://192.0.2.84:8444', 'verify_tls': True, 'sni': True},
        'certificate': '/etc/nginx/ssl/forward.crt', 'certificate_key': '/etc/nginx/ssl/forward.key'}]
    settings['acme_challenge'] = {'origin': 'http://192.0.2.85:8088', 'read_timeout_seconds': 13}
    engine.nginx = sa.render_standard(sa._declaration(settings))
    before = unchanged_files(data)
    assert adoption.adopt(settings, adoption.plan(settings)['plan_id'])['state'] == 'adopted'
    request = engine.request
    assert request['Config']['Image'] == REF
    assert request['Config']['Labels']['io.cryptolabs.update.origin'] == 'customer-pin'
    assert request['Config']['Labels']['com.centurylinklabs.watchtower.enable'] == 'false'
    assert 'RELEASE_SELECTION_REQUIRED=true' in request['Config']['Env']
    mount = next(m for m in request['HostConfig']['Mounts'] if m['Target'] == '/data/auth')
    assert mount['Source'] == str(data)
    assert unchanged_files(data) == before
    rendered = engine.nginx.decode()
    for text in ['server_name console.example.test metrics.example.test;', 'proxy_pass http://192.0.2.84:8181;',
                 'proxy_pass https://192.0.2.84:8444;', 'location ^~ /.well-known/acme-challenge/',
                 'proxy_pass http://192.0.2.85:8088;', 'proxy_ssl_verify on;', 'proxy_read_timeout 97s;']:
        assert text in rendered
    assert [c[1] for c in engine.calls if c[0] == 'create'] == ['cryptolabs-proxy']
    assert all(c[1] == REF for c in engine.calls if c[0] == 'pull')
    print('PIN_REQUIRED_FORWARD_ACME_ONLY_PROXY preserved')


@pytest.mark.parametrize('existing_cert,validation_ok', [(True, True), (True, False), (False, False)])
def test_real_ssl_path_and_selected_runtime_command(tmp_path, monkeypatch, existing_cert, validation_ok):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    directory = adoption.config_dir
    cert, key = tmp_path/'fullchain.pem', tmp_path/'privkey.pem'
    cert.write_bytes(b'boundary-certificate')
    key.write_bytes(b'boundary-key')
    calls, freed = [], []
    monkeypatch.setattr(setup, 'CONFIG_DIR', directory)
    monkeypatch.setattr(setup, 'check_existing_letsencrypt_cert', lambda domain: (existing_cert, cert, key))
    monkeypatch.setattr(setup, '_setup_renewal_hook', lambda domain: None)
    monkeypatch.setattr(setup, 'ensure_docker_network', lambda: True)
    monkeypatch.setattr(setup, 'get_proxy_config', lambda: {'FLEET_ADMIN_USER': 'operator', 'FLEET_ADMIN_PASS': 'obsolete'})
    monkeypatch.setattr(setup, '_free_ports_80_443', lambda: freed.append('port_cleanup'))
    monkeypatch.setattr(setup, '_save_internal_token', lambda token: None)
    monkeypatch.setattr(setup, 'wait_for_container_healthy', lambda *a, **kw: True)
    monkeypatch.setattr(setup.shutil, 'which', lambda name: '/boundary/certbot')
    copy = setup.shutil.copy2
    def namespace_copy(source, destination):
        if str(source).startswith('/etc/letsencrypt/live/'):
            source = cert if Path(source).name == 'fullchain.pem' else key
        return copy(source, destination)
    monkeypatch.setattr(setup.shutil, 'copy2', namespace_copy)
    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ['docker', 'version']:
            return SimpleNamespace(returncode=0, stdout='linux/amd64', stderr='')
        if cmd[:3] == ['docker', 'image', 'inspect']:
            return SimpleNamespace(returncode=0, stdout=json.dumps([engine.image(REF)]), stderr='')
        if cmd[:2] == ['docker', 'inspect']:
            return SimpleNamespace(returncode=1, stdout='', stderr='Error: No such object: cryptolabs-proxy')
        if cmd[:3] == ['docker', 'run', '--rm']:
            return SimpleNamespace(returncode=0 if validation_ok else 1, stdout='', stderr='syntax failure boundary')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    monkeypatch.setattr(setup.subprocess, 'run', run)
    config = setup.ProxyConfig(settings['domain'], use_letsencrypt=True, email='review@example.test',
        fleet_admin_pass='different-install', release_selection_dir=Path(settings['release_selection_dir']))
    ok, message = setup.setup_proxy(config)
    validator = next(c for c in calls if c[:3] == ['docker', 'run', '--rm'])
    print('SSL_TRACE', json.dumps({'existing_cert': existing_cert, 'validation_ok': validation_ok,
        'result': [ok, message], 'commands': calls, 'port_cleanup': freed}))
    assert validator[-3:] == [REF, 'nginx', '-t']
    if validation_ok:
        runtime = next(c for c in calls if c[:3] == ['docker', 'run', '-d'])
        def namespaces(command):
            return {command[i+1].split(':', 1)[1] for i,v in enumerate(command) if v == '-v'
                and any(x in command[i+1] for x in ('/etc/nginx/ssl', '/etc/nginx/nginx.conf', '/etc/letsencrypt', '/var/www/certbot'))}
        assert namespaces(runtime) == namespaces(validator)
        assert runtime[-1] == REF
        assert '/etc/letsencrypt/live/review.example.test/fullchain.pem' in (directory/'nginx.conf').read_text()
    else:
        assert not ok and not freed
        assert not any(c[:3] == ['docker', 'run', '-d'] for c in calls)
        assert not any(c[:2] == ['docker', 'stop'] or c[:2] == ['systemctl', 'stop'] for c in calls)


@pytest.mark.parametrize('challenge', ['mounted-webroot', 'busy-standalone', 'timeout'])
def test_actual_certificate_acquisition_keeps_running_customer_service(tmp_path, monkeypatch, challenge):
    monkeypatch.setattr(setup, 'CONFIG_DIR', tmp_path)
    monkeypatch.setattr(setup.shutil, 'which', lambda name: '/boundary/certbot')
    calls = []
    source = {'State': {'Running': True}, 'Mounts': []}
    webroot = tmp_path/'certbot'/'www'
    if challenge == 'mounted-webroot':
        source['Mounts'].append({'Source': str(webroot), 'Destination': '/var/www/certbot', 'RW': False})
    declaration = {'domain':'cert.example.test', 'tls':'letsencrypt', 'services':{}}
    nginx = sa.render_standard(declaration)
    assert b'root /var/www/certbot;' in nginx
    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ['docker', 'inspect']:
            return SimpleNamespace(returncode=0, stdout=json.dumps([source]), stderr='')
        if command[:3] == ['docker', 'exec', 'cryptolabs-proxy']:
            return SimpleNamespace(returncode=0, stdout=nginx.decode(), stderr='')
        if command[:2] == ['certbot', 'certonly']:
            if challenge == 'timeout': raise subprocess.TimeoutExpired(command, 120)
            return SimpleNamespace(returncode=0 if challenge == 'mounted-webroot' else 1,
                stdout='', stderr='Address already in use' if challenge == 'busy-standalone' else '')
        raise AssertionError(command)
    monkeypatch.setattr(setup.subprocess, 'run', run)
    assert setup.obtain_letsencrypt_cert('cert.example.test','owner@example.test') == (challenge == 'mounted-webroot')
    certbot = next(c for c in calls if c[:2] == ['certbot', 'certonly'])
    if challenge == 'mounted-webroot':
        assert certbot[2:5] == ['--webroot', '-w', str(webroot)]
        assert webroot.is_dir()
    else: assert certbot[2] == '--standalone'
    assert source['State']['Running']
    assert not any(c[:2] in (['docker','stop'], ['systemctl','stop']) for c in calls)
    print('REAL_CERTBOT_COMMAND', json.dumps(certbot), 'source_running', source['State']['Running'])


def test_requested_selected_letsencrypt_failure_does_not_downgrade(tmp_path, monkeypatch):
    adoption, engine, settings, data = fixture(tmp_path, monkeypatch)
    directory = adoption.config_dir
    monkeypatch.setattr(setup, 'CONFIG_DIR', directory)
    monkeypatch.setattr(setup, 'check_existing_letsencrypt_cert', lambda domain: (False, None, None))
    monkeypatch.setattr(setup.shutil, 'which', lambda name: '/boundary/certbot')
    (directory/'ssl').mkdir()
    (directory/'ssl'/'server.crt').write_bytes(b'previous-customer-cert')
    (directory/'ssl'/'server.key').write_bytes(b'previous-customer-key')
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if command[:2] == ['docker','version']:
            return SimpleNamespace(returncode=0,stdout='linux/amd64',stderr='')
        if command[:2] == ['docker','inspect']:
            return SimpleNamespace(returncode=1,stdout='',stderr='Error: No such object: cryptolabs-proxy')
        if command[:2] == ['certbot','certonly']:
            return SimpleNamespace(returncode=1,stdout='',stderr='port80 busy')
        raise AssertionError(command)
    monkeypatch.setattr(setup.subprocess,'run',run)
    config = setup.ProxyConfig(settings['domain'], email='owner@example.test',
        use_letsencrypt=True, release_selection_dir=Path(settings['release_selection_dir']))
    ok, message = setup.setup_proxy(config)
    assert not ok and "Let's Encrypt" in message and 'running' in message
    assert (directory/'ssl'/'server.crt').read_bytes() == b'previous-customer-cert'
    assert (directory/'ssl'/'server.key').read_bytes() == b'previous-customer-key'
    assert engine.source['State']['Running']
    assert not any(c[0] == 'openssl' or c[:2] in (['docker','stop'], ['systemctl','stop']) for c in calls)
