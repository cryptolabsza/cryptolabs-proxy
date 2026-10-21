"""Serialized fleet image updates executed outside the serving proxy container.

Job files contain only operation state, never container environments or Docker
error bodies. Existing containers remain available as rollback artifacts.
"""
from __future__ import annotations

import fcntl
import io
import json
import os
import re
import subprocess
import time
import tarfile
import uuid
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

from .migration import DockerEngine, MigrationError, _mount_request, endpoint_configurations
from . import release_selection as selection
from . import controller_recovery


SERVICES = {
    'cryptolabs-proxy': {'container': 'cryptolabs-proxy', 'port': 8080, 'image': 'ghcr.io/cryptolabsza/cryptolabs-proxy', 'self': True},
    'ipmi-monitor': {'container': 'ipmi-monitor', 'port': 5000, 'image': 'ghcr.io/cryptolabsza/ipmi-monitor'},
    'dc-overview': {'container': 'dc-overview', 'port': 5001, 'image': 'ghcr.io/cryptolabsza/dc-overview'},
    'grafana': {'container': 'grafana', 'port': 3000, 'image': 'grafana/grafana'},
    'prometheus': {'container': 'prometheus', 'port': 9090, 'image': 'prom/prometheus'},
    'vastai-exporter': {'container': 'vastai-exporter', 'port': 8622, 'image': 'ghcr.io/cryptolabsza/vastai-exporter'},
    'vast-price-manager': {'container': 'vast-price-manager', 'port': 8088, 'image': '',
                           'check_image': 'ghcr.io/cryptolabsza/vast-price-manager',
                           'lifecycle_manager': 'dc-overview', 'update_supported': False},
    'runpod-exporter': {'container': 'runpod-exporter', 'port': 8623, 'image': 'ghcr.io/cryptolabsza/runpod-exporter'},
}
JOBS_DIR = Path('/data/auth/update-jobs')
CHANNEL_LABEL = 'io.cryptolabs.update.channel-image'
IMAGE_LABEL = 'io.cryptolabs.update.image-id'
WATCHTOWER_LABEL = 'com.centurylinklabs.watchtower.enable'
SELECTION_DIR = selection.SELECTION_DIR
ACTIVE_STATES = {'queued', 'running'}
CHECK_TTL = 900
BUILD_ENV = {'GIT_COMMIT', 'GIT_BRANCH', 'BUILD_TIME', 'APP_VERSION', 'HOSTNAME'}
# Docker 29 no longer accepts old Engine API clients.  1.45 is supported by
# Docker 29 (minimum 1.44) and retains the endpoint fields used below.
DOCKER_API_VERSION = 'v1.45'
PROXY_REPLACEMENT_POLICY = 'host-adoption-required-v1'
PROXY_ADOPTION_MESSAGE = ('Proxy replacement requires the published host CLI: run '
    'cryptolabs-proxy configuration plan --declaration /root/proxy-declaration.json, '
    'then cryptolabs-proxy configuration adopt --declaration /root/proxy-declaration.json --plan-id <plan-id>. '
    'An old proxy runtime or source-image update helper is not repaired by updating the host package.')


def get_capabilities():
    """Additive caller contract; proxy replacement requires host authority."""
    return {'selection_contract': selection.SELECTION_CONTRACT,
            'proxy_replacement_policy': PROXY_REPLACEMENT_POLICY,
            'controller_adoption_guard': dict(controller_recovery.CAPABILITY)}


def _require_selected_updater(engine, source):
    """The selected helper executes source-image code, not the host package."""
    try:
        capabilities = engine.updater_capabilities(source['Id'])
        if not source.get('State', {}).get('Running') or not isinstance(capabilities, dict):
            raise ValueError()
        if type(capabilities.get('selection_contract')) is not int or capabilities['selection_contract'] != 1:
            raise ValueError()
        if type(capabilities.get('proxy_replacement_policy')) is not str or capabilities['proxy_replacement_policy'] != PROXY_REPLACEMENT_POLICY:
            raise ValueError()
        current = engine.inspect('cryptolabs-proxy')
        if current['Id'] != source['Id'] or current['Image'] != source['Image'] or not current.get('State', {}).get('Running'):
            raise ValueError()
    except Exception:
        raise UpdateError('Selected helper requires verified live updater capabilities. '+PROXY_ADOPTION_MESSAGE) from None


def _proxy_replacement_required(source, candidate, policy=None):
    return candidate['Id'] != source['Image'] or bool(policy and
        (source['Config'].get('Labels') or {}).get(WATCHTOWER_LABEL) != 'false')


def _proxy_hold():
    return {'success': False, 'state': 'blocked', 'reason': 'proxy_host_adoption_required',
            'message': PROXY_ADOPTION_MESSAGE}


class UpdateError(RuntimeError):
    """Public, non-sensitive updater failure."""


class UpdateBusy(UpdateError):
    def __init__(self, job):
        super().__init__('An update is already in progress.')
        self.job = job


class UpdateEngine(DockerEngine):
    def _request(self, method, path, payload=None, allowed=(200, 201, 204)):
        """Use an Engine API version accepted by the Docker 29 fleet host."""
        if not path.startswith(f'/{DOCKER_API_VERSION}/'):
            path = f'/{DOCKER_API_VERSION}{path}'
        return super()._request(method, path, payload, allowed)

    def image(self, reference):
        return json.loads(self._request('GET', f'/images/{quote(reference, safe="")}/json'))

    def updater_capabilities(self, source_id):
        """Read the shipped updater CLI in the inspected source container."""
        try:
            result = subprocess.run(['docker', 'exec', source_id, 'python3', '-m',
                'cryptolabs_proxy.updates', 'capabilities'], capture_output=True, timeout=self.timeout)
            if result.returncode or len(result.stdout) > 4096:
                raise ValueError()
            value = json.loads(result.stdout)
            if not isinstance(value, dict): raise ValueError()
            return value
        except (OSError, subprocess.SubprocessError, ValueError):
            raise UpdateError('Live updater capabilities unavailable.') from None

    def selection_bytes(self):
        return self._release_bytes('selection.json')

    def manifest_bytes(self, digest):
        if not re.fullmatch('[0-9a-f]{64}', digest):
            raise UpdateError('invalid_hash')
        return self._release_bytes('manifests/' + digest + '.json')

    def _release_bytes(self, relative):
        # Fixed public files only; do not extract archive paths or read secrets.
        raw = self._request('GET', '/containers/cryptolabs-proxy/archive?path=/etc/cryptolabs/releases/' + relative)
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            files = [m for m in archive.getmembers() if m.isfile() and m.name == relative.rsplit('/', 1)[-1]]
            if len(files) != 1 or files[0].size > selection.MAX_BYTES:
                raise UpdateError('selection_unavailable')
            return archive.extractfile(files[0]).read()


def installed_selection(directory=None, *, selection_id=None, selection_sha256=None):
    directory = Path(directory or SELECTION_DIR)
    required = os.environ.get('RELEASE_SELECTION_REQUIRED') == 'true'
    explicit = selection_id is not None or selection_sha256 is not None
    if not required and not explicit and not directory.exists():
        return None
    try:
        return selection.load(directory, selection_id=selection_id, selection_sha256=selection_sha256)
    except selection.SelectionError as error:
        raise UpdateError(str(error)) from None


def _platform(image):
    return image.get('Os', '') + '/' + image.get('Architecture', '')


def _selection_plan(snapshot, engine):
    """Every enabled proxy role must exist and be running before queuing work."""
    enabled = snapshot['selection']['components']
    sources = {}
    platform = None
    for name, entry in enabled.items():
        if entry['enabled'] and snapshot['manifest']['components'][name]['owner'] == 'proxy-updater':
            if name not in SERVICES or SERVICES[name].get('update_supported') is False:
                raise UpdateError('unsupported_proxy_role')
            try:
                source = engine.inspect(SERVICES[name]['container'])
                actual_platform = _platform(engine.image(source['Image']))
            except Exception:
                raise UpdateError('required_service_missing') from None
            if not source.get('State', {}).get('Running'):
                raise UpdateError('required_service_stopped')
            if platform and actual_platform != platform:
                raise UpdateError('platform_mismatch')
            platform = actual_platform
            sources[name] = {'container_id': source['Id'], 'image_id': source['Image']}
    if not platform:
        platform = _platform(engine.image(engine.inspect('cryptolabs-proxy')['Image']))
    try:
        targets = selection.targets(snapshot, platform)
    except selection.SelectionError as error:
        raise UpdateError(str(error)) from None
    return targets, sources


def target_for(name, source, branch):
    """Only floating, first-party channels may follow the branch selector."""
    service = SERVICES[name]
    if service.get('update_supported') is False:
        return None
    config = source.get('Config', {})
    reference = config.get('Image', '')
    labels = config.get('Labels') or {}
    if reference.startswith('sha256:') and labels.get(IMAGE_LABEL) == source.get('Image'):
        reference = labels.get(CHANNEL_LABEL, reference)
    base = service['image']
    if reference not in {base, f'{base}:latest', f'{base}:main', f'{base}:dev'}:
        return None
    tag = ('dev' if branch == 'dev' else 'latest') if base.startswith('ghcr.io/cryptolabsza/') else reference.rsplit(':', 1)[-1]
    if tag == base or tag == 'main':
        tag = 'latest'
    return f'{base}:{tag}'


def check_target(name, source, branch, engine):
    """Compare official images to a channel without granting update permission."""
    if branch not in ('main', 'dev'):
        return None
    service = SERVICES[name]
    base = service.get('check_image') or service['image']
    reference = source.get('Config', {}).get('Image', '')
    references = [reference]
    if reference.startswith('sha256:'):
        image = engine.image(source['Image'])
        references = (image.get('RepoDigests') or []) + (image.get('RepoTags') or [])
    for reference in references:
        repository = reference.split('@', 1)[0]
        if ':' in repository.rsplit('/', 1)[-1]:
            repository = repository.rsplit(':', 1)[0]
        if repository == base:
            channel = 'dev' if branch == 'dev' and base.startswith('ghcr.io/cryptolabsza/') else 'latest'
            return f'{base}:{channel}'
    return None


def _check_path(directory, name, branch):
    if name not in SERVICES or branch not in ('main', 'dev'):
        raise UpdateError('Invalid image check.')
    return Path(directory) / 'checks' / f'{name}-{branch}.json'


def _invalidate_checks(directory, names, branch):
    for name in names:
        _write_json(_check_path(directory, name, branch), {})


def _latest_status(name, branch, source, engine, directory):
    try:
        comparison = check_target(name, source, branch, engine)
        check = json.loads(_check_path(directory, name, branch).read_text())
        age = time.time() - check['checked_at']
        if comparison and check.get('target') == comparison and check.get('image_id') and 0 <= age < CHECK_TTL:
            return {'latest_status': 'latest' if check['image_id'] == source['Image'] else 'update_available',
                    'checked_at': check['checked_at']}
    except Exception:
        pass
    return {'latest_status': 'unknown'}


def update_status(name, branch, *, engine=None, selection_directory=None, directory=JOBS_DIR):
    engine = engine or UpdateEngine()
    result = {'update_available': None, 'pinned': False, 'desired': None, 'observed': None,
              'origin': None, 'reason': None, 'owner': 'proxy-updater', 'scope': 'proxy-updater',
              'suite_complete': False, 'external_owners': [], 'latest_status': 'unknown'}
    try:
        snapshot = installed_selection(selection_directory)
        source = engine.inspect(SERVICES[name]['container'])
        if snapshot:
            targets = selection.targets(snapshot, _platform(engine.image(source['Image'])))
            result['external_owners'] = sorted({t['owner'] for t in targets.values() if t['owner'] != 'proxy-updater'})
            policy = targets.get(name)
            if not policy:
                result.update(reason='disabled', state='skipped')
                return result
            target = policy.get('reference')
            result.update(origin=policy['origin'], owner=policy['owner'], selection_id=snapshot['selection_id'])
        else:
            target = target_for(name, source, branch)
        result.update(desired=target, observed=source['Image'])
        result.update({'running_image_id': source['Image'], 'target_image': target,
                       'pinned': target is None or result['origin'] == 'customer-pin'})
        if target:
            candidate = engine.image(target)
            if snapshot and (target not in candidate.get('RepoDigests', []) or _platform(candidate) != policy['platform']):
                raise UpdateError('artifact_identity_mismatch')
            result.update({'target_image_id': candidate['Id'], 'update_available': candidate['Id'] != source['Image']})
        result.update(_latest_status(name, branch, source, engine, directory))
    except (UpdateError, selection.SelectionError) as error:
        result.update(state='blocked', reason=str(error))
    except Exception:
        result['reason'] = 'identity_unavailable'
    return result


def _env(values):
    return dict(value.split('=', 1) for value in (values or []) if '=' in value)


def build_update_request(source, old_image, new_image):
    """Preserve deploy overrides while allowing target image defaults to change."""
    config = deepcopy(source['Config'])
    old_defaults, new_defaults = old_image.get('Config') or {}, new_image.get('Config') or {}
    env = _env(new_defaults.get('Env'))
    old_env = _env(old_defaults.get('Env'))
    for key, value in _env(config.get('Env')).items():
        if key not in BUILD_ENV and (key not in old_env or old_env[key] != value):
            env[key] = value
    config['Env'] = [f'{key}={value}' for key, value in env.items()]
    labels = deepcopy(new_defaults.get('Labels') or {})
    old_labels = old_defaults.get('Labels') or {}
    for key, value in (config.get('Labels') or {}).items():
        if not key.startswith('org.opencontainers.image.') and (key not in old_labels or old_labels[key] != value):
            labels[key] = value
    config['Labels'] = labels
    for key in ('Cmd', 'Entrypoint', 'User', 'WorkingDir', 'Healthcheck', 'StopSignal', 'Shell', 'ExposedPorts', 'Volumes'):
        if key in old_defaults and config.get(key) == old_defaults[key]:
            if key in new_defaults:
                config[key] = deepcopy(new_defaults[key])
            else:
                config.pop(key, None)
    if config.get('Hostname') in (source.get('Id'), source.get('Id', '')[:12]):
        config.pop('Hostname', None)
    config['Image'] = new_image['Id']
    host = deepcopy(source['HostConfig'])
    if host.get('AutoRemove') or host.get('VolumesFrom'):
        raise UpdateError('Automatic removal or inherited volumes require a managed update.')
    mounts = deepcopy(host.get('Mounts') or [])
    targets = {mount.get('Target') for mount in mounts}
    targets.update((host.get('Tmpfs') or {}).keys())
    for binding in host.get('Binds') or []:
        parts = binding.split(':')
        if len(parts) < 2:
            raise UpdateError('Cannot preserve an ambiguous mount.')
        targets.add(parts[1])
    for mount in source.get('Mounts', []):
        if mount['Destination'] not in targets:
            mounts.append(_mount_request(mount))
    host['Mounts'] = mounts
    endpoints = endpoint_configurations(source)
    generated_aliases = {source.get('Id'), source.get('Id', '')[:12]}
    for endpoint in endpoints.values():
        if endpoint.get('Aliases'):
            endpoint['Aliases'] = [alias for alias in endpoint['Aliases'] if alias not in generated_aliases]
    return {'Config': config, 'HostConfig': host, 'NetworkingConfig': {'EndpointsConfig': endpoints}}


def _probe(source, name):
    """Fallback application probe for containers without Docker healthchecks."""
    service = SERVICES[name]
    addresses = [endpoint.get('IPAddress') for endpoint in source.get('NetworkSettings', {}).get('Networks', {}).values()]
    if source.get('HostConfig', {}).get('NetworkMode') == 'host':
        addresses = ['127.0.0.1']
    paths = {'cryptolabs-proxy': '/api/health', 'dc-overview': '/api/health',
             'ipmi-monitor': '/health', 'grafana': '/api/health', 'prometheus': '/-/ready'}
    path = paths.get(name, '/metrics')
    if name == 'prometheus':
        for argument in source.get('Config', {}).get('Cmd') or []:
            if argument.startswith('--web.route-prefix='):
                path = argument.split('=', 1)[1].rstrip('/') + '/-/ready'
    for address in addresses:
        if address:
            try:
                with urlopen(f'http://{address}:{service["port"]}{path}', timeout=3) as response:
                    if response.status == 200:
                        return True
            except Exception:
                pass
    return False


def wait_ready(engine, name, image_id, timeout=150):
    deadline = time.monotonic() + timeout
    while True:
        source = engine.inspect(name)
        state = source.get('State', {})
        health = state.get('Health', {}).get('Status')
        if source.get('Image') != image_id or not state.get('Running') or health == 'unhealthy':
            return False
        if health == 'healthy' or (health is None and _probe(source, name)):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(1)


def replace_container(engine, name, image, job_id, *, timeout=150, expected_id=None, policy=None, expected_image=None):
    """Swap without destroying the previous runtime; prove recovery on failure."""
    backup = f'{name}.rollback-{job_id}'
    detached = []
    started_stop = renamed = created = False
    source = None
    try:
        source = engine.inspect(name)
        if expected_id and source['Id'] != expected_id:
            raise UpdateError('Container changed during update preparation.')
        if not source.get('State', {}).get('Running'):
            raise UpdateError('Service is stopped; use its installer to start it.')
        candidate = engine.image(image)
        if expected_image and candidate['Id'] != expected_image:
            raise UpdateError('Candidate changed during update preparation.')
        if policy and (image not in candidate.get('RepoDigests', []) or _platform(candidate) != policy['platform']):
            raise UpdateError('Candidate digest or platform verification failed.')
        if candidate['Id'] == source['Image'] and (not policy or (source['Config'].get('Labels') or {}).get(WATCHTOWER_LABEL) == 'false'):
            return {'success': True, 'state': 'unchanged', 'image_id': source['Image'], 'message': 'Already running the selected image.'}
        if name == 'cryptolabs-proxy': return _proxy_hold()
        request = build_update_request(source, engine.image(source['Image']), candidate)
        if policy:
            request['Config']['Labels'].update({WATCHTOWER_LABEL: 'false',
                'io.cryptolabs.update.origin': policy['origin'], 'io.cryptolabs.update.reference': image})
        if not image.startswith('sha256:'):
            request['Config']['Labels'].update({CHANNEL_LABEL: image, IMAGE_LABEL: candidate['Id']})
        endpoints = request['NetworkingConfig']['EndpointsConfig']
        started_stop = True
        engine.stop(name)
        for network in endpoints:
            engine.disconnect(name, network)
            detached.append(network)
        engine.rename(name, backup)
        renamed = True
        engine.create(name, request)
        created = True
        engine.start(name)
        if not wait_ready(engine, name, candidate['Id'], timeout):
            raise UpdateError('Replacement failed application health or image verification.')
        return {'success': True, 'state': 'completed', 'image_id': candidate['Id'],
                'rollback_container': backup, 'message': 'Updated and health verified.'}
    except Exception as error:
        message = str(error) if isinstance(error, UpdateError) else 'Container update failed.'
        if not started_stop:
            return {'success': False, 'state': 'failed', 'message': message}
        try:
            if created:
                engine.remove(name, ignore_missing=True)
            if renamed:
                engine.rename(backup, name)
            for network in detached:
                engine.connect(name, network, endpoints[network])
            engine.start(name)
            if not wait_ready(engine, name, source['Image'], timeout):
                raise UpdateError('Original service did not recover.')
            return {'success': False, 'state': 'rolled_back', 'message': message + ' Original service restored and health verified.'}
        except Exception:
            return {'success': False, 'state': 'recovery_required', 'message': message + ' Automatic recovery was not verified; operator recovery required.', 'rollback_container': backup if renamed else name}


def _job_path(directory, job_id):
    if not re.fullmatch('[0-9a-f]{32}', job_id):
        raise UpdateError('Invalid update job identifier.')
    return Path(directory) / f'{job_id}.json'


def _write_json(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp-' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def write_job(directory, job):
    _write_json(_job_path(directory, job['id']), job)


def read_job(directory, job_id):
    try:
        return json.loads(_job_path(directory, job_id).read_text())
    except FileNotFoundError:
        raise UpdateError('Update job not found.') from None


def job_status(job_id, *, directory=JOBS_DIR, engine=None):
    job = read_job(directory, job_id)
    if job.get('state') in ACTIVE_STATES:
        engine = engine or UpdateEngine()
        try:
            running = engine.inspect(job['helper'])['State']['Running']
        except MigrationError as error:
            if not str(error).endswith('HTTP 404'):
                return job
            running = False
        except Exception:
            return job
        if not running:
            job = read_job(directory, job_id)
            if job.get('state') in ACTIVE_STATES:
                job.update(state='interrupted', success=False,
                           message='Update helper stopped before completion. Inspect services before retrying.')
                write_job(directory, job)
    return job


@contextmanager
def _lock(directory, name):
    try:
        with controller_recovery.updater_lock(directory, name):
            yield
    except controller_recovery.RecoveryError:
        raise UpdateError('controller_recovery_required') from None


def helper_request(source, directory, job_id):
    """The helper uses the current immutable proxy image, outside its PID space."""
    parent = next((mount for mount in sorted(source.get('Mounts', []), key=lambda item: len(item['Destination']), reverse=True)
                   if str(directory).startswith(mount['Destination'].rstrip('/') + '/')), None)
    if not parent or not parent.get('RW', True):
        raise UpdateError('Updater needs a writable persistent /data/auth mount.')
    mount = _mount_request(parent)
    return {
        'Config': {'Image': source['Image'], 'Entrypoint': ['python3'],
                   'Cmd': ['-m', 'cryptolabs_proxy.updates', 'worker', job_id, str(directory)],
                   'Env': ['PYTHONPATH=/app/src'], 'Healthcheck': {'Test': ['NONE']},
                   'Labels': {'io.cryptolabs.update.worker': job_id, 'com.centurylinklabs.watchtower.enable': 'false'}},
        'HostConfig': {'NetworkMode': 'host', 'RestartPolicy': {'Name': 'no'},
                       'Mounts': [mount, {'Type': 'bind', 'Source': '/var/run/docker.sock', 'Target': '/var/run/docker.sock'}],
                       'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '1'}}},
        'NetworkingConfig': {},
    }


def submit_job(service, branch, action, *, directory=JOBS_DIR, engine=None,
               selection_id=None, selection_sha256=None, selection_directory=None):
    if branch not in ('main', 'dev') or action not in ('pull', 'update'):
        raise UpdateError('Invalid update channel or action.')
    if service != 'all' and (service not in SERVICES or (action == 'update' and SERVICES[service].get('update_supported') is False)):
        raise UpdateError('Service is not managed by this updater.')
    engine = engine or UpdateEngine()
    snapshot = installed_selection(selection_directory, selection_id=selection_id, selection_sha256=selection_sha256)
    if snapshot and branch == 'dev':
        raise UpdateError('selection_channel_conflict')
    targets, sources = _selection_plan(snapshot, engine) if snapshot else ({}, {})
    if snapshot and service != 'all' and (service not in targets or targets[service]['owner'] != 'proxy-updater'):
        raise UpdateError('service_not_selected')
    with _lock(directory, 'dispatch.lock'):
        try:
            controller_recovery.require_clear(directory)
        except controller_recovery.RecoveryError:
            raise UpdateError('controller_recovery_required') from None
        active = Path(directory) / 'active.json'
        if active.exists():
            previous = read_job(directory, json.loads(active.read_text())['id'])
            if previous.get('state') in ACTIVE_STATES:
                try:
                    running = engine.inspect(previous['helper'])['State']['Running']
                except MigrationError as error:
                    if not str(error).endswith('HTTP 404'):
                        # An inaccessible Engine is not proof that a worker stopped.
                        raise UpdateBusy(previous) from None
                    running = False
                except Exception:
                    # An inaccessible Engine is not proof that a worker stopped.
                    raise UpdateBusy(previous) from None
                if running:
                    raise UpdateBusy(previous)
                previous.update(state='interrupted', success=False,
                                message='Update helper exited before recording completion. Inspect service status before retrying.')
                write_job(directory, previous)
        source = engine.inspect('cryptolabs-proxy')
        if action == 'update' and service in ('all', 'cryptolabs-proxy'):
            proxy_target = targets.get('cryptolabs-proxy') if snapshot else None
            if snapshot and proxy_target and proxy_target['owner'] == 'proxy-updater':
                try: noop = not _proxy_replacement_required(source, engine.image(proxy_target['reference']), proxy_target)
                except Exception: noop = False
                if not noop: raise UpdateError(PROXY_ADOPTION_MESSAGE)
            elif not snapshot and source.get('State', {}).get('Running') and target_for('cryptolabs-proxy',source,branch):
                # Floating channels cannot prove a future old helper's pull is a
                # no-op. A host dispatcher must not launch unpatched source code.
                raise UpdateError(PROXY_ADOPTION_MESSAGE)
        if snapshot:
            _require_selected_updater(engine, source)
        job_id = uuid.uuid4().hex
        helper = 'cryptolabs-update-' + job_id
        request = helper_request(source, Path(directory), job_id)
        if action == 'pull':
            _invalidate_checks(directory, SERVICES if service == 'all' else [service], branch)
        job = {'id': job_id, 'helper': helper, 'service': service, 'branch': branch,
               'action': action, 'state': 'queued', 'results': {}, 'created_at': time.time(),
               'scope': 'proxy-updater', 'suite_complete': False, 'external_owners': []}
        if snapshot:
            job.update(selection_id=snapshot['selection_id'], selection_sha256=snapshot['selection_sha256'],
                manifest_sha256=snapshot['manifest_sha256'], selection_snapshot=snapshot, targets=targets,
                sources=sources, scope='proxy-updater', suite_complete=False,
                external_owners=sorted({t['owner'] for t in targets.values() if t['owner'] != 'proxy-updater'}))
        write_job(directory, job)
        _write_json(active, {'id': job_id})
        try:
            engine.create(helper, request)
            engine.start(helper)
        except Exception:
            job.update(state='failed', success=False, message='Could not launch update helper.')
            write_job(directory, job)
            raise UpdateError(job['message']) from None
        return job


def pull_target(target):
    try:
        result = subprocess.run(['docker', 'pull', target], capture_output=True, timeout=300)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _run_selected_job(directory, job, engine):
    """Stage all exact artifacts and clone requests before stopping any service."""
    try:
        stored = job['selection_snapshot']
        snapshot = selection.validate(stored['selection_bytes'].encode(), stored['manifest_bytes'].encode(),
            selection_id=job['selection_id'], selection_sha256=job['selection_sha256'])
        if selection.sha256(engine.selection_bytes()) != job['selection_sha256']:
            raise UpdateError('selection_changed')
        if selection.sha256(engine.manifest_bytes(job['manifest_sha256'])) != job['manifest_sha256']:
            raise UpdateError('manifest_changed')
        targets, sources = _selection_plan(snapshot, engine)
        if targets != job['targets'] or sources != job['sources']:
            raise UpdateError('runtime_changed')
        names = [name for name, target in targets.items() if target['owner'] == 'proxy-updater'
                 and job['service'] in ('all', name)]
        names.sort(key=lambda name: name == 'cryptolabs-proxy')
        staged = {}
        for name in names:
            target = targets[name]
            if not pull_target(target['reference']):
                raise UpdateError('image_pull_failed')
            image = engine.image(target['reference'])
            if target['reference'] not in image.get('RepoDigests', []) or _platform(image) != target['platform']:
                raise UpdateError('artifact_identity_mismatch')
            source = engine.inspect(SERVICES[name]['container'])
            build_update_request(source, engine.image(source['Image']), image)
            if job['action'] != 'pull' and name == 'cryptolabs-proxy' and _proxy_replacement_required(source,image,target):
                raise UpdateError('proxy_host_adoption_required')
            staged[name] = image['Id']
        checked = {}
        if job['action'] == 'pull':
            for name in targets:
                if name not in SERVICES or job['service'] not in ('all', name):
                    continue
                try:
                    source = engine.inspect(SERVICES[name]['container'])
                    comparison = check_target(name, source, job['branch'], engine)
                    if comparison and source.get('State', {}).get('Running') and pull_target(comparison):
                        checked[name] = {'target': comparison, 'image_id': engine.image(comparison)['Id'],
                                         'checked_at': time.time()}
                except Exception:
                    pass  # Optional channel discovery cannot block a verified selected artifact.
        # A policy edit or container replacement during pulls invalidates the
        # complete plan before the first stop, rather than allowing partial work.
        if selection.sha256(engine.selection_bytes()) != job['selection_sha256'] or selection.sha256(engine.manifest_bytes(job['manifest_sha256'])) != job['manifest_sha256'] or _selection_plan(snapshot, engine)[1] != sources:
            raise UpdateError('selection_or_runtime_changed')
        for name, check in checked.items():
            _write_json(_check_path(directory, name, job['branch']), check)
    except Exception as error:
        reason = str(error) if isinstance(error, (UpdateError, selection.SelectionError)) else 'preflight_unavailable'
        job.update(state='blocked', success=False, reason=reason, finished_at=time.time(),
                   message=PROXY_ADOPTION_MESSAGE if reason=='proxy_host_adoption_required' else reason,
                   results={name: {'success': False, 'state': 'blocked', 'reason': reason,
                      'message': (PROXY_ADOPTION_MESSAGE if name=='cryptolabs-proxy' else 'Bundle held because proxy requires host adoption.') if reason=='proxy_host_adoption_required' else reason,
                      'owner': target['owner'], 'origin': target['origin'], 'desired': target.get('reference', target.get('sha256')),
                      'observed': None} for name, target in job.get('targets', {}).items()})
        write_job(directory, job)
        return job
    for name, target in targets.items():
        if target['owner'] != 'proxy-updater':
            job['results'][name] = {'success': False, 'state': 'blocked', 'owner': target['owner'],
                'desired': target.get('reference', target.get('sha256')), 'observed': None,
                'origin': target['origin'], 'reason': 'external_owner_required'}
    for name in names:
        target = targets[name]
        if job['action'] == 'pull':
            result = {'success': True, 'state': 'checked', 'image_id': staged[name],
                      'update_available': staged[name] != sources[name]['image_id']}
        else:
            result = replace_container(engine, name, target['reference'], job['id'], policy=target,
                expected_id=sources[name]['container_id'], expected_image=staged[name])
        result.update(owner=target['owner'], origin=target['origin'], desired=target['reference'],
                      observed=result.get('image_id'), reason=None if result['success'] else 'replacement_failed')
        job['results'][name] = result
        write_job(directory, job)
        if not result['success']:
            break
    owned = [r for r in job['results'].values() if r['owner'] == 'proxy-updater']
    success = all(r['success'] for r in owned)
    job.update(state='completed' if success else 'failed', success=success, finished_at=time.time())
    write_job(directory, job)
    return job


def run_job(directory, job_id, *, engine=None):
    engine = engine or UpdateEngine()
    with _lock(directory, 'operation.lock'):
        job = read_job(directory, job_id)
        if job.get('state') not in (None, 'queued'):
            return job  # A completed/interrupted operation is never replayed.
        try:
            controller_recovery.require_clear(directory)
        except controller_recovery.RecoveryError:
            job.update(state='blocked', success=False, reason='controller_recovery_required',
                       finished_at=time.time(), results={})
            write_job(directory, job)
            return job
        job.update(state='running', results={})
        write_job(directory, job)
        if job['action'] == 'pull':
            _invalidate_checks(directory, SERVICES if job['service'] == 'all' else [job['service']], job['branch'])
        if 'selection_snapshot' in job:
            return _run_selected_job(directory, job, engine)
        if hasattr(engine, 'selection_bytes'):
            try:
                current_policy = engine.selection_bytes()
            except MigrationError as error:
                # A absent public policy file permits legacy mode only when
                # the serving proxy has no recorded baseline authority.
                if not str(error).endswith('HTTP 404'):
                    current_policy = b'unknown'
                else:
                    labels = engine.inspect('cryptolabs-proxy').get('Config', {}).get('Labels') or {}
                    current_policy = b'required' if labels.get('io.cryptolabs.update.origin') else None
            except Exception:
                current_policy = b'unknown'
            if current_policy is not None:
                job.update(state='blocked', success=False, reason='selection_snapshot_required',
                           scope='proxy-updater', suite_complete=False)
                write_job(directory, job)
                return job
        names = list(SERVICES) if job['service'] == 'all' else [job['service']]
        names.sort(key=lambda name: name == 'cryptolabs-proxy')
        if job['action'] != 'pull' and 'cryptolabs-proxy' in names:
            try:
                proxy = engine.inspect('cryptolabs-proxy')
                target = target_for('cryptolabs-proxy',proxy,job['branch'])
                if proxy.get('State',{}).get('Running') and target:
                    if not pull_target(target): raise UpdateError('image_pull_failed')
                    if _proxy_replacement_required(proxy,engine.image(target)):
                        raise UpdateError('proxy_host_adoption_required')
            except MigrationError as error:
                if not str(error).endswith('HTTP 404'):
                    job.update(state='blocked',success=False,reason='proxy_preflight_unavailable',finished_at=time.time())
                    write_job(directory,job); return job
            except Exception as error:
                reason=str(error) if isinstance(error,UpdateError) else 'proxy_preflight_unavailable'
                job.update(state='blocked',success=False,reason=reason,
                    message=PROXY_ADOPTION_MESSAGE if reason=='proxy_host_adoption_required' else reason,
                    finished_at=time.time())
                write_job(directory,job); return job
        for name in names:
            if job['action'] == 'update' and SERVICES[name].get('update_supported') is False:
                continue
            try:
                source = engine.inspect(name)
                target = (check_target(name, source, job['branch'], engine) if job['action'] == 'pull'
                          else target_for(name, source, job['branch']))
                if target and source.get('State', {}).get('Running') and job['action'] == 'update':
                    _invalidate_checks(directory, [name], job['branch'])
                if not source.get('State', {}).get('Running') or not target:
                    result = {'success': job['service'] == 'all', 'state': 'skipped',
                              'message': 'Stopped or pinned service; configuration preserved.'}
                elif not pull_target(target):
                    result = {'success': False, 'state': 'failed', 'message': 'Image pull failed; service unchanged.'}
                else:
                    image = engine.image(target)
                    _write_json(_check_path(directory, name, job['branch']), {
                        'target': target, 'image_id': image['Id'], 'checked_at': time.time(),
                    })
                    if job['action'] == 'pull':
                        result = {'success': True, 'state': 'checked', 'image_id': image['Id'],
                                  'update_available': image['Id'] != source['Image'], 'message': 'Image checked; running service unchanged.'}
                    else:
                        result = replace_container(engine, name, target, job_id, expected_id=source['Id'])
            except Exception as error:
                missing = isinstance(error, MigrationError) and str(error).endswith('HTTP 404')
                if missing and job['service'] == 'all':
                    result = {'success': True, 'state': 'skipped', 'message': 'Service is not installed.'}
                else:
                    result = {'success': False, 'state': 'failed', 'message': 'Could not inspect or prepare service; no update started.'}
            job['results'][name] = result
            write_job(directory, job)
            if result.get('state') == 'recovery_required':
                break
        success = all(result['success'] for result in job['results'].values())
        job.update(state='completed' if success else 'failed', success=success, finished_at=time.time())
        write_job(directory, job)
        return job


def main(argv=None):
    """Supported JSON interface for host fleet CLI clients."""
    import argparse
    parser = argparse.ArgumentParser(description='Fleet image updater')
    commands = parser.add_subparsers(dest='command', required=True)
    submit = commands.add_parser('submit')
    submit.add_argument('--branch', choices=('main', 'dev'), default='main')
    submit.add_argument('--service', default='all', choices=['all', *SERVICES])
    submit.add_argument('--action', choices=('update', 'pull'), default='update')
    submit.add_argument('--selection-id')
    submit.add_argument('--selection-sha256')
    commands.add_parser('capabilities')
    status = commands.add_parser('status')
    status.add_argument('job_id')
    worker = commands.add_parser('worker')
    worker.add_argument('job_id')
    worker.add_argument('directory', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'submit':
            result = submit_job(args.service, args.branch, args.action,
                selection_id=args.selection_id, selection_sha256=args.selection_sha256)
        elif args.command == 'capabilities':
            result = get_capabilities()
        elif args.command == 'status':
            result = job_status(args.job_id)
        else:
            result = run_job(args.directory, args.job_id)
        print(json.dumps(result))
        return 0
    except UpdateBusy as error:
        print(json.dumps({'error': str(error), 'job': error.job}))
        return 2
    except UpdateError as error:
        print(json.dumps({'error': str(error)}))
        return 1
    except Exception:
        print(json.dumps({'error': 'Updater unavailable; no completion confirmed.'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
