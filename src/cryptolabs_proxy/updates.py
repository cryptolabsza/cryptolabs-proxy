"""Serialized fleet image updates executed outside the serving proxy container.

Job files contain only operation state, never container environments or Docker
error bodies. Existing containers remain available as rollback artifacts.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import time
import uuid
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from urllib.parse import quote
from urllib.request import urlopen

from .migration import DockerEngine, MigrationError, _mount_request, endpoint_configurations


SERVICES = {
    'cryptolabs-proxy': {'container': 'cryptolabs-proxy', 'port': 8080, 'image': 'ghcr.io/cryptolabsza/cryptolabs-proxy', 'self': True},
    'ipmi-monitor': {'container': 'ipmi-monitor', 'port': 5000, 'image': 'ghcr.io/cryptolabsza/ipmi-monitor'},
    'dc-overview': {'container': 'dc-overview', 'port': 5001, 'image': 'ghcr.io/cryptolabsza/dc-overview'},
    'grafana': {'container': 'grafana', 'port': 3000, 'image': 'grafana/grafana'},
    'prometheus': {'container': 'prometheus', 'port': 9090, 'image': 'prom/prometheus'},
    'vastai-exporter': {'container': 'vastai-exporter', 'port': 8622, 'image': 'ghcr.io/cryptolabsza/vastai-exporter'},
    'vast-price-manager': {'container': 'vast-price-manager', 'port': 8088, 'image': '',
                           'lifecycle_manager': 'dc-overview', 'update_supported': False},
    'runpod-exporter': {'container': 'runpod-exporter', 'port': 8623, 'image': 'ghcr.io/cryptolabsza/runpod-exporter'},
}
JOBS_DIR = Path('/data/auth/update-jobs')
CHANNEL_LABEL = 'io.cryptolabs.update.channel-image'
IMAGE_LABEL = 'io.cryptolabs.update.image-id'
ACTIVE_STATES = {'queued', 'running'}
BUILD_ENV = {'GIT_COMMIT', 'GIT_BRANCH', 'BUILD_TIME', 'APP_VERSION', 'HOSTNAME'}
# Docker 29 no longer accepts old Engine API clients.  1.45 is supported by
# Docker 29 (minimum 1.44) and retains the endpoint fields used below.
DOCKER_API_VERSION = 'v1.45'


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


def update_status(name, branch, *, engine=None):
    engine = engine or UpdateEngine()
    result = {'update_available': None, 'pinned': False}
    try:
        source = engine.inspect(SERVICES[name]['container'])
        target = target_for(name, source, branch)
        result.update({'running_image_id': source['Image'], 'target_image': target, 'pinned': target is None})
        if target:
            candidate = engine.image(target)
            result.update({'target_image_id': candidate['Id'], 'update_available': candidate['Id'] != source['Image']})
    except Exception:
        pass  # Unknown image identity is never presented as up-to-date.
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


def replace_container(engine, name, image, job_id, *, timeout=150, expected_id=None):
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
        if candidate['Id'] == source['Image']:
            return {'success': True, 'state': 'unchanged', 'image_id': source['Image'], 'message': 'Already running the selected image.'}
        request = build_update_request(source, engine.image(source['Image']), candidate)
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
    Path(directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(Path(directory) / name, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


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


def submit_job(service, branch, action, *, directory=JOBS_DIR, engine=None):
    if branch not in ('main', 'dev') or action not in ('pull', 'update'):
        raise UpdateError('Invalid update channel or action.')
    if service != 'all' and (service not in SERVICES or SERVICES[service].get('update_supported') is False):
        raise UpdateError('Service is not managed by this updater.')
    engine = engine or UpdateEngine()
    with _lock(directory, 'dispatch.lock'):
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
        job_id = uuid.uuid4().hex
        helper = 'cryptolabs-update-' + job_id
        request = helper_request(engine.inspect('cryptolabs-proxy'), Path(directory), job_id)
        job = {'id': job_id, 'helper': helper, 'service': service, 'branch': branch,
               'action': action, 'state': 'queued', 'results': {}, 'created_at': time.time()}
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


def run_job(directory, job_id, *, engine=None):
    engine = engine or UpdateEngine()
    with _lock(directory, 'operation.lock'):
        job = read_job(directory, job_id)
        if job.get('state') not in (None, 'queued'):
            return job  # A completed/interrupted operation is never replayed.
        job.update(state='running', results={})
        write_job(directory, job)
        names = list(SERVICES) if job['service'] == 'all' else [job['service']]
        names.sort(key=lambda name: name == 'cryptolabs-proxy')
        for name in names:
            if SERVICES[name].get('update_supported') is False:
                continue
            try:
                source = engine.inspect(name)
                target = target_for(name, source, job['branch'])
                if not source.get('State', {}).get('Running') or not target:
                    result = {'success': job['service'] == 'all', 'state': 'skipped',
                              'message': 'Stopped or pinned service; configuration preserved.'}
                elif not pull_target(target):
                    result = {'success': False, 'state': 'failed', 'message': 'Image pull failed; service unchanged.'}
                elif job['action'] == 'pull':
                    image = engine.image(target)
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
    status = commands.add_parser('status')
    status.add_argument('job_id')
    worker = commands.add_parser('worker')
    worker.add_argument('job_id')
    worker.add_argument('directory', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'submit':
            result = submit_job(args.service, args.branch, args.action)
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
