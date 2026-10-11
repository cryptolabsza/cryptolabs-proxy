"""Pure, bounded contract1 consumer; approval remains with the host operator.

Hashes identify exact imported bytes, not publisher trust. Never interpret data
as executable policy. This module performs no Docker operations or writes.
"""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

SELECTION_CONTRACT = 1
SELECTION_DIR = Path('/etc/cryptolabs/releases')
MAX_BYTES = 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}')
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,79}')
PLATFORMS = {'linux/amd64', 'linux/arm64', 'any'}
# Product data may select these artifacts; it cannot add a command or owner.
COMPONENTS = {
    'cryptolabs-proxy': ('proxy-updater', 'ghcr.io/cryptolabsza/cryptolabs-proxy'),
    'dc-overview': ('proxy-updater', 'ghcr.io/cryptolabsza/dc-overview'),
    'ipmi-monitor': ('proxy-updater', 'ghcr.io/cryptolabsza/ipmi-monitor'),
    'grafana': ('proxy-updater', 'grafana/grafana'),
    'prometheus': ('proxy-updater', 'prom/prometheus'),
    'vastai-exporter': ('proxy-updater', 'ghcr.io/cryptolabsza/vastai-exporter'),
    'runpod-exporter': ('proxy-updater', 'ghcr.io/cryptolabsza/runpod-exporter'),
    'vast-price-manager': ('dc-vpm', 'ghcr.io/cryptolabsza/vast-price-manager'),
    'dc-overview-cli': ('host-cli', 'cryptolabsza/dc-overview'),
    'dc-exporter': ('dc-worker', 'cryptolabsza/dc-exporter-releases'),
    'node-exporter': ('dc-worker', 'prometheus/node_exporter'),
    'dc-watchdog-agent': ('dc-worker', 'cryptolabsza/dc-watchdog'),
}


class SelectionError(ValueError):
    """Non-sensitive policy error, safe to return to API callers."""


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _fields(value, required, optional=()):
    if not isinstance(value, dict) or set(value) - set(required) - set(optional) or not set(required) <= set(value):
        raise SelectionError('invalid_schema')


def _identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise SelectionError('invalid_identifier')


def _hash(value):
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise SelectionError('invalid_hash')


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise SelectionError('duplicate_field')
            result[key] = value
        return result
    try:
        if not isinstance(data, bytes) or len(data) > MAX_BYTES:
            raise SelectionError('invalid_bytes')
        return json.loads(data, object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        raise SelectionError('invalid_json') from None


def validate(selection_bytes, manifest_bytes, *, selection_id=None, selection_sha256=None):
    """Validate exact bytes, all declared artifacts and every enabled role."""
    selection = _json(selection_bytes)
    manifest = _json(manifest_bytes)
    _fields(selection, ('schema_version', 'selection_id', 'manifest_sha256', 'components'))
    _fields(manifest, ('schema_version', 'selection_contract', 'baseline_id', 'components'))
    if type(selection['schema_version']) is not int or selection['schema_version'] != 1 or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1 or type(manifest['selection_contract']) is not int or manifest['selection_contract'] != 1:
        raise SelectionError('unsupported_contract')
    _identifier(selection['selection_id']); _identifier(manifest['baseline_id'])
    _hash(selection['manifest_sha256'])
    if sha256(manifest_bytes) != selection['manifest_sha256']:
        raise SelectionError('manifest_hash_mismatch')
    if (selection_id is None) != (selection_sha256 is None):
        raise SelectionError('selection_pair_required')
    if selection_id is not None:
        _identifier(selection_id); _hash(selection_sha256)
        if selection_id != selection['selection_id'] or selection_sha256 != sha256(selection_bytes):
            raise SelectionError('selection_changed')
    if not isinstance(manifest['components'], dict) or not isinstance(selection['components'], dict) or not selection['components']:
        raise SelectionError('invalid_components')
    for name, component in manifest['components'].items():
        if name not in COMPONENTS:
            raise SelectionError('unknown_component')
        _fields(component, ('release', 'owner', 'artifacts'))
        _identifier(component['release'])
        owner, repository = COMPONENTS[name]
        if component['owner'] != owner:
            raise SelectionError('owner_mismatch')
        if not isinstance(component['artifacts'], dict) or not component['artifacts']:
            raise SelectionError('missing_artifact')
        for platform, artifact in component['artifacts'].items():
            if platform not in PLATFORMS:
                raise SelectionError('unsupported_platform')
            if owner in ('proxy-updater', 'dc-vpm'):
                _fields(artifact, ('kind', 'reference'))
                if platform == 'any' or artifact['kind'] != 'oci' or not isinstance(artifact['reference'], str) or not re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', artifact['reference']):
                    raise SelectionError('invalid_oci_artifact')
            else:
                _fields(artifact, ('kind', 'url', 'sha256'))
                _hash(artifact['sha256'])
                kind = 'wheel' if owner == 'host-cli' else 'binary'
                if artifact['kind'] != kind or (owner == 'host-cli' and platform != 'any') or (owner == 'dc-worker' and platform == 'any'):
                    raise SelectionError('invalid_artifact_kind')
                if not isinstance(artifact['url'], str):
                    raise SelectionError('invalid_artifact_url')
                url = urlsplit(artifact['url'])
                prefix = '/' + repository + '/releases/download/'
                suffix = url.path[len(prefix):].split('/') if url.path.startswith(prefix) else []
                if url.scheme != 'https' or url.netloc != 'github.com' or url.query or url.fragment or len(suffix) != 2 or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+-]*', p) or p in ('latest', 'main', 'dev') for p in suffix):
                    raise SelectionError('invalid_artifact_url')
    for name, entry in selection['components'].items():
        if name not in manifest['components']:
            raise SelectionError('missing_component')
        _fields(entry, ('origin', 'enabled'), ('pin',))
        if type(entry['enabled']) is not bool or entry['origin'] not in ('baseline', 'customer-pin', 'unmanaged'):
            raise SelectionError('invalid_origin')
        if entry['origin'] == 'customer-pin' and not isinstance(entry.get('pin'), str):
            raise SelectionError('pin_required')
        if entry['origin'] != 'customer-pin' and 'pin' in entry:
            raise SelectionError('unexpected_pin')
        if entry['enabled'] and entry['origin'] == 'unmanaged':
            raise SelectionError('unmanaged_required')
        if entry['origin'] == 'customer-pin':
            candidates = [a.get('reference', a.get('sha256')) for a in manifest['components'][name]['artifacts'].values()]
            if entry['pin'] not in candidates:
                raise SelectionError('pin_conflict')
    return {'selection': selection, 'manifest': manifest,
            'selection_id': selection['selection_id'], 'selection_sha256': sha256(selection_bytes),
            'manifest_sha256': selection['manifest_sha256'], 'selection_bytes': selection_bytes.decode('utf-8'),
            'manifest_bytes': manifest_bytes.decode('utf-8')}


def load(directory=SELECTION_DIR, **kwargs):
    try:
        selection_bytes = (Path(directory) / 'selection.json').read_bytes()
        selection = _json(selection_bytes)
        digest = selection.get('manifest_sha256') if isinstance(selection, dict) else None
        _hash(digest)
        manifest_bytes = (Path(directory) / 'manifests' / (digest + '.json')).read_bytes()
        return validate(selection_bytes, manifest_bytes, **kwargs)
    except OSError:
        raise SelectionError('selection_unavailable') from None


def targets(snapshot, platform):
    """Resolve immutable artifact dictionaries, preserving external owners."""
    if platform not in PLATFORMS - {'any'}:
        raise SelectionError('unsupported_platform')
    result = {}
    for name, entry in snapshot['selection']['components'].items():
        if not entry['enabled']:
            continue
        component = snapshot['manifest']['components'][name]
        selected_platform = 'any' if component['owner'] == 'host-cli' else platform
        artifact = component['artifacts'].get(selected_platform)
        if artifact is None:
            raise SelectionError('missing_platform')
        identity = artifact.get('reference', artifact.get('sha256'))
        if entry['origin'] == 'customer-pin' and entry['pin'] != identity:
            raise SelectionError('pin_conflict')
        result[name] = {'release': component['release'], 'owner': component['owner'], 'platform': selected_platform,
                        'origin': entry['origin'], **artifact}
    return result
