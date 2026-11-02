# TRACEWEAVER: file-role=native-service-recovery; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Private proof of restoration of an exact failed native service job.

No lifecycle, Flask, updater or DC imports. Observations are produced by the
installed fixed observer, never accepted from command-line or HTTP callers.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import uuid

from . import release_selection

MAX_RECEIPT = 16384
MAX_JOB = 8 * 1024 * 1024
BASELINE_ROOT = Path('/var/backups/cryptolabs/ipmi132')
HASH_KEYS = {'runtime_config_sha256', 'host_config_sha256', 'mounts_sha256',
             'network_sha256', 'schema_sha256', 'settings_sha256',
             'stable_cloud_sha256', 'stable_inventory_sha256',
             'saved_identity_sha256', 'declared_config_sha256'}
CONTINUITY_KEYS = HASH_KEYS | {'projection', 'database_device', 'database_inode',
    'saved_identity_field_count', 'stored_key_digest_matches', 'sync_enabled'}
RECEIPT_KEYS = {'schema_version', 'kind', 'service', 'job_id', 'job_sha256',
    'active_sha256', 'selection_id', 'selection_sha256', 'manifest_sha256',
    'original_container_id', 'original_image_id', 'helper_name',
    'baseline_receipt_sha256', 'continuity', 'outcome', 'verified_at'}


def hold():
    raise ValueError('native_service_recovery_required')


def require(condition):
    if not condition:
        hold()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(value):
    return sha256(encoded(value))


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def _finite_float(value):
    number = float(value)
    require(math.isfinite(number))
    return number


def strict_json(raw, maximum=MAX_RECEIPT):
    try:
        require(isinstance(raw, bytes) and 0 < len(raw) <= maximum)
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: hold(),
                          parse_float=lambda value: _finite_float(value))
    except (UnicodeError, ValueError, TypeError, RecursionError):
        hold()


def _pattern(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def validate_continuity(value):
    require(type(value) is dict and set(value) == CONTINUITY_KEYS)
    require(value['projection'] == 'ipmi-original-continuity-v1')
    for key in HASH_KEYS:
        require(_pattern(value[key], '[0-9a-f]{64}'))
    require(type(value['database_device']) is int and value['database_device'] >= 0)
    require(type(value['database_inode']) is int and value['database_inode'] > 0)
    require(type(value['saved_identity_field_count']) is int and value['saved_identity_field_count'] == 5)
    require(value['stored_key_digest_matches'] is True and value['sync_enabled'] is False)
    return value


# TRACEWEAVER: entrypoint=validate_receipt; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def validate_receipt(value):
    if isinstance(value, bytes):
        value = strict_json(value)
    require(type(value) is dict and set(value) == RECEIPT_KEYS)
    require(type(value['schema_version']) is int and value['schema_version'] == 1)
    require(value['kind'] == 'native-service-original-restored' and value['service'] == 'ipmi-monitor')
    require(value['outcome'] == 'original_restored')
    for key in ('job_sha256', 'active_sha256', 'selection_sha256', 'manifest_sha256',
                'baseline_receipt_sha256', 'original_container_id'):
        require(_pattern(value[key], '[0-9a-f]{64}'))
    require(_pattern(value['job_id'], '[0-9a-f]{32}'))
    require(_pattern(value['selection_id'], '[A-Za-z0-9][A-Za-z0-9_.-]{0,79}'))
    require(_pattern(value['original_image_id'], 'sha256:[0-9a-f]{64}'))
    require(value['helper_name'] == 'cryptolabs-update-' + value['job_id'])
    require(_pattern(value['verified_at'], r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z'))
    try:
        datetime.fromisoformat(value['verified_at'].replace('Z', '+00:00'))
    except ValueError:
        hold()
    validate_continuity(value['continuity'])
    return value


def _private(info, *, directory=False, root=False):
    require(info.st_uid == (0 if root else os.geteuid()))
    require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1)


@contextmanager
def open_existing_directory(path, *, root=False):
    """Never create stores; traverse no-follow descriptors and trusted ancestors."""
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if index == len(path.parts) - 2:
                _private(info, directory=True, root=root)
            elif root:
                require(info.st_uid == 0 and not info.st_mode & 0o022)
        yield fd
    except (OSError, KeyError, TypeError):
        hold()
    finally:
        os.close(fd)


def read_private(directory_fd, name, maximum=MAX_RECEIPT, *, root=False):
    require(type(name) is str and '/' not in name and name not in ('.', '..'))
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        _private(before, root=root)
        require(before.st_size <= maximum)
        raw = b''
        while len(raw) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(len(raw) <= maximum and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns))
        require((before.st_dev, before.st_ino) == (current.st_dev, current.st_ino))
        return raw
    finally:
        os.close(fd)


def validate_job(raw, job_id):
    require(_pattern(job_id, '[0-9a-f]{32}'))
    job = strict_json(raw, MAX_JOB)
    try:
        require(job['id'] == job_id and job['helper'] == 'cryptolabs-update-' + job_id)
        require(job['service'] == 'ipmi-monitor' and job['action'] == 'update')
        require(job['state'] == 'failed' and job['success'] is False)
        require(job['results']['ipmi-monitor']['state'] == 'recovery_required')
        original = job['sources']['ipmi-monitor']
        require(_pattern(original['container_id'], '[0-9a-f]{64}'))
        require(_pattern(original['image_id'], 'sha256:[0-9a-f]{64}'))
        stored = job['selection_snapshot']
        snapshot = release_selection.validate(stored['selection_bytes'].encode(), stored['manifest_bytes'].encode(),
            selection_id=job['selection_id'], selection_sha256=job['selection_sha256'])
        require(snapshot['manifest_sha256'] == job['manifest_sha256'])
        target = job['targets']['ipmi-monitor']
        require(type(target) is dict and target.get('owner') == 'proxy-updater')
        expected = release_selection.targets(snapshot, target['platform'])
        require(expected['ipmi-monitor'] == target)
    except (KeyError, TypeError, AttributeError, release_selection.SelectionError):
        hold()
    return job


def load_bound_job(directory_fd, job_id):
    require(_pattern(job_id, '[0-9a-f]{32}'))
    raw = read_private(directory_fd, job_id + '.json', MAX_JOB)
    active = read_private(directory_fd, 'active.json')
    pointer = strict_json(active)
    require(type(pointer) is dict and set(pointer) == {'id'} and pointer['id'] == job_id)
    validate_job(raw, job_id)
    return raw, active


@dataclass(frozen=True)
class OriginalObservation:
    container_id: str
    image_id: str
    helper_terminated: bool
    healthy: bool
    continuity: dict


def validate_original_restored(job_raw, receipt_raw, observation):
    value = validate_receipt(receipt_raw)
    job = validate_job(job_raw, value['job_id'])
    require(isinstance(observation, OriginalObservation))
    require(value['job_sha256'] == sha256(job_raw))
    for key in ('selection_id', 'selection_sha256', 'manifest_sha256'):
        require(value[key] == job[key])
    original = job['sources']['ipmi-monitor']
    require(value['original_container_id'] == original['container_id'] == observation.container_id)
    require(value['original_image_id'] == original['image_id'] == observation.image_id)
    require(observation.helper_terminated is True and observation.healthy is True)
    require(validate_continuity(observation.continuity) == value['continuity'])
    return value


def publish_original_restored(directory_fd, receipt):
    """Both caller locks must be held. No replace of a conflicting final file."""
    validate_receipt(receipt)
    _private(os.fstat(directory_fd), directory=True)
    name = 'service-recovery-' + receipt['job_id'] + '.json'
    raw = encoded(receipt) + b'\n'
    require(len(raw) <= MAX_RECEIPT)
    try:
        existing = read_private(directory_fd, name)
    except FileNotFoundError:
        existing = None
    if existing is not None:
        require(validate_receipt(existing) == receipt)
        os.fsync(directory_fd)
        require(read_private(directory_fd, name) == existing)
        return existing
    temporary = '.service-recovery-' + uuid.uuid4().hex + '.tmp'
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # link is atomic create-if-absent; replace would overwrite a competing final.
        os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=directory_fd)
        os.fsync(directory_fd)
        require(read_private(directory_fd, name) == raw)
        return raw
    finally:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass


def runtime_fingerprints(runtime):
    try:
        require(type(runtime['Config']) is dict and type(runtime['HostConfig']) is dict and
                type(runtime['Mounts']) is list and type(runtime['NetworkSettings']['Networks']) is dict)
        mounts = sorted(runtime['Mounts'], key=lambda m: (m.get('Destination', ''), m.get('Source', ''), encoded(m)))
        networks = {name: {'NetworkID': entry['NetworkID'], 'Aliases': sorted(entry.get('Aliases') or [])}
                    for name, entry in runtime['NetworkSettings']['Networks'].items()}
        return {'runtime_config_sha256': fingerprint(runtime['Config']),
                'host_config_sha256': fingerprint(runtime['HostConfig']),
                'mounts_sha256': fingerprint(mounts),
                'network_sha256': fingerprint({'mode': runtime['HostConfig'].get('NetworkMode'), 'networks': networks})}
    except (KeyError, TypeError, ValueError):
        hold()


# Static packaged read-only program. Its only entrypoint uses the fixed service
# DB/config/health paths. No caller SQL, path, shell, or source code is accepted.
DATABASE_PROGRAM = r'''
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

def _encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,
        default=lambda v: {'sqlite_blob_base64':base64.b64encode(v).decode()} if isinstance(v,bytes) else str(v)).encode()

def _fingerprint(value):
    return hashlib.sha256(_encode(value)).hexdigest()

def _need(value):
    if not value: raise ValueError('native_service_recovery_required')

def database_fingerprints(database):
    database=Path(database)
    before=database.lstat()
    _need(stat.S_ISREG(before.st_mode) and not database.is_symlink())
    deadline=time.monotonic()+5
    connection=sqlite3.connect(database.as_uri()+'?mode=ro',uri=True,timeout=5)
    connection.set_progress_handler(lambda:int(time.monotonic()>deadline),500)
    try:
        connection.execute('PRAGMA query_only=ON')
        _need(connection.execute('PRAGMA query_only').fetchone()[0]==1)
        connection.execute('BEGIN')
        schema=[];schema_size=0
        for item in connection.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'):
            schema_size+=len(_encode(item));_need(schema_size<=8*1024*1024 and time.monotonic()<=deadline)
            schema.append(item)
        tables={};size=0
        for name in ('system_settings','cloud_sync','server'):
            definition=connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,)).fetchone()
            _need(definition and definition[0] and not definition[0].lstrip().upper().startswith('CREATE VIRTUAL TABLE'))
            info=connection.execute('PRAGMA table_xinfo("'+name+'")').fetchall()
            _need(info and all(r[6]==0 for r in info))
            columns=[r[1] for r in info]
            primary=[r[1] for r in sorted(info,key=lambda r:r[5]) if r[5]]
            quote=lambda n:'"'+n.replace('"','""')+'"'
            order=','.join(map(quote,primary)) if primary else 'rowid'
            rows=[]
            for row in connection.execute('SELECT '+','.join(map(quote,columns))+' FROM "'+name+'" ORDER BY '+order):
                size+=len(_encode(row));_need(size<=8*1024*1024 and time.monotonic()<=deadline)
                rows.append(row)
            tables[name]=(columns,rows)
        settings=[dict(zip(tables['system_settings'][0],r)) for r in tables['system_settings'][1]]
        keys=('ai_link_email','ai_link_user_id','ai_link_customer_id','ai_link_linked_at','ai_link_key_digest')
        saved={r['key']:r['value'] for r in settings if r['key'] in keys}
        _need(set(saved)==set(keys) and all(type(v) is str and v for v in saved.values()))
        columns,rows=tables['cloud_sync'];_need(len(rows)==1)
        cloud=dict(zip(columns,rows[0]));credential=cloud.get('license_key')
        _need(type(credential) is str and credential and cloud.get('sync_enabled') in (0,False))
        _need(saved['ai_link_key_digest']==hashlib.sha256(credential.encode()).hexdigest())
        stable_cloud_columns=[n for n in columns if n not in ('last_sync','last_sync_status','last_sync_message','updated_at')]
        stable_cloud_rows=[tuple(dict(zip(columns,r))[n] for n in stable_cloud_columns) for r in rows]
        columns,rows=tables['server']
        stable_inventory_columns=[n for n in columns if n not in ('status','updated_at')]
        stable_inventory_rows=[tuple(dict(zip(columns,r))[n] for n in stable_inventory_columns) for r in rows]
        result={'schema_sha256':_fingerprint(schema),
            'settings_sha256':_fingerprint(sorted((r['key'],r['value']) for r in settings)),
            'stable_cloud_sha256':_fingerprint([stable_cloud_columns,stable_cloud_rows]),
            'stable_inventory_sha256':_fingerprint([stable_inventory_columns,stable_inventory_rows]),
            'saved_identity_sha256':_fingerprint(saved),'saved_identity_field_count':5,
            'stored_key_digest_matches':True,'sync_enabled':False}
    finally:
        connection.rollback();connection.close()
    after=database.lstat()
    _need((before.st_dev,before.st_ino)==(after.st_dev,after.st_ino))
    result.update(database_device=before.st_dev,database_inode=before.st_ino)
    return result

def fixed_observation():
    from urllib.request import urlopen
    database=Path('/app/data/ipmi_events.db')
    result=database_fingerprints(database)
    info=database.lstat()
    _need(result['database_device']==info.st_dev and result['database_inode']==info.st_ino)
    declared={}
    for name in ('/app/config/servers.yaml','/app/data/servers.json'):
        path=Path(name)
        try:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        except FileNotFoundError:
            declared[name]={'present':False};continue
        try:
            before=os.fstat(fd);_need(stat.S_ISREG(before.st_mode) and before.st_size<=8*1024*1024)
            raw=b''
            while len(raw)<=8*1024*1024:
                part=os.read(fd,65536)
                if not part:break
                raw+=part
            after=os.fstat(fd);current=path.lstat()
            _need(len(raw)<=8*1024*1024 and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns))
            _need((before.st_dev,before.st_ino)==(current.st_dev,current.st_ino))
            declared[name]={'present':True,'sha256':hashlib.sha256(raw).hexdigest()}
        finally:os.close(fd)
    result['declared_config_sha256']=_fingerprint(declared)
    with urlopen('http://127.0.0.1:5000/health',timeout=3) as response:
        _need(response.status==200)
        health=json.loads(response.read(16385));_need(type(health) is dict)
    _need(health.get('status')=='healthy' and health.get('checks',{}).get('database')=='ok')
    from datetime import datetime,timezone
    last=datetime.fromisoformat(health['last_collection'].replace('Z','+00:00'))
    if last.tzinfo is None:last=last.replace(tzinfo=timezone.utc)
    _need(0<=(datetime.now(timezone.utc)-last).total_seconds()<=180)
    return {'continuity':result,'last_collection':last.isoformat()}
'''
_database_namespace = {}
exec(compile(DATABASE_PROGRAM, '<packaged-read-only-recovery-projection>', 'exec'), _database_namespace)
database_fingerprints = _database_namespace['database_fingerprints']
FIXED_PROBE = DATABASE_PROGRAM + "\ntry:\n print(json.dumps(fixed_observation(),sort_keys=True))\nexcept Exception:\n raise SystemExit(1)\n"


def _timestamp(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(parsed.tzinfo is not None)
    return parsed.timestamp()


def discover_baseline(job, runtime, observed, *, deadline=None):
    """Verify one pre-job private bundle; never create or refresh a baseline."""
    original = job['sources']['ipmi-monitor']
    matches = []
    deadline = time.monotonic() + 90 if deadline is None else deadline
    with open_existing_directory(BASELINE_ROOT, root=True) as parent_fd:
        names = []
        with os.scandir(parent_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                require(len(names) <= 64)
        for name in names:
            require(time.monotonic() <= deadline)
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            require(stat.S_ISDIR(info.st_mode))
            with open_existing_directory(BASELINE_ROOT / name, root=True) as fd:
                raw = read_private(fd, 'receipt.json', MAX_JOB, root=True)
                baseline = strict_json(raw, MAX_JOB)
                require(baseline.get('status') == 'verified-bounded-selected-state-protection')
                artifacts = baseline.get('artifacts')
                require(type(artifacts) is list and 2 <= len(artifacts) <= 4)
                records = {}
                for entry in artifacts:
                    require(time.monotonic() <= deadline)
                    artifact = Path(entry['path']).name
                    require(artifact in {'runtime-config.private.json', 'selected-state.private.sqlite', 'config-0.private', 'config-1.private'} and artifact not in records)
                    maximum = 16 * 1024 * 1024 if artifact.endswith('.sqlite') else MAX_JOB
                    data = read_private(fd, artifact, maximum, root=True)
                    require(type(entry.get('bytes')) is int and len(data) == entry['bytes'] and sha256(data) == entry['sha256'])
                    records[artifact] = data
                require({'runtime-config.private.json', 'selected-state.private.sqlite'} <= records.keys())
                retained = strict_json(records['runtime-config.private.json'], MAX_JOB)
                if retained.get('Id') != original['container_id'] or retained.get('Image') != original['image_id']:
                    continue
                require(type(job['created_at']) in (int, float) and math.isfinite(job['created_at']))
                require(_timestamp(baseline['utc']) < job['created_at'])
                require(baseline['source_sql_read_only'] is True and baseline['new_full_database_snapshot'] is False)
                require(baseline['source']['device'] == observed['database_device'] and baseline['source']['inode'] == observed['database_inode'])
                require(runtime_fingerprints(retained) == runtime_fingerprints(runtime))
                expected = {key: baseline['baseline'][key] for key in ('settings_sha256', 'stable_cloud_sha256', 'stable_inventory_sha256', 'saved_identity_sha256', 'saved_identity_field_count', 'stored_key_digest_matches', 'sync_enabled')}
                # Recompute stable selected-state inputs from the actual retained
                # SQLite, whose exact bytes were verified above. No live copy.
                sqlite_path = BASELINE_ROOT / name / 'selected-state.private.sqlite'
                projected = database_fingerprints(sqlite_path)
                require(all(projected[key] == value for key, value in expected.items()))
                require(read_private(fd, 'selected-state.private.sqlite', 16 * 1024 * 1024, root=True) == records['selected-state.private.sqlite'])
                expected['schema_sha256'] = baseline['source']['schema_sha256']
                require(all(observed[key] == value for key, value in expected.items()))
                declared = {}
                require(set(baseline['declared_config']) == {'/app/config/servers.yaml', '/app/data/servers.json'})
                for index, (path, config) in enumerate(sorted(baseline['declared_config'].items())):
                    require(type(config.get('present')) is bool)
                    declared[path] = {'present': config['present']}
                    if config['present']:
                        artifact = 'config-' + str(index) + '.private'
                        require(artifact in records and config['backup']['sha256'] == sha256(records[artifact]))
                        declared[path]['sha256'] = config['backup']['sha256']
                require(fingerprint(declared) == observed['declared_config_sha256'])
                require(time.monotonic() <= deadline)
                matches.append(sha256(raw))
    require(len(matches) == 1)
    return matches[0]
