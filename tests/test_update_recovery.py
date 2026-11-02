# TRACEWEAVER: file-role=verification; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
# TRACEWEAVER: verifies=VER-FLEETUPDATE-001; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001
"""Approved shared receipt contract; synthetic private filesystem only.

Initial RED is missing-module evidence, not proof that the future rejection,
durability or host bootstrap behavior has been exercised.
"""
import importlib
import json
import os
from copy import deepcopy

import pytest


def receipt():
    """Exact versioned shape; deliberately synthetic IDs and fingerprints."""
    continuity = {
        'projection': 'ipmi-original-continuity-v1',
        'database_device': 1, 'database_inode': 2,
        'saved_identity_field_count': 5,
        'stored_key_digest_matches': True, 'sync_enabled': False,
    }
    for key in ('runtime_config', 'host_config', 'mounts', 'network', 'schema',
                'settings', 'stable_cloud', 'stable_inventory', 'saved_identity',
                'declared_config'):
        continuity[key + '_sha256'] = 'b' * 64
    return {
        'schema_version': 1, 'kind': 'native-service-original-restored',
        'service': 'ipmi-monitor', 'job_id': 'a' * 32,
        'job_sha256': 'c' * 64, 'active_sha256': 'd' * 64,
        'selection_id': 'synthetic-scoped-selection',
        'selection_sha256': 'e' * 64, 'manifest_sha256': 'f' * 64,
        'original_container_id': '1' * 64, 'original_image_id': 'sha256:' + '2' * 64,
        'helper_name': 'cryptolabs-update-' + 'a' * 32,
        'baseline_receipt_sha256': '3' * 64,
        'continuity': continuity, 'outcome': 'original_restored',
        'verified_at': '2026-11-02T08:00:00Z',
    }


def test_shared_receipt_schema_and_private_atomic_publication(tmp_path, monkeypatch):
    recovery = importlib.import_module('cryptolabs_proxy.update_recovery')
    for name in ('validate_receipt', 'load_bound_job', 'validate_original_restored',
                 'publish_original_restored'):
        assert callable(getattr(recovery, name))
    value = receipt()
    recovery.validate_receipt(value)
    for change in ('extra-key', 'bool-version', 'foreign-helper', 'false-continuity'):
        bad = deepcopy(value)
        if change == 'extra-key': bad['force'] = True
        if change == 'bool-version': bad['schema_version'] = True
        if change == 'foreign-helper': bad['helper_name'] = 'foreign-helper'
        if change == 'false-continuity': bad['continuity']['stored_key_digest_matches'] = False
        with pytest.raises(ValueError):
            recovery.validate_receipt(bad)

    tmp_path.chmod(0o700)
    # The publisher must not create, rewrite or remove historical job/pointer files.
    job = tmp_path / ('a' * 32 + '.json')
    active = tmp_path / 'active.json'
    job.write_bytes(b'{"synthetic":"historical failed job"}\n')
    active.write_bytes(b'{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n')
    job.chmod(0o600); active.chmod(0o600)
    before = (job.read_bytes(), active.read_bytes())
    final = tmp_path / ('service-recovery-' + value['job_id'] + '.json')
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        original_fsync = os.fsync
        def interrupted_fsync(fd):
            raise OSError('synthetic disk interruption before durable file')
        with monkeypatch.context() as patch:
            patch.setattr(os, 'fsync', interrupted_fsync)
            with pytest.raises(OSError):
                recovery.publish_original_restored(descriptor, value)
        assert not final.exists()
        assert (job.read_bytes(), active.read_bytes()) == before
        calls = []
        def record_fsync(fd):
            calls.append(os.fstat(fd).st_mode)
            return original_fsync(fd)
        with monkeypatch.context() as patch:
            patch.setattr(os, 'fsync', record_fsync)
            recovery.publish_original_restored(descriptor, value)
        stored = final.read_bytes()
        assert json.loads(stored) == value
        assert final.stat().st_mode & 0o777 == 0o600
        assert final.stat().st_nlink == 1
        assert len(calls) >= 2  # file and parent directory durability
        recovery.publish_original_restored(descriptor, value)
        assert final.read_bytes() == stored
        assert (job.read_bytes(), active.read_bytes()) == before
    finally:
        os.close(descriptor)


def historical_snapshot(snapshot):
    from cryptolabs_proxy import release_selection
    manifest=deepcopy(snapshot['manifest'])
    manifest['components']['ipmi-monitor']={'release':'synthetic-legacy','owner':'proxy-updater',
        'artifacts':{'linux/amd64':{'kind':'oci','reference':'ghcr.io/cryptolabsza/ipmi-monitor@sha256:'+'c'*64}}}
    manifest_raw=json.dumps(manifest).encode()
    selected=deepcopy(snapshot['selection'])
    selected['components']['ipmi-monitor']={'enabled':True,'origin':'baseline'}
    selected['manifest_sha256']=release_selection.sha256(manifest_raw)
    return release_selection.validate(json.dumps(selected).encode(),manifest_raw)


@pytest.fixture
def bound(tmp_path):
    from tests.test_release_selection import selection_files
    from cryptolabs_proxy import release_selection
    directory, digest = selection_files(tmp_path)
    snapshot = historical_snapshot(release_selection.load(directory))
    digest = snapshot['selection_sha256']
    value = receipt()
    value.update(selection_id=snapshot['selection_id'], selection_sha256=digest,
                 manifest_sha256=snapshot['manifest_sha256'])
    job = {'id': value['job_id'], 'helper': value['helper_name'], 'service': 'ipmi-monitor',
           'branch': 'main', 'action': 'update', 'state': 'failed', 'success': False,
           'results': {'ipmi-monitor': {'state': 'recovery_required', 'success': False}},
           'sources': {'ipmi-monitor': {'container_id': value['original_container_id'],
                                      'image_id': value['original_image_id']}},
           'selection_id': value['selection_id'], 'selection_sha256': value['selection_sha256'],
           'manifest_sha256': value['manifest_sha256'], 'selection_snapshot': snapshot,
           'targets': release_selection.targets(snapshot,'linux/amd64')}
    raw = json.dumps(job).encode()
    value['job_sha256'] = __import__('hashlib').sha256(raw).hexdigest()
    return job, raw, value


def test_shared_job_binding_and_observation_are_not_clearance_tokens(bound):
    from cryptolabs_proxy import update_recovery as recovery
    job, raw, value = bound
    observation = recovery.OriginalObservation(
        container_id=value['original_container_id'], image_id=value['original_image_id'],
        helper_terminated=True, healthy=True, continuity=value['continuity'])
    encoded = json.dumps(value).encode()
    assert recovery.validate_original_restored(raw, encoded, observation) == value
    for changes in ({'healthy': False}, {'helper_terminated': False},
                    {'container_id': '9' * 64}, {'continuity': {}}):
        from dataclasses import replace
        with pytest.raises(ValueError):
            recovery.validate_original_restored(raw, encoded, replace(observation, **changes))
    with pytest.raises(ValueError):
        recovery.validate_original_restored(raw + b' ', encoded, observation)
    with pytest.raises(ValueError):
        recovery.validate_receipt(encoded[:-1] + b',"job_id":"' + b'a'*32 + b'"}')
    for bad in (dict(value, verified_at='tomorrow'), dict(value, job_sha256=True)):
        with pytest.raises(ValueError): recovery.validate_receipt(bad)


def test_existing_receipt_conflict_and_untrusted_records_fail_closed(tmp_path, bound):
    from cryptolabs_proxy import update_recovery as recovery
    job, raw, value = bound
    tmp_path.chmod(0o700)
    active = json.dumps({'id': job['id']}).encode()
    for name, data in ((job['id']+'.json', raw), ('active.json', active)):
        (tmp_path/name).write_bytes(data); (tmp_path/name).chmod(0o600)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert recovery.load_bound_job(fd, job['id']) == (raw, active)
        recovery.publish_original_restored(fd, value)
        with pytest.raises(ValueError):
            recovery.publish_original_restored(fd, dict(value, baseline_receipt_sha256='4'*64))
        (tmp_path/(job['id']+'.json')).chmod(0o644)
        with pytest.raises(ValueError): recovery.load_bound_job(fd, job['id'])
    finally: os.close(fd)


def test_runtime_fingerprint_retains_duplicate_mounts_and_ignores_only_volatile_network():
    from cryptolabs_proxy import update_recovery as recovery
    runtime = {'Config': {'Env': ['PRIVATE=synthetic']}, 'HostConfig': {'NetworkMode': 'private'},
        'Mounts': [{'Destination': '/data', 'Source': '/synthetic', 'RW': True}],
        'NetworkSettings': {'Networks': {'private': {'NetworkID': 'x', 'Aliases': ['b','a'], 'EndpointID': 'old', 'IPAddress':'192.0.2.1'}}}}
    original = recovery.runtime_fingerprints(runtime)
    changed = deepcopy(runtime)
    changed['NetworkSettings']['Networks']['private'].update(EndpointID='new', IPAddress='192.0.2.2', Aliases=['a','b'])
    assert recovery.runtime_fingerprints(changed) == original
    changed['Mounts'] *= 2
    assert recovery.runtime_fingerprints(changed)['mounts_sha256'] != original['mounts_sha256']
    changed = deepcopy(runtime); changed['Config']['Env'].append('NEW=drift')
    assert recovery.runtime_fingerprints(changed)['runtime_config_sha256'] != original['runtime_config_sha256']


def make_database(path):
    import sqlite3
    connection = sqlite3.connect(path)
    connection.executescript('CREATE TABLE system_settings (key TEXT PRIMARY KEY,value TEXT);'
        'CREATE TABLE cloud_sync (id INTEGER PRIMARY KEY,license_key TEXT,sync_enabled INTEGER,last_sync TEXT);'
        'CREATE TABLE server (id INTEGER PRIMARY KEY,name TEXT,status TEXT,updated_at TEXT);')
    digest = __import__('hashlib').sha256(b'synthetic-private-key').hexdigest()
    for key, value in zip(('ai_link_email','ai_link_user_id','ai_link_customer_id','ai_link_linked_at','ai_link_key_digest'),
                          ('synthetic@example.test','user','customer','2020-01-01',digest)):
        connection.execute('INSERT INTO system_settings VALUES (?,?)',(key,value))
    connection.execute('INSERT INTO cloud_sync VALUES (1,?,0,?)',('synthetic-private-key','old'))
    connection.execute('INSERT INTO server VALUES (1,?,?,?)',('synthetic-server','up','old'))
    connection.commit(); connection.close()


def test_actual_sqlite_projection_ignores_volatile_fields_but_preserves_identity(tmp_path):
    from cryptolabs_proxy import update_recovery as recovery
    import sqlite3
    db = tmp_path/'selected.sqlite'; make_database(db)
    before = recovery.database_fingerprints(db)
    connection=sqlite3.connect(db)
    connection.execute("UPDATE cloud_sync SET last_sync='new'")
    connection.execute("UPDATE server SET status='down',updated_at='new'")
    connection.commit()
    assert recovery.database_fingerprints(db) == before
    connection.execute("UPDATE server SET name='drift'");connection.commit()
    assert recovery.database_fingerprints(db)['stable_inventory_sha256'] != before['stable_inventory_sha256']
    connection.execute("UPDATE cloud_sync SET license_key='changed'");connection.commit();connection.close()
    with pytest.raises(ValueError): recovery.database_fingerprints(db)


@pytest.fixture
def retained_bundle(tmp_path, monkeypatch):
    from cryptolabs_proxy import update_recovery as recovery
    from datetime import datetime,timezone
    live=tmp_path/'live.sqlite';make_database(live)
    root=tmp_path/'baselines';root.mkdir(mode=0o700)
    operation=root/'synthetic-pre-job';operation.mkdir(mode=0o700)
    runtime={'Id':'1'*64,'Image':'sha256:'+'2'*64,'Config':{'Env':['PRIVATE=synthetic']},
        'HostConfig':{'NetworkMode':'private'},'Mounts':[{'Destination':'/app/data','Source':'/synthetic','RW':True}],
        'NetworkSettings':{'Networks':{'private':{'NetworkID':'3'*64,'Aliases':['ipmi-monitor']}}}}
    state=recovery.database_fingerprints(live)
    continuity=dict(state,**recovery.runtime_fingerprints(runtime),projection='ipmi-original-continuity-v1',
        database_device=live.stat().st_dev,database_inode=live.stat().st_ino,
        declared_config_sha256=recovery.fingerprint({'/app/config/servers.yaml':{'present':True,'sha256':recovery.sha256(b'synthetic')},
                                                    '/app/data/servers.json':{'present':False}}))
    artifacts=[]
    for name,raw in (('runtime-config.private.json',json.dumps(runtime).encode()),
                     ('selected-state.private.sqlite',live.read_bytes()),('config-0.private',b'synthetic')):
        path=operation/name;path.write_bytes(raw);path.chmod(0o600)
        artifacts.append({'path':str(path),'bytes':len(raw),'sha256':recovery.sha256(raw)})
    value={'status':'verified-bounded-selected-state-protection','utc':'2020-01-01T00:00:00Z',
        'source_sql_read_only':True,'new_full_database_snapshot':False,
        'source':{'device':live.stat().st_dev,'inode':live.stat().st_ino,'schema_sha256':state['schema_sha256']},
        'baseline':state,'artifacts':artifacts,'declared_config':{
            '/app/config/servers.yaml':{'present':True,'backup':{'sha256':recovery.sha256(b'synthetic')}},
            '/app/data/servers.json':{'present':False}}}
    raw=json.dumps(value).encode();(operation/'receipt.json').write_bytes(raw);(operation/'receipt.json').chmod(0o600)
    job={'sources':{'ipmi-monitor':{'container_id':runtime['Id'],'image_id':runtime['Image']}},
         'created_at':datetime(2020,1,2,tzinfo=timezone.utc).timestamp()}
    monkeypatch.setattr(recovery,'BASELINE_ROOT',root)
    private=recovery._private
    monkeypatch.setattr(recovery,'_private',lambda info,**kw:private(info,directory=kw.get('directory',False)))
    opened=recovery.open_existing_directory
    monkeypatch.setattr(recovery,'open_existing_directory',lambda path,**kw:opened(path))
    return job,runtime,continuity,operation,raw


def test_retained_bundle_uses_actual_private_artifacts_not_new_baseline(retained_bundle):
    from cryptolabs_proxy import update_recovery as recovery
    job,runtime,continuity,operation,raw=retained_bundle
    before={p.name:p.read_bytes() for p in operation.iterdir()}
    assert recovery.discover_baseline(job,runtime,continuity)==recovery.sha256(raw)
    assert {p.name:p.read_bytes() for p in operation.iterdir()}==before
    (operation/'config-0.private').write_bytes(b'corrupted')
    with pytest.raises(ValueError):recovery.discover_baseline(job,runtime,continuity)


@pytest.mark.parametrize('drift',['runtime','database','identity','multiple','post-job'])
def test_retained_bundle_rejects_mismatch_ambiguity_and_post_job_inputs(retained_bundle,drift):
    from cryptolabs_proxy import update_recovery as recovery
    job,runtime,continuity,operation,raw=retained_bundle
    if drift=='runtime':runtime['Config']['Env'].append('DRIFT=1')
    if drift=='database':continuity['database_inode']+=1
    if drift=='identity':continuity['saved_identity_sha256']='8'*64
    if drift=='multiple':
        import shutil
        shutil.copytree(operation,operation.parent/'another-pre-job')
    if drift=='post-job':job['created_at']=1
    with pytest.raises(ValueError):recovery.discover_baseline(job,runtime,continuity)


def test_directory_fsync_failure_never_acknowledges_and_retry_durably_rechecks(tmp_path,monkeypatch):
    from cryptolabs_proxy import update_recovery as recovery
    tmp_path.chmod(0o700)
    fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    fsync=os.fsync;calls=[]
    def fail_parent(descriptor):
        calls.append(descriptor)
        if descriptor==fd:raise OSError('synthetic directory fsync failure')
        return fsync(descriptor)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(os,'fsync',fail_parent)
            with pytest.raises(OSError):recovery.publish_original_restored(fd,receipt())
        saved=(tmp_path/('service-recovery-'+'a'*32+'.json')).read_bytes()
        calls.clear()
        with monkeypatch.context() as patch:
            patch.setattr(os,'fsync',lambda descriptor:(calls.append(descriptor),fsync(descriptor))[1])
            recovery.publish_original_restored(fd,receipt())
        assert fd in calls
        assert (tmp_path/('service-recovery-'+'a'*32+'.json')).read_bytes()==saved
    finally:os.close(fd)


@pytest.mark.parametrize('wrong',['absent','platform','reference'])
def test_historical_target_is_bound_to_embedded_selection(bound,wrong):
    from cryptolabs_proxy import update_recovery as recovery
    job,raw,value=bound
    if wrong=='absent':job['targets'].pop('ipmi-monitor')
    if wrong=='platform':job['targets']['ipmi-monitor']['platform']='linux/unknown'
    if wrong=='reference':job['targets']['ipmi-monitor']['reference']='ghcr.io/cryptolabsza/ipmi-monitor@sha256:'+'9'*64
    with pytest.raises(ValueError):recovery.validate_job(json.dumps(job).encode(),job['id'])
