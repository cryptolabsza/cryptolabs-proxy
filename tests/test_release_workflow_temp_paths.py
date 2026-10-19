"""Execute selected immutable release recipes with offline package boundaries."""
import concurrent.futures
import glob
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/publish.yml'
publisher_spec = importlib.util.spec_from_file_location('publisher_fixtures', ROOT / 'tests/test_release_publication.py')
publisher_fixtures = importlib.util.module_from_spec(publisher_spec)
publisher_spec.loader.exec_module(publisher_fixtures)
Publisher = publisher_fixtures.Publisher


def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def selected_job(name):
    reference = workflow()['jobs'][name]['uses']
    match = re.fullmatch(r'cryptolabsza/cryptolabs-proxy/(\.github/workflows/[\w-]+\.yml)@([a-f0-9]{40})', reference)
    assert match is not None
    raw = subprocess.check_output(['git', 'show', match[2] + ':' + match[1]], cwd=ROOT)
    jobs = yaml.safe_load(raw)['jobs']
    assert len(jobs) == 1
    return next(iter(jobs.values()))


def step(job, name):
    return next(s for s in selected_job(job)['steps'] if s.get('name') == name)


def action(job, prefix):
    return next(s for s in selected_job(job)['steps'] if s.get('uses', '').startswith(prefix))


def shell(script, env, cwd):
    return subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script], env=env, cwd=cwd,
                          capture_output=True, text=True, timeout=15)


def initialize(env, env_file, cwd):
    env = {**env, 'GITHUB_ENV': str(env_file)}
    allocators = [s for s in selected_job('cpu-build')['steps'] if 'mktemp -d' in s.get('run', '')]
    assert len(allocators) == 1
    result = shell(allocators[0]['run'], env, cwd)
    assert result.returncode == 0, result.stderr
    for line in env_file.read_text().splitlines():
        key, value = line.split('=', 1)
        env[key] = value
    return env


@pytest.fixture
def boundary(tmp_path):
    workspace = tmp_path / 'checkout'; workspace.mkdir()
    source = (ROOT / 'pyproject.toml').read_text()
    project = re.search(r'^name = "([^"]+)"', source, re.M).group(1)
    version = re.search(r'^version = "([^"]+)"', source, re.M).group(1)
    (workspace / 'pyproject.toml').write_text(f'[project]\nname="{project}"\nversion="{version}"\n')
    subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
    subprocess.run(['git', '-C', str(workspace), 'add', 'pyproject.toml'], check=True)
    subprocess.run(['git', '-C', str(workspace), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                    '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture'], check=True)
    sha = subprocess.check_output(['git', '-C', str(workspace), 'rev-parse', 'HEAD']).decode().strip()
    context = {'project': project, 'version': version, 'tag': 'v' + version,
               'repository': 'cryptolabsza/' + project, 'source_sha': sha}
    context_file = tmp_path / 'context.json'; context_file.write_text(json.dumps(context))
    bins = tmp_path / 'bin'; bins.mkdir()
    bridge = bins / 'python'
    bridge.write_text('#!' + sys.executable + '\n' + '''import io,json,os,pathlib,sys,tarfile,zipfile
args=sys.argv[1:];assert args[:2]==['-m','build']
context=json.loads(pathlib.Path(os.environ['FIXTURE_CONTEXT']).read_text())
source=pathlib.Path(args[2]);assert (source/'pyproject.toml').is_file()
assert os.environ['GIT_WORK_TREE']==str(source)
assert os.environ['GITHUB_REF_NAME']==context['tag']
dist=pathlib.Path(args[args.index('--outdir')+1]);stem=context['project'].replace('-','_')+'-'+context['version']
metadata=('Metadata-Version: 2.1\\nName: '+context['project']+'\\nVersion: '+context['version']+'\\n').encode()
with zipfile.ZipFile(dist/(stem+'-py3-none-any.whl'),'w') as archive:
    archive.writestr(stem+'.dist-info/METADATA',metadata)
with tarfile.open(dist/(stem+'.tar.gz'),'w:gz') as archive:
    info=tarfile.TarInfo(stem+'/PKG-INFO');info.size=len(metadata);archive.addfile(info,io.BytesIO(metadata))
''')
    bridge.chmod(0o755)
    temp = tmp_path / 'shared runner temp'; temp.mkdir()
    env = {'PATH': str(bins) + os.pathsep + os.environ['PATH'], 'RUNNER_TEMP': str(temp),
           'GITHUB_WORKSPACE': str(workspace), 'RELEASE_TAG': context['tag'], 'FIXTURE_CONTEXT': str(context_file)}
    return tmp_path, workspace, temp, env, context


def build(boundary, number):
    base, workspace, _, env, _ = boundary
    env = initialize(env, base / f'build-{number}.env', workspace)
    for name in ['Build once from the checked-out revision', 'Checksum built Python distributions']:
        command = step('cpu-build', name)['run'].replace('${{ env.RELEASE_JOB_DIR }}', env['RELEASE_JOB_DIR'])
        result = shell(command, env, workspace)
        assert result.returncode == 0, result.stderr
    pattern = action('cpu-build', 'actions/upload-artifact')['with']['path'].replace('${{ env.RELEASE_JOB_DIR }}', env['RELEASE_JOB_DIR'])
    paths = [Path(p) for p in glob.glob(pattern)]
    dist = Path(env['RELEASE_JOB_DIR']) / 'release-dist'
    bundle = {str(p.relative_to(dist)): p.read_bytes() for p in paths}
    assert len(bundle) == 3 and 'SHA256SUMS' in bundle
    sums = ''.join(hashlib.sha256(bundle[name]).hexdigest() + '  ' + name + '\n'
                   for name in sorted(bundle) if name != 'SHA256SUMS')
    assert bundle['SHA256SUMS'] == sums.encode()
    assert action('cpu-build', 'actions/upload-artifact')['with']['if-no-files-found'] == 'error'
    return env, Path(env['RELEASE_JOB_DIR']), bundle


@pytest.fixture
def selected_publisher(tmp_path, monkeypatch):
    checkout = action('publish', 'actions/checkout')['with']
    assert re.fullmatch('[a-f0-9]{40}', checkout['ref'])
    assert checkout['repository'] == 'cryptolabsza/cryptolabs-proxy'
    code = tmp_path / 'selected-publisher'; code.mkdir()
    for path in checkout['sparse-checkout'].splitlines():
        if not path:continue
        assert path.startswith('/.github/publisher/')
        raw = subprocess.check_output(['git', 'show', checkout['ref'] + ':' + path.lstrip('/')], cwd=ROOT)
        (code / Path(path).name).write_bytes(raw)
    for name in ['verify_artifact', 'package_publisher', 'policy', 'release_runtime']:
        spec = importlib.util.spec_from_file_location(name, code / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
    runtime = sys.modules['release_runtime']
    runtime.original_verify = runtime.v.verify
    monkeypatch.setattr(runtime.v.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100*1024**3))
    assert runtime.v.OUTPUT == Path('verified-artifact')
    assert sys.modules['policy'].POLICY.recipe_ref == workflow()['jobs']['cpu-build']['uses']
    return runtime


def verify_in_fresh_publish_job(boundary, bundle, number, runtime, monkeypatch, client):
    base, _, _, _, context = boundary
    workspace = base / f'publisher-job-{number}'; workspace.mkdir()
    monkeypatch.chdir(workspace)
    event = {'inputs': {'release_tag': context['tag'], 'version': context['version']}}
    eventfile = workspace / 'event.json'; eventfile.write_text(json.dumps(event))
    for key, value in {'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_SHA': context['source_sha'],
                       'GITHUB_EVENT_PATH': str(eventfile), 'GITHUB_REPOSITORY': context['repository']}.items():
        monkeypatch.setenv(key, value)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as output:
        for name, raw in sorted(bundle.items()):output.writestr(name, raw)
    data = archive.getvalue()
    proof = {'repository': context['repository'], 'head_sha': context['source_sha'], 'branch': 'main',
             'run_id': 123, 'run_attempt': 1, 'artifact_id': 456, 'size_in_bytes': len(data),
             'artifact_digest': 'sha256:' + hashlib.sha256(data).hexdigest()}
    monkeypatch.setattr(runtime, 'Client', lambda *args: client)
    monkeypatch.setattr(client, 'source_project', lambda sha: {'name': context['project'], 'version': context['version']}, raising=False)
    monkeypatch.setattr(runtime.v, 'verify_metadata', lambda *args, **kwargs: dict(proof))
    # Run the selected extractor and atomic output path. Only external producer
    # metadata and ZIP download are fixtures in this path-focused test.
    def downloaded(path, destination, maximum):
        assert path.endswith('/actions/artifacts/456/zip') and len(data) <= maximum
        destination.write_bytes(data)
    monkeypatch.setattr(runtime.v, 'verify', lambda policy, *ids: runtime.original_verify(policy, *ids, download=downloaded))
    assert runtime.main(['verify', '123', '1', '456']) == 0
    output = workspace / runtime.v.OUTPUT
    saved = json.loads((output / 'publication-plan.json').read_text())
    assert saved['ids'] == [123, 1, 456]
    assert saved['plan']['source_sha'] == context['source_sha']
    assert {p.name: p.read_bytes() for p in (output / 'files').iterdir()} == bundle
    return workspace, output, saved


def test_stale_shared_build_paths_are_preserved(boundary):
    _, _, temp, _, _ = boundary
    for name in ['release-source', 'release-dist', 'release-bundle']:
        (temp / name).mkdir(); (temp / name / 'unrelated').write_bytes(b'preserve stale bytes')
    (temp / 'build-receipt.json').write_bytes(b'stale unrelated receipt')
    (temp / 'verified-publication.json').write_bytes(b'stale unrelated verification')
    old = {str(p.relative_to(temp)): p.read_bytes() for p in temp.rglob('*') if p.is_file()}
    _, owned, bundle = build(boundary, 1)
    assert owned.parent == temp and owned != temp and bundle
    assert all((temp / rel).read_bytes() == raw for rel, raw in old.items())


def test_concurrent_build_jobs_use_distinct_owned_directories(boundary):
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda number: build(boundary, number), [1, 2]))
    assert results[0][1] != results[1][1]
    assert all(root.parent == boundary[2] for _, root, _ in results)


def test_retained_bundle_recovers_exact_bytes_on_new_publish_job(boundary, selected_publisher, monkeypatch):
    _, _, temp, _, context = boundary
    (temp / 'verified-publication.json').write_bytes(b'unrelated stale receipt')
    _, _, bundle = build(boundary, 1)
    runtime = selected_publisher; client = Publisher(context); upload = client.upload_github
    first_workspace, first, saved = verify_in_fresh_publish_job(boundary, bundle, 1, runtime, monkeypatch, client)
    client.upload_github = lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic github upload failure'))
    assert runtime.main(['upload']) == 1
    assert client.files and not (first / 'publication-receipt.json').exists()
    client.upload_github = upload
    second_workspace, second, recovered = verify_in_fresh_publish_job(boundary, bundle, 2, runtime, monkeypatch, client)
    assert first_workspace != second_workspace and first.parent != second.parent
    assert recovered['plan'] == saved['plan']
    assert runtime.main(['upload']) == 0
    receipt = json.loads((second / 'publication-receipt.json').read_text())
    assert receipt['status'] == 'verified' and receipt['source_sha'] == context['source_sha']
    assert [name for name, _ in client.writes].count('pypi') == 1
    assert {p.name: p.read_bytes() for p in (second / 'files').iterdir()} == bundle
    for item in receipt['artifacts']:
        assert item['sha256'] == hashlib.sha256(bundle[item['filename']]).hexdigest()
    assert (temp / 'verified-publication.json').read_bytes() == b'unrelated stale receipt'


def test_unique_verified_receipt_is_retained_after_post_verification_failure(boundary, selected_publisher, monkeypatch):
    _, _, bundle = build(boundary, 1)
    runtime = selected_publisher; client = Publisher(boundary[4])
    _, output, _ = verify_in_fresh_publish_job(boundary, bundle, 1, runtime, monkeypatch, client)
    def failed_stdout(*args, **kwargs):
        if kwargs.get('file') is None:raise OSError('synthetic stdout failure after receipt write')
    monkeypatch.setattr(runtime, 'print', failed_stdout, raising=False)
    assert runtime.main(['upload']) == 1
    receipt = json.loads((output / 'publication-receipt.json').read_text())
    assert receipt['status'] == 'verified'
    for item in receipt['artifacts']:
        assert item['sha256'] == hashlib.sha256(bundle[item['filename']]).hexdigest()
    retain = action('publish', 'actions/upload-artifact')
    assert retain.get('if') == 'always()'
    assert retain['with']['if-no-files-found'] == 'error'
    assert Path(retain['with']['path']) == runtime.v.OUTPUT / 'publication-receipt.json'
    assert not any(s.get('continue-on-error') for s in selected_job('publish')['steps'])


def test_allocator_failure_does_not_write_a_false_job_path(boundary):
    base, workspace, _, env, _ = boundary
    allocator = next(s for s in selected_job('cpu-build')['steps'] if 'mktemp -d' in s.get('run', ''))
    bad = base / 'bad'; bad.mkdir(); executable = bad / 'mktemp'; executable.write_text('#!/bin/sh\nexit 1\n'); executable.chmod(0o755)
    env_file = base / 'bad.env'; env = {**env, 'PATH': str(bad) + os.pathsep + env['PATH'], 'GITHUB_ENV': str(env_file)}
    result = shell(allocator['run'], env, workspace)
    assert result.returncode != 0
    assert not env_file.exists() or not env_file.read_bytes()


def test_receipt_retention_does_not_read_an_unallocated_root_path(boundary, selected_publisher, monkeypatch):
    runtime = selected_publisher
    retain = action('publish', 'actions/upload-artifact')
    path = Path(retain['with']['path'])
    assert path == Path('verified-artifact/publication-receipt.json')
    assert not path.is_absolute() and '${{' not in str(path) and '..' not in path.parts
    assert retain.get('if') == 'always()'
    workspace = boundary[0] / 'refused-publisher-job'; workspace.mkdir(); monkeypatch.chdir(workspace)
    runtime.v.OUTPUT.mkdir(); stale = runtime.v.OUTPUT / 'publication-receipt.json'; stale.write_bytes(b'unrelated')
    def unexpected(*args, **kwargs):raise AssertionError('existing output must refuse before remote reads')
    with pytest.raises(runtime.v.Refused, match='verified output already exists'):
        runtime.original_verify(sys.modules['policy'].POLICY, 123, 1, 456, api=unexpected, download=unexpected)
    assert stale.read_bytes() == b'unrelated'
