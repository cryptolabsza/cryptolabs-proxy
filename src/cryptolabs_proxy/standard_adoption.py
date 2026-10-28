# TRACEWEAVER: file-role=fleet-release-implementation; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Explicit standard configuration adoption, without Nginx passthrough.

Public manifests contain identities and declarative fields only. Inspected
credentials and persistent auth archives stay in private recovery storage.
"""
from copy import deepcopy
from contextlib import contextmanager, ExitStack
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import tarfile
import time
from urllib.parse import quote, urlsplit

from .config import get_jinja_env, validate_host_forward_groups, render_host_forward_groups, validate_acme_challenge, render_acme_challenge, validate_hostname_policy, validate_http_policy, render_policy_healthcheck, policy_healthcheck
from .custom_config import render_managed_vpm_config
from .migration import (DockerEngine, CustomConfigMigrator, MigrationError, SwitchController,
                        build_recreate_request, endpoint_configurations, wait_for_container_healthy,
                        wait_for_proxy_ready, PROXY_READY_TIMEOUT, _snapshot_registry_files,
                        _write_registry_backup, _restore_registry_files)
from .release_selection import load, targets, sha256, SelectionError, validate as validate_selection
from .services import ServiceRegistry, DEFAULT_SERVICES


class AdoptionError(MigrationError):
    """Safe public failure; never contains inspected environment/config values."""


NAME = re.compile(r'[a-z][a-z0-9-]{0,62}')
DOMAIN = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?')
PATH = re.compile(r'/(?:[A-Za-z0-9_-]+/)+')
AUTH_OVERLAY = '/app/src/cryptolabs_proxy/auth.py'
MAX_CONFIG = 1024 * 1024
TOKENS = re.compile(r'''\s+|\#[^\n]*|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|[{};]|[^\s{};'"]+''')


OWNED_AUTH_FILES = {'users.json','settings.json','exporter-mgmt-token','watchdog_api_key','watchdog_verified'}


def auth_state(data, *, allow_active_jobs=False):
    """Validate account authority; hash files and protect unrelated active jobs."""
    from .identity import validate_identity_users
    owned={}; external={}
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive:
                p=Path(member.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='auth' or not(member.isfile() or member.isdir()): raise AdoptionError('auth_snapshot_unsupported')
                if member.isdir(): continue
                content=archive.extractfile(member).read(); name='/'.join(p.parts[1:])
                # PairStore creates this empty mutex on reads. Preserve it on
                # disk without treating first-read presence as account state.
                if name=='account_link.lock' and not content: continue
                if name=='users.json':
                    try: validate_identity_users(json.loads(content))
                    except (ValueError,UnicodeError): raise AdoptionError('auth_identity_store_invalid; operator recovery required') from None
                if name.startswith('update-jobs/') and name.endswith('.json'):
                    try: job=json.loads(content)
                    except ValueError: raise AdoptionError('auth_update_job_uninspectable') from None
                    if not allow_active_jobs and isinstance(job,dict) and job.get('state') in ('queued','running'): raise AdoptionError('active_update_job_requires_quiescence')
                (owned if name in OWNED_AUTH_FILES else external)[name]=sha256(content)
    except tarfile.TarError: raise AdoptionError('auth_snapshot_invalid') from None
    if 'users.json' not in owned: raise AdoptionError('auth_identity_store_missing')
    return {'owned':owned,'external':external}


def owned_auth_archive(data):
    """Only product-owned root files are restored; unrelated state is untouched."""
    auth_state(data); output=io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data)) as source, tarfile.open(fileobj=output,mode='w') as target:
        for member in source:
            if member.isfile() and member.name in {'auth/'+name for name in OWNED_AUTH_FILES}:
                target.addfile(member,source.extractfile(member))
    return output.getvalue()

def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def _durable_private(path, content):
    """Atomic, fsynced owner journal writes; never expose inspected values."""
    import os as filesystem
    import uuid
    path=Path(path)
    temporary=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    descriptor=filesystem.open(temporary,filesystem.O_WRONLY|filesystem.O_CREAT|filesystem.O_EXCL|filesystem.O_NOFOLLOW,0o600)
    try:
        with filesystem.fdopen(descriptor,'wb') as stream:
            stream.write(content); stream.flush(); filesystem.fsync(stream.fileno())
        filesystem.replace(temporary,path)
        descriptor=filesystem.open(path.parent,filesystem.O_RDONLY|filesystem.O_DIRECTORY)
        try: filesystem.fsync(descriptor)
        finally: filesystem.close(descriptor)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass


def _restoration_evidence(engine, source, plan, expected, config_dir):
    serving=engine.inspect('cryptolabs-proxy')
    sanitized=[e for e in source['Config'].get('Env',[]) if not e.startswith('FLEET_ADMIN_PASS=')]+['FLEET_ADMIN_PASS=']
    if (not serving.get('State',{}).get('Running') or serving['Image']!=source['Image']
            or serving['Config'].get('Env',[])!=sanitized
            or sha256(engine.read_config('cryptolabs-proxy'))!=plan['config_sha256']
            or auth_state(engine.archive_auth('cryptolabs-proxy'),allow_active_jobs=True)!=expected):
        raise AdoptionError('source_recovery_unverified')
    registry=_snapshot_registry_files(ServiceRegistry(config_dir))
    registry_sha=sha256(_canonical({p.name:sha256(data) if data is not None else None for p,data in registry.items()}))
    if registry_sha!=plan['registry_sha256']: raise AdoptionError('source_registry_recovery_unverified')
    return {'schema_version':1,'plan_id':plan['plan_id'],'runtime_sha256':_runtime_identity(serving),
        'container_id':serving['Id'],'image_id':serving['Image'],'config_sha256':plan['config_sha256'],
        'selection_sha256':plan['selection_sha256'],'registry_sha256':registry_sha,
        'auth_state_sha256':sha256(_canonical(expected)),'startup_verified':True,'health_verified':True}


def parse_nginx(data):
    """Bounded structural comparison; unknown directives are never executed."""
    if not isinstance(data,bytes) or len(data)>MAX_CONFIG:
        raise AdoptionError('active_config_unavailable')
    try: text=data.decode('utf-8')
    except UnicodeError: raise AdoptionError('active_config_invalid') from None
    tokens=[]; offset=0
    for m in TOKENS.finditer(text):
        if m.start()!=offset: raise AdoptionError('active_config_invalid')
        offset=m.end(); token=m.group()
        if not token.isspace() and not token.startswith('#'): tokens.append(token)
    if offset!=len(text): raise AdoptionError('active_config_invalid')
    root=[]; stack=[root]; words=[]
    for token in tokens:
        if token=='{':
            if not words or len(stack)>128: raise AdoptionError('active_config_invalid')
            children=[]; stack[-1].append([words,children]); stack.append(children); words=[]
        elif token=='}':
            if words or len(stack)==1: raise AdoptionError('active_config_invalid')
            stack.pop()
        elif token==';':
            if not words: raise AdoptionError('active_config_invalid')
            stack[-1].append([words,None]); words=[]
        else: words.append(token)
    if words or len(stack)!=1: raise AdoptionError('active_config_invalid')
    return root


def _walk(nodes):
    for words,children in nodes:
        yield words
        if children is not None: yield from _walk(children)


def _runtime_identity(inspect):
    # Exclude volatile health timestamps, assigned endpoint IDs and runtime IPs.
    material={k:inspect.get(k) for k in ('Id','Image','Config','HostConfig','Mounts')}
    # Docker may enumerate the same bindings in a different order on each read.
    if isinstance(material['Mounts'],list):
        material['Mounts']=sorted(material['Mounts'],key=_canonical)
    material['endpoints']=endpoint_configurations(inspect)
    return sha256(_canonical(material))


def _safe(value):
    return value if isinstance(value,str) and len(value)<256 and re.fullmatch(r'[A-Za-z0-9_/.=~^@:$()<>?*+ -]+',value) else '[unsupported value]'


def _safe_upstream(words):
    # Nginx values may be quoted or contain variables. Check URL authority
    # structure before any formatting/allowlist processing.
    for word in words:
        value=word.strip('"\'')
        if re.match(r'(?i)https?://',value):
            try:
                parsed=urlsplit(value)
                if not parsed.netloc: return '[unsupported upstream]'
                if parsed.username is not None: return '[credential-bearing upstream redacted]'
            except ValueError: return '[unsupported upstream]'
    return _safe(' '.join(words))


def _declaration(value):
    required={'schema_version','domain','tls','release_selection_dir','services','obsolete_overlays','obsolete_owner_labels'}
    if not isinstance(value,dict) or set(value)-required-{'host_forward_groups','acme_challenge','hostname_policy','http_policy','release_broker_enabled'} or not required<=set(value) or type(value['schema_version']) is not int or value['schema_version']!=1:
        raise AdoptionError('declaration_schema_invalid')
    if 'release_broker_enabled' in value and type(value['release_broker_enabled']) is not bool:
        raise AdoptionError('release_broker_policy_invalid')
    domain=value['domain']
    if not isinstance(domain,str) or not DOMAIN.fullmatch(domain) or '..' in domain or domain.endswith('.') or value['tls'] not in ('self-signed','letsencrypt'):
        raise AdoptionError('domain_or_tls_invalid')
    directory=value['release_selection_dir']
    if not isinstance(directory,str) or not Path(directory).is_absolute() or any(c in directory for c in '\n\r\0:') or '..' in Path(directory).parts:
        raise AdoptionError('release_directory_invalid')
    if not isinstance(value['services'],dict) or not value['services']: raise AdoptionError('services_required')
    services={}; paths=[]
    reserved=['/auth/','/internal/','/api/','/assets/','/static/','/vastai/','/runpod/','/vastai-api/','/runpod-api/']
    for name,service in value['services'].items():
        if not isinstance(name,str) or not NAME.fullmatch(name) or not isinstance(service,dict) or set(service)-{'container_name','path','port','display_name'} or not {'container_name','path','port'}<=set(service):
            raise AdoptionError('service_schema_invalid')
        container=service['container_name']; path=service['path']; port=service['port']
        if not isinstance(container,str) or not NAME.fullmatch(container) or not isinstance(path,str) or not PATH.fullmatch(path) or type(port) is not int or not 1<=port<=65535:
            raise AdoptionError('service_target_invalid')
        if any(path.startswith(p) or p.startswith(path) for p in reserved+paths): raise AdoptionError('route_collision')
        if name in DEFAULT_SERVICES:
            default=DEFAULT_SERVICES[name]
            if path!=default['path'] or name=='vast-price-manager' and (container!=default['container_name'] or port!=default['port']): raise AdoptionError('product_route_invalid')
        display=service.get('display_name',name)
        if not isinstance(display,str) or not re.fullmatch(r'[A-Za-z0-9 ._-]{1,100}',display): raise AdoptionError('display_name_invalid')
        paths.append(path); services[name]={**deepcopy(DEFAULT_SERVICES.get(name,{})),**service,'display_name':display}
    if not isinstance(value['obsolete_overlays'],list) or len(value['obsolete_overlays'])>1: raise AdoptionError('overlay_declaration_invalid')
    for overlay in value['obsolete_overlays']:
        if not isinstance(overlay,dict) or set(overlay)!={'destination','sha256','replacement_sha256','equivalence_evidence_sha256'} or overlay['destination']!=AUTH_OVERLAY or not isinstance(overlay['sha256'],str) or any(not isinstance(overlay[k],str) or not re.fullmatch('[0-9a-f]{64}',overlay[k]) for k in ('sha256','replacement_sha256','equivalence_evidence_sha256')): raise AdoptionError('overlay_declaration_invalid')
    if not isinstance(value['obsolete_owner_labels'],list) or any(not isinstance(label,str) or not label.startswith('cryptolabs.migration.') for label in value['obsolete_owner_labels']): raise AdoptionError('owner_declaration_invalid')
    try:
        groups=validate_host_forward_groups(value.get('host_forward_groups',[]),domain)
        acme=validate_acme_challenge(value.get('acme_challenge'))
        policy=validate_hostname_policy(value.get('hostname_policy'),domain)
        http_policy=validate_http_policy(value.get('http_policy'),domain,acme)
    except ValueError as error: raise AdoptionError(str(error)) from None
    canonical=deepcopy(value)
    for name,setting in [('hostname_policy',policy),('http_policy',http_policy)]:
        if setting is None: canonical.pop(name,None)
        else: canonical[name]=setting
    return {**canonical,'host_forward_groups':groups,'acme_challenge':acme,'release_selection_dir':str(Path(directory).resolve()),'services':services}


def render_standard(declaration):
    return get_jinja_env().get_template('nginx.conf.j2').render(domain=declaration['domain'],letsencrypt=declaration['tls']=='letsencrypt',services=declaration['services'],host_forward_groups=declaration.get('host_forward_groups',[]),acme_challenge=declaration.get('acme_challenge'),hostname_policy=validate_hostname_policy(declaration.get('hostname_policy'),declaration['domain']),http_policy=validate_http_policy(declaration.get('http_policy'),declaration['domain'],declaration.get('acme_challenge'))).encode()


PREVIOUS_STANDARD_SOURCE = '444d7c0e06e0f9935971c51872e9f37bd8869282'
PREVIOUS_STANDARD_TEMPLATES = {'previous-standard-nginx-444d7c0.conf.j2': 'f12e2b9800cbaa0e49e685506cfaad38eb7e568fa6d239fa15277af59073d8de', 'vast-price-manager-auth-blocks.conf.j2': 'b9d7013434557492887b0600bc2afc92227ee17f9efebe55b0cccc4b16bd3f81', 'acme-challenge.conf.j2': '7e594162700825757c9d402971094448aa1834d1f7121ac1c02f152f345e149a', 'fleet-api-routes.conf.j2': '6991ca6bf1dd4b258e8ee7851fc69ef50b19dfe2353570e4911a0ebadc68ed1b', 'vast-price-manager.conf.j2': '32483d169a09c42653396e66c5c7efe1995bd599f44f11ee64fa2f0731a0a2f8', 'standard-service-routes.conf.j2': 'ef0f55aae48e35127d288781e68281a371505ba27384c8fd04dff9200dce3963', 'exporter-auth-routes.conf.j2': '450f4c418c09474ac45b6dd314c47cc090fe7d230a0206b30e48c7975023133b', 'host-forwarding.conf.j2': '35c4a1fe1d3001865a77d7653350b7a61968953b94172dc7063bc31a42c0f9f7'}


def render_previous_standard(declaration):
    env=get_jinja_env()
    for name,expected in PREVIOUS_STANDARD_TEMPLATES.items():
        raw=env.loader.get_source(env,name)[0].encode()
        if sha256(raw)!=expected: raise AdoptionError('previous_standard_profile_unavailable')
    return env.get_template('previous-standard-nginx-444d7c0.conf.j2').render(
        domain=declaration['domain'],letsencrypt=declaration['tls']=='letsencrypt',services=declaration['services'],
        host_forward_groups=declaration.get('host_forward_groups',[]),acme_challenge=declaration.get('acme_challenge'),
        hostname_policy=validate_hostname_policy(declaration.get('hostname_policy'),declaration['domain']),
        http_policy=validate_http_policy(declaration.get('http_policy'),declaration['domain'],declaration.get('acme_challenge'))).encode()


def _policy_healthcheck(source, declaration):
    try:
        return policy_healthcheck(source.get('Config',{}).get('Healthcheck'),declaration['domain'],declaration.get('hostname_policy'),declaration.get('http_policy'),letsencrypt=declaration['tls']=='letsencrypt')
    except ValueError: raise AdoptionError('source_healthcheck_unmapped') from None


def _guarded_bootstrap_profile(legacy, declaration):
    """Exact observed legacy delta, checked against an independent full fixture.

    This constructs the supported tree; it never strips unknown source nodes.
    Only the declared primary literal is substituted, in explicit positions.
    """
    domain=declaration['domain']
    tree=parse_nginx(render_managed_vpm_config(legacy,True))
    http=next(c for w,c in tree if w==['http'])
    server=next(c for w,c in http if w==['server'])
    # The captured HTTPS server is the released bootstrap minus HTTP listen.
    server.remove([['listen','80','default_server'],None])
    name=next(n for n in server if n[0]==['server_name','_'])
    name[0][1]=domain
    guard=parse_nginx(('if ($host != '+domain+') { return 444; }').encode())[0]
    server.insert(server.index(name)+1,guard)
    auth=next(n for n in server if n[0]==['location','=','/_auth_check'])
    protected=parse_nginx(b"""
        location = /auth/headers { return 404; }
        location = /auth/headers/ { return 404; }
        location = /auth/exporters/authorize { return 404; }
        location = /auth/exporters/authorize/ { return 404; }
        location = /_exporter_admin {
            internal;
            proxy_pass http://auth_server/auth/exporters/authorize;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header Cookie $http_cookie;
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_pass_header X-Mgmt-Token;
        }
    """)
    index=server.index(auth)+1;server[index:index]=protected
    login=next(c for w,c in server if w==['location','/auth/'])
    upstream=next(n for n in login if n[0]==['proxy_pass','http://auth_server/auth/'])
    index=login.index(upstream)+1
    login[index:index]=parse_nginx(b'proxy_hide_header X-Mgmt-Token; proxy_cookie_flags fleet_session secure httponly samesite=lax;')
    for route in ('^/vastai-api/(.*)$','^/runpod-api/(.*)$'):
        children=next(c for w,c in server if w==['location','~',route])
        request=next(w for w,c in children if w==['auth_request','/_auth_check'])
        request[1]='/_exporter_admin'
    public=parse_nginx(('server { listen 80 default_server; server_name '+domain+'; if ($host != '+domain+') { return 444; } location ^~ /.well-known/acme-challenge/ { root /var/www/certbot; default_type text/plain; try_files $uri =404; } location / { return 308 https://'+domain+'$request_uri; } }').encode())[0]
    public[1].extend(parse_nginx(get_jinja_env().get_template('vast-price-manager-auth-blocks.conf.j2').render().encode()))
    index=next(i for i,n in enumerate(http) if n[0]==['server'])
    http.insert(index,public)
    http.extend(parse_nginx(render_host_forward_groups(declaration.get('host_forward_groups',[]),legacy_profile=True)))
    return tree


class AdoptionEngine(DockerEngine):
    """Existing Engine/switch safety with bounded archive and validation actions."""
    def prove_recovery_auth(self,source,expected,identity):
        """Execute the source image's auth startup with no network or ports.

        The stopped source store stays quiescent while this actual old initializer
        proves it preserves every file with the obsolete bootstrap disabled.
        """
        from .migration import _mount_request
        name='cryptolabs-recovery-proof-'+identity
        mount=next(m for m in source['Mounts'] if m['Destination']=='/data/auth')
        environment=[e for e in source['Config'].get('Env',[]) if not e.startswith('FLEET_ADMIN_PASS=')]+['FLEET_ADMIN_PASS=']
        command="import pathlib,runpy,time; runpy.run_path('/app/auth-server.py',run_name='recovery_probe'); pathlib.Path('/tmp/auth-preserved').write_text('ready'); time.sleep(180)"
        self.create(name,{'Config':{'Image':source['Image'],'Entrypoint':['python3','-c',command],
            'Env':environment,'Healthcheck':{'Test':['NONE']},'Labels':{'io.cryptolabs.adoption.recovery-proof':identity}},
            'HostConfig':{'NetworkMode':'none','RestartPolicy':{'Name':'no'},'Mounts':[_mount_request(mount)]},
            'NetworkingConfig':{'EndpointsConfig':{}}})
        try:
            self.start(name); deadline=time.monotonic()+self.timeout
            while True:
                if not self.inspect(name).get('State',{}).get('Running'): raise AdoptionError('source_auth_startup_failed')
                try:
                    if self._file_bytes(name,'/tmp/auth-preserved')==b'ready': break
                except MigrationError: pass
                if time.monotonic()>=deadline: raise AdoptionError('source_auth_startup_unverified')
                time.sleep(.1)
            if auth_state(self.archive_auth(name),allow_active_jobs=True)!=expected:
                raise AdoptionError('source_auth_startup_changed_authority; forward_repair_required')
        finally: self.remove(name,ignore_missing=True)

    @contextmanager
    def updater_guard(self,source,image,identity):
        """Hold the updater's actual shared-store locks through switch/recovery.

        A container provides the same filesystem/inodes for bind and named
        volumes, including remote Docker engines. It runs only stdlib locking,
        with no network, Docker socket, auth startup, or inspected environment.
        """
        from .migration import _mount_request
        mount=next(m for m in source['Mounts'] if m['Destination']=='/data/auth')
        if not mount.get('RW',True): raise AdoptionError('auth_mount_requires_write')
        command="""import fcntl,os,pathlib,sys,time
directory=pathlib.Path(sys.argv[1]); directory.mkdir(mode=0o700,parents=True,exist_ok=True)
streams=[]
try:
 for name in ('dispatch.lock','operation.lock'):
  stream=os.fdopen(os.open(directory/name,os.O_RDWR|os.O_CREAT,0o600),'w'); streams.append(stream)
  fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 sys.exit(73)
# Presence is sufficient: malformed/unknown/link markers also require recovery.
if os.path.lexists(directory/'controller-adoption.json'): sys.exit(74)
pathlib.Path(sys.argv[2]).write_text('held')
while True: time.sleep(60)
"""
        name='cryptolabs-adoption-lock-'+identity
        self.create(name,{'Config':{'Image':image,'Entrypoint':['python3'],
            'Cmd':['-c',command,'/data/auth/update-jobs','/tmp/updater-held'],
            'Healthcheck':{'Test':['NONE']},'Labels':{'io.cryptolabs.adoption.guard':identity,
                'com.centurylinklabs.watchtower.enable':'false'}},
            'HostConfig':{'NetworkMode':'none','RestartPolicy':{'Name':'no'},'Mounts':[_mount_request(mount)]},
            'NetworkingConfig':{'EndpointsConfig':{}}})
        def check():
            if not self.inspect(name).get('State',{}).get('Running'):
                raise AdoptionError('updater_quiescence_unavailable')
        try:
            self.start(name); deadline=time.monotonic()+self.timeout
            while True:
                check()
                try:
                    if self._file_bytes(name,'/tmp/updater-held')==b'held': break
                except MigrationError: pass
                if time.monotonic()>=deadline: raise AdoptionError('updater_quiescence_unavailable')
                time.sleep(.1)
            yield check
        finally:
            self.remove(name,ignore_missing=True)

    @contextmanager
    def controller_guard(self, source_proxy, image_id, operation_id, *, recover=False):
        """Exclude durable updates until verified controller completion.

        Context exit always removes the helper but retains its marker. Recovery
        reclaims the same source/mount/operation only under both real locks.
        """
        from . import controller_recovery as recovery
        from .migration import _mount_request
        import uuid
        if type(recover) is not bool:
            raise AdoptionError('controller_guard_identity_invalid')
        owner = uuid.uuid4().hex + uuid.uuid4().hex
        mounts = source_proxy.get('Mounts', [])
        auth = [m for m in mounts if m.get('Destination') == '/data/auth']
        if len(auth) != 1 or not auth[0].get('RW', True) or any(
                m.get('Destination', '').startswith('/data/auth/') for m in mounts):
            raise AdoptionError('controller_guard_auth_mount_unsupported')
        if auth[0].get('Type') not in ('bind', 'volume') or image_id != source_proxy.get('Image'):
            raise AdoptionError('controller_guard_source_unsupported')
        try:
            mount = _mount_request(auth[0])
            record = recovery.validate_record({'schema_version': 1, 'kind': 'dc-controller-adoption',
                'operation_id': operation_id, 'source_id': source_proxy['Id'], 'source_image': image_id,
                'auth_mount_sha256': sha256(_canonical(mount)), 'owner': owner})
        except (KeyError, TypeError, ValueError, MigrationError, recovery.RecoveryError):
            raise AdoptionError('controller_guard_identity_invalid') from None
        name = 'cryptolabs-controller-lock-' + owner[:24]
        command = Path(recovery.__file__).read_text()
        self.create(name, {'Config': {'Image': image_id, 'Entrypoint': ['python3'],
            'Cmd': ['-c', command, '/data/auth/update-jobs', '/tmp/controller-guard.sock',
                    json.dumps(record, sort_keys=True, separators=(',', ':')),
                    'recover' if recover else 'new', str(min(self.timeout, 15))],
            'Healthcheck': {'Test': ['NONE']}, 'Labels': {'io.cryptolabs.controller.guard': owner,
                'com.centurylinklabs.watchtower.enable': 'false'}},
            'HostConfig': {'NetworkMode': 'none', 'RestartPolicy': {'Name': 'no'},
                'Mounts': [mount], 'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '1'}}},
            'NetworkingConfig': {'EndpointsConfig': {}}})
        helper_id = None
        completed = False

        def invoke(action):
            try:
                helper = self.inspect(helper_id or name)
                if (not helper.get('State', {}).get('Running') or helper.get('Image') != image_id
                        or helper.get('Config', {}).get('Labels', {}).get('io.cryptolabs.controller.guard') != owner
                        or helper_id and helper.get('Id') != helper_id):
                    raise ValueError()
                response = self._controller_guard_rpc(helper['Id'], owner, action)
                if response != {'owner': owner, 'state': 'completed' if action == 'complete' else 'held'}:
                    raise ValueError()
                return helper['Id']
            except Exception:
                raise AdoptionError('controller_guard_unavailable; controller recovery required') from None

        def check():
            if completed:
                raise AdoptionError('controller_guard_completed')
            invoke('check')

        def complete():
            nonlocal completed
            invoke('complete')
            completed = True

        check.complete = complete
        try:
            self.start(name)
            deadline = time.monotonic() + min(self.timeout, 15) + 1
            while True:
                try:
                    helper_id = invoke('check')
                    break
                except AdoptionError:
                    if time.monotonic() >= deadline or not self.inspect(name).get('State', {}).get('Running'):
                        raise AdoptionError('controller_guard_unavailable; controller recovery required') from None
                    time.sleep(.02)
            yield check
        finally:
            self.remove(helper_id or name, ignore_missing=True)

    def _controller_guard_rpc(self, helper_id, owner, action):
        """Execute the fixed client on this Engine, with bounded framed output."""
        from .controller_recovery import CLIENT_COMMAND
        from .migration import _UnixHTTPConnection
        try:
            command = ['python3', '-c', CLIENT_COMMAND, owner, action]
            if action not in ('check', 'complete'):
                raise ValueError()
            created = self._request('POST', '/containers/' + quote(helper_id, safe='') + '/exec',
                {'AttachStdin': False, 'AttachStdout': True, 'AttachStderr': True,
                 'Tty': False, 'Cmd': command})
            if len(created) > 4096:
                raise ValueError()
            exec_id = json.loads(created)['Id']
            if not isinstance(exec_id, str) or not re.fullmatch('[0-9a-f]{64}', exec_id):
                raise ValueError()
            # Generic Engine requests read the complete response. Bound this
            # attached exec stream before allocation on the very same socket.
            connection = _UnixHTTPConnection(self.socket_path, min(self.timeout, 5))
            try:
                connection.request('POST', '/exec/' + exec_id + '/start',
                    body=json.dumps({'Detach': False, 'Tty': False}).encode(),
                    headers={'Content-Type': 'application/json'})
                response = connection.getresponse()
                if response.status != 200:
                    raise ValueError()
                output = response.read(16385)
            finally:
                connection.close()
            if len(output) > 16384:
                raise ValueError()
            stdout = bytearray()
            offset = 0
            while offset < len(output):
                header = output[offset:offset + 8]
                if len(header) != 8 or header[0] not in (1, 2) or header[1:4] != b'\0\0\0':
                    raise ValueError()
                length = int.from_bytes(header[4:8], 'big')
                offset += 8
                if length > len(output) - offset or header[0] == 2 and length:
                    raise ValueError()
                if header[0] == 1:
                    if len(stdout) + length > 4096:
                        raise ValueError()
                    stdout.extend(output[offset:offset + length])
                offset += length
            inspected = self._request('GET', '/exec/' + exec_id + '/json')
            if len(inspected) > 4096:
                raise ValueError()
            execution = json.loads(inspected)
            process = execution.get('ProcessConfig', {})
            if (execution.get('ID') != exec_id or execution.get('ContainerID') != helper_id
                    or execution.get('Running') is not False
                    or type(execution.get('ExitCode')) is not int or execution['ExitCode'] != 0
                    or process.get('entrypoint') != command[0] or process.get('arguments') != command[1:]
                    or process.get('tty') is not False):
                raise ValueError()
            value = json.loads(stdout)
            if value != {'owner': owner, 'state': 'completed' if action == 'complete' else 'held'}:
                raise ValueError()
            return value
        except Exception:
            raise AdoptionError('controller_guard_unavailable') from None

    def read_config(self,name):
        return CustomConfigMigrator(Path('/etc/cryptolabs-proxy'),Path('/etc/cryptolabs-proxy/migrations'),engine=self)._read_active_config(name)
    def image(self,reference): return json.loads(self._request('GET','/images/'+quote(reference,safe='')+'/json'))
    def pull(self,reference):
        # Keep registry errors/private transport bodies out of public output.
        self._request('POST','/images/create?fromImage='+quote(reference,safe=''),allowed=(200,))
    def validate(self,image,candidate,inspect,identity):
        CustomConfigMigrator(candidate.parent,candidate.parent,engine=self)._validate_candidate(image,candidate,inspect,identity)
    def anonymous_auth(self,name,tls,domain=None):
        # Internal fixed executable probes both auth server and public Nginx.
        import subprocess
        probe="import http.client; c=http.client.HTTPConnection('127.0.0.1',8081,timeout=5); c.request('GET','/auth/exporters/authorize'); assert c.getresponse().status==401; c.close(); c=http.client.HTTPSConnection('127.0.0.1',443,context=__import__('ssl')._create_unverified_context(),timeout=5); c.request('GET','/api/versions'); assert c.getresponse().status==401; c.close(); c=http.client.HTTPSConnection('127.0.0.1',443,context=__import__('ssl')._create_unverified_context(),timeout=5); c.request('GET','/auth/vast-price-manager/session'); assert c.getresponse().status==404"
        if domain is not None:
            validate_hostname_policy('primary-only',domain)
            # Connect only to loopback, while TLS SNI and HTTP Host use the
            # same declared literal. Preserve existing local unverified probe.
            connect="class PrimaryHTTPS(http.client.HTTPSConnection):\n def connect(self):\n  sock=__import__('socket').create_connection(('127.0.0.1',443),self.timeout); self.sock=self._context.wrap_socket(sock,server_hostname=self.host)\n"
            probe=probe.replace("c=http.client.HTTPSConnection('127.0.0.1',443,", "c=PrimaryHTTPS("+repr(domain)+",443,")
            certificate='/etc/letsencrypt/live/'+domain+'/fullchain.pem' if tls=='letsencrypt' else '/etc/nginx/ssl/server.crt'
            probe=probe.replace("context=__import__('ssl')._create_unverified_context()", "context=ctx")
            connect+="ctx=__import__('ssl').create_default_context(); ctx.load_verify_locations(cafile="+repr(certificate)+");\n"
            probe=probe.replace("import http.client; ", "import http.client\n"+connect+"\n")
        try:
            result=subprocess.run(['docker','exec',name,'python3','-c',probe],capture_output=True,timeout=self.timeout)
            return result.returncode==0
        except (OSError,subprocess.SubprocessError): return False
    def overlay_bytes(self,destination):
        if destination!=AUTH_OVERLAY: raise AdoptionError('unsupported_overlay')
        return self._file_bytes('cryptolabs-proxy',destination)
    def _file_bytes(self,name,path):
        data=self._request('GET','/containers/'+quote(name,safe='')+'/archive?path='+quote(path,safe=''))
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members=archive.getmembers()
            if len(members)!=1 or not members[0].isfile() or members[0].name!=Path(path).name or members[0].size>MAX_CONFIG: raise AdoptionError('artifact_file_unavailable')
            return archive.extractfile(members[0]).read()
    def artifact_file_sha256(self,image,destination,identity):
        if destination!=AUTH_OVERLAY: raise AdoptionError('unsupported_overlay')
        name='cryptolabs-proof-'+identity
        self.create(name,{'Config':{'Image':image,'Entrypoint':['/app/entrypoint.sh']},'HostConfig':{'NetworkMode':'none'},'NetworkingConfig':{'EndpointsConfig':{}}})
        try: return sha256(self._file_bytes(name,destination))
        finally: self.remove(name,ignore_missing=True)
    def archive_auth(self,name):
        data=self._request('GET','/containers/'+quote(name,safe='')+'/archive?path=/data/auth')
        # Never extract archive names on the host; only permit bounded regular
        # files/dirs under auth. No link/device/special file restoration.
        if len(data)>256*1024*1024: raise AdoptionError('auth_snapshot_too_large')
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive:
                p=Path(member.name)
                if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0]!='auth' or not(member.isfile() or member.isdir()): raise AdoptionError('auth_snapshot_unsupported')
        return data
    def restore_auth(self,source,data,image,identity):
        """Restore a stopped shared store, including deletion of new schema files."""
        from .migration import _mount_request
        inspect=self.inspect(source)
        if inspect.get('State',{}).get('Running'): raise AdoptionError('auth_restore_requires_stopped_proxy')
        mount=next(m for m in inspect['Mounts'] if m['Destination']=='/data/auth')
        name='cryptolabs-state-'+identity
        # Fixed command, fixed target, no network, no inspected credentials.
        expected=auth_state(data)
        command="import pathlib,time; p=pathlib.Path('/data/auth'); [(p/n).unlink(missing_ok=True) for n in "+repr(sorted(OWNED_AUTH_FILES))+"]; pathlib.Path('/tmp/state-cleared').write_text('ready'); time.sleep(180)"
        self.create(name,{'Config':{'Image':image,'Entrypoint':['python3','-c',command],'Healthcheck':{'Test':['NONE']},'Labels':{'io.cryptolabs.adoption.recovery':identity}},'HostConfig':{'NetworkMode':'none','Mounts':[_mount_request(mount)]},'NetworkingConfig':{'EndpointsConfig':{}}})
        try:
            self.start(name); deadline=time.monotonic()+self.timeout
            while True:
                try:
                    if self._file_bytes(name,'/tmp/state-cleared')==b'ready': break
                except MigrationError: pass
                if time.monotonic()>=deadline: raise AdoptionError('auth_restore_clear_unverified')
                time.sleep(.1)
            self.stop(name); self.put_auth(name,owned_auth_archive(data))
            observed=auth_state(self.archive_auth(name))
            if observed!=expected: raise AdoptionError('auth_restore_identity_mismatch; forward_repair_required')
        finally: self.remove(name,ignore_missing=True)
    def put_auth(self,name,data):
        # Archive API accepts tar bytes, unlike the JSON mutation adapter.
        from .migration import _UnixHTTPConnection
        connection=_UnixHTTPConnection(self.socket_path,self.timeout)
        try:
            connection.request('PUT','/containers/'+quote(name,safe='')+'/archive?path=/data',body=data,headers={'Content-Type':'application/x-tar'})
            response=connection.getresponse(); response.read()
            if response.status!=200: raise AdoptionError('auth_copy_failed')
        finally: connection.close()


class StandardAdoption:
    def __init__(self,config_dir,*,engine=None):
        self.config_dir=Path(config_dir); self.engine=engine or AdoptionEngine(); self.backup_root=self.config_dir/'standard-adoptions'

    def inspect(self):
        source=self.engine.inspect('cryptolabs-proxy'); active=self.engine.read_config('cryptolabs-proxy'); tree=parse_nginx(active)
        words=list(_walk(tree)); registry=ServiceRegistry(self.config_dir)
        return {'container_id':source['Id'],'runtime_sha256':_runtime_identity(source),'config_sha256':sha256(active),
            'running':source.get('State',{}).get('Running',False),'routes':[_safe(' '.join(w[1:])) for w in words if w[0]=='location'],
            'tls':{'certificates':[_safe(w[1]) for w in words if w[0]=='ssl_certificate'],'listeners':[_safe(' '.join(w[1:])) for w in words if w[0]=='listen'],'domains':[_safe(' '.join(w[1:])) for w in words if w[0]=='server_name']},
            'mounts':[{'type':m.get('Type'),'destination':_safe(m.get('Destination')),'source':_safe(m.get('Name') if m.get('Type')=='volume' else m.get('Source')),'read_only':not m.get('RW',True)} for m in source.get('Mounts',[])],
            'services':{n:{k:_safe(str(s.get(k,''))) for k in ('container_name','path','port','lifecycle_manager')} for n,s in registry.services.items()},
            'upstreams':[_safe_upstream(w[1:]) for w in words if w[0] in ('proxy_pass','set') and any(re.search(r'(?i)https?://', word) for word in w[1:])],
            'custom_mode':registry.config.get('custom_config',{}).get('mode'),'owner':'cryptolabs-proxy','directives':sorted({w[0] for w in words})}

    def _coverage(self,active,declaration):
        tree=parse_nginx(active)
        # Entire configuration, including every directive and server, must
        # match a supported profile. Only explicit server_name is normalized.
        def normalize(nodes):
            nodes=deepcopy(nodes)
            def visit(items):
                for words,children in items:
                    if words[0]=='server_name':
                        if words[1:]==[declaration['domain']] or words[1:]==['_'] and not declaration.get('hostname_policy'): words[1:]=['DECLARED_DOMAIN']
                        elif words[1:] not in [g['hostnames'] for g in declaration.get('host_forward_groups',[])]: raise AdoptionError('source_domain_unmapped')
                    if children is not None: visit(children)
            visit(nodes); return nodes
        actual=normalize(tree); expected=normalize(parse_nginx(render_standard(declaration)))
        if actual==expected: return 'standard'
        if actual==normalize(parse_nginx(render_previous_standard(declaration))): return 'standard-444d7c0'
        legacy=get_jinja_env().loader.get_source(get_jinja_env(),'legacy-bootstrap-nginx.conf')[0].encode()
        profiles=[legacy]
        for enabled in (False,True): profiles.append(render_managed_vpm_config(legacy,enabled))
        forwarding_tree=parse_nginx(render_host_forward_groups(declaration.get('host_forward_groups',[]),legacy_profile=True))
        profile_trees=[]
        for profile in profiles:
            profile_tree=parse_nginx(profile)
            if declaration.get('acme_challenge'):
                http=next(children for words,children in profile_tree if words==['http'])
                server=next(children for words,children in http if words==['server'])
                index=next(i for i,(words,children) in enumerate(server) if words[0]=='location')
                server[index:index]=parse_nginx(render_acme_challenge(declaration['acme_challenge'],legacy_profile=True))
            next(children for words,children in profile_tree if words==['http']).extend(deepcopy(forwarding_tree))
            profile_trees.append(profile_tree)
        if not declaration.get('hostname_policy') and any(actual==normalize(p) for p in profile_trees):
            required={'ipmi-monitor','dc-overview','grafana','prometheus','vastai-exporter','runpod-exporter'}
            if b'location = /vast-pricing' in active: required.add('vast-price-manager')
            if not required<=set(declaration['services']) or declaration['tls']!='self-signed': raise AdoptionError('legacy_services_or_tls_unmapped')
            for name in required:
                if any(declaration['services'][name][k]!=DEFAULT_SERVICES[name][k] for k in ('container_name','port','path')): raise AdoptionError('legacy_target_unmapped')
            return 'released-bootstrap-1.2.0'
        if declaration.get('hostname_policy')=='primary-only' and declaration.get('http_policy')=='redirect-primary-https' and declaration['tls']=='self-signed' and not declaration.get('acme_challenge'):
            guarded=_guarded_bootstrap_profile(legacy,declaration)
            if actual==normalize(guarded):
                required={'ipmi-monitor','dc-overview','grafana','prometheus','vastai-exporter','runpod-exporter','vast-price-manager'}
                if not required<=set(declaration['services']): raise AdoptionError('legacy_services_or_tls_unmapped')
                for name in required:
                    if any(declaration['services'][name][k]!=DEFAULT_SERVICES[name][k] for k in ('container_name','port','path')): raise AdoptionError('legacy_target_unmapped')
                return 'released-bootstrap-primary-only'
        supported=[expected]+([normalize(p) for p in profile_trees] if not declaration.get('hostname_policy') else [])
        actual_words=list(_walk(actual)); actual_set={tuple(w) for w in actual_words}
        closest=min(supported,key=lambda profile:len(actual_set^{tuple(w) for w in _walk(profile)}))
        known={tuple(w) for w in _walk(closest)}
        mismatch=next((w for w in actual_words if tuple(w) not in known),['structural-order'])
        context=_safe(' '.join(mismatch) if mismatch[0]=='location' else mismatch[0])
        raise AdoptionError('unsupported_source_behavior: '+context+' requires a supported declarative product profile')

# TRACEWEAVER: entrypoint=plan; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def plan(self,settings,*,environment=None,proposed_selection=None):
        declaration=_declaration(settings); source=self.engine.inspect('cryptolabs-proxy')
        if not source.get('State',{}).get('Running'): raise AdoptionError('source_not_running')
        healthcheck=_policy_healthcheck(source,declaration)
        active=self.engine.read_config('cryptolabs-proxy')
        recorded=ServiceRegistry(self.config_dir).config.get('standard_adoption',{})
        source_declaration=recorded.get('declaration',declaration)
        profile=self._coverage(active,source_declaration)
        env={e.split('=',1)[0]:e.split('=',1)[1] for e in source['Config'].get('Env',[]) if '=' in e}
        if source['Config'].get('Entrypoint')!=['/app/entrypoint.sh'] or source['Config'].get('Cmd') not in (None,['nginx','-g','daemon off;']): raise AdoptionError('unsupported_runtime_command')
        if not env.get('AUTH_SECRET_KEY'): raise AdoptionError('persistent_session_key_required')
        if env.get('AUTH_DATA_DIR','/data/auth')!='/data/auth': raise AdoptionError('unsupported_auth_directory')
        mounts=source.get('Mounts',[])
        auth=[m for m in mounts if m.get('Destination')=='/data/auth']
        if len(auth)!=1 or auth[0].get('Type') not in ('volume','bind'): raise AdoptionError('persistent_auth_mount_required')
        declared={o['destination']:o for o in declaration['obsolete_overlays']}
        for mount in mounts:
            target=mount.get('Destination','')
            if target.startswith(('/app','/usr/local/lib','/usr/lib/python')) and target not in declared: raise AdoptionError('undeclared_code_overlay')
        for destination,overlay in declared.items():
            matching=[m for m in mounts if m.get('Destination')==destination]
            if len(matching)!=1 or matching[0].get('Type')!='bind' or matching[0].get('RW') is not False: raise AdoptionError('overlay_mount_unproven')
            if sha256(self.engine.overlay_bytes(destination))!=overlay['sha256']: raise AdoptionError('overlay_source_changed')
            if overlay['replacement_sha256']!=sha256(Path(__file__).with_name('auth.py').read_bytes()): raise AdoptionError('overlay_replacement_module_unproven')
        if proposed_selection is None:
            snapshot=load(declaration['release_selection_dir'])
        else:
            if not isinstance(proposed_selection,dict): raise SelectionError('invalid_snapshot')
            snapshot=validate_selection(proposed_selection['selection_bytes'].encode(), proposed_selection['manifest_bytes'].encode(),
                selection_id=proposed_selection['selection_id'],selection_sha256=proposed_selection['selection_sha256'])
        image=self.engine.image(source['Image']); platform=image.get('Os','')+'/'+image.get('Architecture','')
        selected=targets(snapshot,platform); artifact=selected.get('cryptolabs-proxy')
        if not artifact or artifact['owner']!='proxy-updater': raise AdoptionError('approved_proxy_required')
        candidate=render_standard(declaration)
        registry=_snapshot_registry_files(ServiceRegistry(self.config_dir))
        registry_hash=sha256(_canonical({p.name:sha256(data) if data is not None else None for p,data in registry.items()}))
        plan={'container_id':source['Id'],'runtime_sha256':_runtime_identity(source),'config_sha256':sha256(active),'registry_sha256':registry_hash,
            'declaration_sha256':sha256(_canonical(declaration)),'candidate_sha256':sha256(candidate),'selection_id':snapshot['selection_id'],'selection_sha256':snapshot['selection_sha256'],
            'manifest_sha256':snapshot['manifest_sha256'],'image':artifact['reference'],'platform':platform,'origin':artifact['origin'],'source_profile':profile,
            'environment_sha256':sha256(_canonical(environment or {}))}
        if healthcheck is not None:
            original=source.get('Config',{}).get('Healthcheck')
            plan['healthcheck_sha256']=sha256(_canonical(healthcheck))
            plan['source_healthcheck_sha256']=sha256(_canonical(original))
            plan['healthcheck_action']='preserved-verified-source' if original==healthcheck else 'generated-policy-probe'
        plan['plan_id']=sha256(_canonical(plan))[:24]
        return plan

    def _already(self,declaration,identity):
        registry=ServiceRegistry(self.config_dir); recorded=registry.config.get('standard_adoption',{})
        if recorded.get('plan_id')!=identity: return False
        source=self.engine.inspect('cryptolabs-proxy'); snapshot=load(declaration['release_selection_dir'])
        return recorded.get('serving_sha256')==_runtime_identity(source) and recorded.get('declaration_sha256')==sha256(_canonical(declaration)) and recorded.get('selection_sha256')==snapshot['selection_sha256'] and sha256(self.engine.read_config('cryptolabs-proxy'))==sha256(render_standard(declaration))

    def adopt(self,settings,identity,*,environment=None):
        if os.geteuid()!=0: raise AdoptionError('standard_adoption_requires_root')
        from .cli import registry_lock
        backup=None
        try:
            with registry_lock(self.config_dir), ExitStack() as exclusion:
                declaration=_declaration(settings)
                if not environment and self._already(declaration,identity): return {'state':'already_adopted','plan_id':identity}
                plan=self.plan(settings,environment=environment)
                if plan['plan_id']!=identity: raise AdoptionError('plan_changed')
                source=self.engine.inspect('cryptolabs-proxy'); registry=ServiceRegistry(self.config_dir); previous=_snapshot_registry_files(registry)
                backup=self.backup_root/identity
                if backup.exists(): raise AdoptionError('private_recovery_snapshot_exists; inspect prior outcome before retry')
                backup.mkdir(parents=True,mode=0o700); self.backup_root.chmod(0o700); backup.chmod(0o700)
                import os as filesystem
                for parent in (self.backup_root,self.config_dir):
                    descriptor=filesystem.open(parent,filesystem.O_RDONLY|filesystem.O_DIRECTORY)
                    try: filesystem.fsync(descriptor)
                    finally: filesystem.close(descriptor)
                write=_durable_private
                write(backup/'declaration.json',_canonical(declaration)); write(backup/'inspect.json',_canonical(source)); write(backup/'source.nginx.conf',self.engine.read_config('cryptolabs-proxy')); _write_registry_backup(backup,previous)
                candidate=backup/'candidate.nginx.conf'; write(candidate,render_standard(declaration)); write(backup/'plan.json',_canonical(plan))
                write(backup/'registry-snapshot.json',(backup/'registry-snapshot.json').read_bytes())
                journal={'schema_version':1,'plan_id':identity,'source_id':source['Id'],
                    'source_image_id':source['Image'],'candidate_may_have_started':False}
                def phase(value,**details):
                    journal.update(details); journal['phase']=value
                    write(backup/'phase.json',_canonical(journal))
                def mutation(action,name,invoke,**details):
                    try: before=engine.inspect(name)
                    except Exception: before=None
                    phase(action+'-requested',target=name,prior_id=before.get('Id') if before else None,**details)
                    result=invoke()
                    try: after=engine.inspect(name)
                    except Exception: after=None
                    if action=='create' and after and after.get('Image')==journal.get('candidate_image_id'):
                        journal['candidate_container_id']=after['Id']
                    phase(action+'-done',target=name,observed_id=after.get('Id') if after else None,**details)
                    return result
                engine=self.engine
                phase('candidate-pull-requested')
                self.engine.pull(plan['image']); artifact=self.engine.image(plan['image'])
                phase('candidate-pulled',candidate_image_id=artifact['Id'])
                if plan['image'] not in artifact.get('RepoDigests',[]) or artifact.get('Os','')+'/'+artifact.get('Architecture','')!=plan['platform']: raise AdoptionError('candidate_artifact_mismatch')
                if self.engine.artifact_file_sha256(plan['image'],AUTH_OVERLAY,identity)!=sha256(Path(__file__).with_name('auth.py').read_bytes()): raise AdoptionError('candidate_auth_module_mismatch')
                for overlay in declaration['obsolete_overlays']:
                    if self.engine.artifact_file_sha256(plan['image'],overlay['destination'],identity)!=overlay['replacement_sha256']: raise AdoptionError('overlay_artifact_module_mismatch')
                    write(backup/'retired-auth.py',self.engine.overlay_bytes(overlay['destination']))
                phase('candidate-validate-requested')
                self.engine.validate(plan['image'],candidate,source,identity)
                phase('candidate-validated')
                # Recheck source and all policy/file identities after pull/test.
                if self.plan(settings,environment=environment)!=plan: raise AdoptionError('preflight_changed')
                phase('updater-guard-requested')
                guard=exclusion.enter_context(self.engine.updater_guard(source,plan['image'],identity))
                try: held=self.engine.inspect('cryptolabs-adoption-lock-'+identity)
                except Exception: held=None
                phase('updater-held',guard_id=held.get('Id') if held else None)
                # Reject queued/running jobs and take an identity while the
                # dispatch and operation authorities are both excluded.
                prestop_archive=self.engine.archive_auth(plan['container_id'])
                prestop_auth=auth_state(prestop_archive)
                write(backup/'prestop-auth.tar',prestop_archive)
                phase('source-ready-to-stop',prestop_auth=prestop_auth)
                if self.plan(settings,environment=environment)!=plan: raise AdoptionError('preflight_changed')
                clone=deepcopy(source); clone['Mounts']=[m for m in source['Mounts'] if m.get('Destination') not in ('/etc/nginx/nginx.conf','/etc/cryptolabs/releases') and m.get('Destination') not in {o['destination'] for o in declaration['obsolete_overlays']}]
                auth_mount=next(m for m in source['Mounts'] if m['Destination']=='/data/auth')
                clone['Mounts'].append({'Type':'bind','Source':declaration['release_selection_dir'],'Destination':'/etc/cryptolabs/releases','RW':False})
                if declaration.get('release_broker_enabled'):
                    socket_path='/run/dc-overview-release-broker.sock'
                    metadata=Path(socket_path).lstat()
                    import stat
                    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid!=0 or metadata.st_mode & 0o077:
                        raise AdoptionError('release_broker_owner_unavailable')
                    clone['Mounts']=[m for m in clone['Mounts'] if m.get('Destination')!=socket_path]
                    clone['Mounts'].append({'Type':'bind','Source':socket_path,'Destination':socket_path,'RW':False})
                nginx=self.config_dir/'nginx.conf'; request=build_recreate_request(clone,plan['image'],str(nginx))
                if declaration.get('hostname_policy') or declaration.get('http_policy'):
                    request['Config']['Healthcheck']=_policy_healthcheck(source,declaration)
                config=request['Config']; config['Labels']=deepcopy(config.get('Labels') or {})
                config['Labels'].update({'com.centurylinklabs.watchtower.enable':'false','io.cryptolabs.update.origin':plan['origin'],'io.cryptolabs.update.reference':plan['image']})
                for label in declaration['obsolete_owner_labels']: config['Labels'].pop(label,None)
                config['Env']=[e for e in config.get('Env',[]) if not e.startswith('RELEASE_SELECTION_REQUIRED=') and e.split('=',1)[0] not in (environment or {})]+['RELEASE_SELECTION_REQUIRED=true']+[k+'='+v for k,v in (environment or {}).items()]
                if not any(e.startswith('FLEET_PUBLIC_ORIGIN=') for e in config['Env']):
                    config['Env'].append('FLEET_PUBLIC_ORIGIN=https://'+declaration['domain'])
                engine=self.engine; auth_copy=None; candidate_copy=None; candidate_started=False; recovered_id=None; recovery_expected=None; recovery_verified=False
                def restart_source(name):
                    nonlocal recovered_id,recovery_expected,recovery_verified
                    guard()
                    expected=auth_state(engine.archive_auth(name),allow_active_jobs=True)
                    recovery_expected=expected
                    # Immutable source environment cannot be edited by Docker.
                    # Prove its real startup, then recreate the original image
                    # with only obsolete installation authority disabled.
                    phase('source-startup-proof-requested')
                    engine.prove_recovery_auth(source,expected,identity)
                    phase('source-startup-proven')
                    guard()
                    clone=deepcopy(source)
                    nginx_mount=next((m for m in clone['Mounts'] if m['Destination']=='/etc/nginx/nginx.conf'),None)
                    path=nginx_mount['Source'] if nginx_mount and nginx_mount.get('Type')=='bind' else str(backup/'source.nginx.conf')
                    clone['Mounts']=[m for m in clone['Mounts'] if m['Destination'] not in ('/etc/nginx/nginx.conf',AUTH_OVERLAY)]
                    payload=build_recreate_request(clone,source['Image'],path)
                    if nginx_mount:
                        from .migration import _mount_request
                        payload['HostConfig']['Mounts'][-1]=_mount_request(nginx_mount)
                    payload['Config']['Env']=[e for e in source['Config'].get('Env',[]) if not e.startswith('FLEET_ADMIN_PASS=')]+['FLEET_ADMIN_PASS=']
                    for network in engine.inspect(name).get('NetworkSettings',{}).get('Networks',{}): mutation('disconnect',name,lambda network=network:engine.disconnect(name,network))
                    mutation('rename',name,lambda:engine.rename(name,'cryptolabs-proxy.original-'+identity))
                    mutation('source-create',name,lambda:engine.create(name,payload))
                    recovered_id=engine.inspect(name)['Id']
                    mutation('source-start',name,lambda:engine.start(name))
                    healthy=wait_for_container_healthy(engine,name,PROXY_READY_TIMEOUT)
                    if auth_state(engine.archive_auth(name),allow_active_jobs=True)!=expected:
                        mutation('stop',name,lambda:engine.stop(name))
                        raise AdoptionError('source_recovery_unverified; forward_repair_required')
                    recovery_verified=healthy
                    if not healthy: mutation('stop',name,lambda:engine.stop(name,ignore_missing=True))
                    if healthy:
                        evidence=_restoration_evidence(engine,source,plan,expected,self.config_dir)
                        write(backup/'restoration.json',_canonical(evidence))
                        phase('source-restored',restoration_auth=expected,restoration_sha256=sha256(_canonical(evidence)))
                    guard()
                class StateSafeEngine:
                    def __getattr__(self,name): return getattr(engine,name)
                    def stop(self,name,ignore_missing=False):
                        nonlocal auth_copy,candidate_copy
                        guard()
                        stopping=engine.inspect(name)
                        mutation('stop',name,lambda:engine.stop(name,ignore_missing=ignore_missing))
                        if stopping and stopping['Id'] not in (source['Id'],recovered_id) and candidate_started:
                            candidate_copy=engine.archive_auth(name); write(backup/'candidate-auth.tar',candidate_copy)
                        if name==plan['container_id'] and auth_copy is None:
                            try:
                                auth_copy=engine.archive_auth(name)
                                if auth_state(auth_copy)!=prestop_auth: raise AdoptionError('auth_store_changed_requires_quiescence')
                                write(backup/'auth.tar',auth_copy)
                                phase('source-quiescent')
                                write(nginx,candidate.read_bytes())
                                phase('source-config-ready')
                            except Exception:
                                _restore_registry_files(previous)
                                restart_source('cryptolabs-proxy')
                                raise AdoptionError('auth_snapshot_failed; '+('sanitized_source_recovered' if recovery_verified else 'forward_repair_required')) from None
                    def create(self,name,payload):
                        guard()
                        mutation('create',name,lambda:engine.create(name,payload))
                    def rename(self,name,target):
                        guard(); mutation('rename',name,lambda:engine.rename(name,target),rename_to=target)
                    def disconnect(self,name,network):
                        guard(); mutation('disconnect',name,lambda:engine.disconnect(name,network))
                    def remove(self,name,ignore_missing=False):
                        guard(); mutation('remove',name,lambda:engine.remove(name,ignore_missing=ignore_missing))
                    def connect(self,name,network,endpoint):
                        guard()
                        # The generic switch requests source reconnect before
                        # start. Recovery deliberately defers that topology:
                        # the sanitized source is recreated with its original
                        # endpoints only after owned restore and startup proof.
                        if engine.inspect(name)['Id'] in (source['Id'],recovered_id): return
                        mutation('connect',name,lambda:engine.connect(name,network,endpoint))
                    def start(self,name):
                        nonlocal candidate_started
                        guard()
                        # State restoration precedes old-image startup. A
                        # retained candidate similarly recovers its own schema.
                        if engine.inspect(name)['Id'] in (source['Id'],recovered_id):
                            if candidate_started:
                                if candidate_copy is None or auth_state(auth_copy)['external']!=auth_state(candidate_copy)['external']: raise AdoptionError('shared_store_changed; forward_repair_required')
                                engine.restore_auth(name,auth_copy,plan['image'],identity)
                            _restore_registry_files(previous)
                            if engine.inspect(name)['Id']==source['Id']:
                                restart_source(name)
                                return
                        else:
                            if candidate_copy is not None: engine.restore_auth(name,candidate_copy,plan['image'],identity)
                            write(nginx,candidate.read_bytes()); candidate_started=True
                            phase('candidate-start-requested',candidate_may_have_started=True)
                        mutation('start',name,lambda:engine.start(name))
                        guard()
                def candidate_health(name):
                    guard()
                    ready=wait_for_proxy_ready(engine,name,lambda:engine.anonymous_auth(name,declaration['tls'],declaration['domain']) if declaration.get('hostname_policy') or declaration.get('http_policy') else engine.anonymous_auth(name,declaration['tls']),PROXY_READY_TIMEOUT)
                    if not ready: mutation('stop',name,lambda:engine.stop(name,ignore_missing=True))
                    if ready: phase('candidate-verified',candidate_verified=True,serving_runtime_sha256=_runtime_identity(engine.inspect(name)))
                    guard()
                    return ready
                def rollback_health(name):
                    guard()
                    ready=wait_for_container_healthy(engine,name,PROXY_READY_TIMEOUT)
                    if ready and engine.inspect(name)['Id']==recovered_id:
                        ready=auth_state(engine.archive_auth(name),allow_active_jobs=True)==recovery_expected
                        if not ready: engine.stop(name,ignore_missing=True)
                    guard()
                    return ready
                outcome=SwitchController(StateSafeEngine(),candidate_health,rollback_health_check=rollback_health).apply(plan['container_id'],identity,request,candidate_name='cryptolabs-proxy')
                # Persist only after serving proof. If saving fails, keep the
                # proven candidate/config and private recovery record for repair.
                registry.services=declaration['services']; registry.config.pop('custom_config',None)
                registry.config.update(domain=declaration['domain'],letsencrypt=declaration['tls']=='letsencrypt',release_selection_dir=declaration['release_selection_dir'],host_forward_groups=declaration.get('host_forward_groups',[]),acme_challenge=declaration.get('acme_challenge'))
                for name in ('hostname_policy','http_policy'):
                    if name in declaration: registry.config[name]=declaration[name]
                    else: registry.config.pop(name,None)
                registry.config['release_broker_enabled']=declaration.get('release_broker_enabled',False)
                registry.config['standard_adoption']={'plan_id':identity,'serving_sha256':_runtime_identity(engine.inspect('cryptolabs-proxy')),'declaration_sha256':plan['declaration_sha256'],'selection_sha256':plan['selection_sha256'],'auth_mount':{k:auth_mount[k] for k in ('Type','Name','Source','Destination') if k in auth_mount},'declaration':declaration}
                if declaration.get('hostname_policy') or declaration.get('http_policy'):
                    registry.config['standard_adoption']['healthcheck']=deepcopy(request['Config']['Healthcheck'])
                try: registry.save()
                except OSError:
                    write(backup/'outcome.json',_canonical({'state':'candidate_retained','reason':'registry_forward_repair_required'}))
                    return {'state':'candidate_retained','reason':'registry_forward_repair_required','plan_id':identity}
                result={'state':'adopted' if outcome.state=='applied' else 'candidate_retained','plan_id':identity,'positive_login_verified':False}
                try:
                    write(backup/'outcome.json',_canonical(result))
                    phase('completed')
                except OSError: return {'state':'candidate_retained','reason':'outcome_record_unavailable','plan_id':identity}
                return result
        except (SelectionError,MigrationError,OSError,ValueError,KeyError) as error:
            # Do not stringify Engine bodies, inspected values or raw configs.
            if backup is not None and backup.exists():
                # Actual runtime states are public metadata; snapshots remain
                # private. Never infer restored state from a caught exception.
                states={}
                for name in ('cryptolabs-proxy','cryptolabs-proxy.rollback-'+identity,'cryptolabs-proxy.candidate-'+identity,'cryptolabs-proxy.original-'+identity):
                    try:
                        observed=self.engine.inspect(name)
                        if observed: states[name]={'id':observed['Id'],'running':observed.get('State',{}).get('Running',False)}
                    except Exception: states[name]={'unknown':True}
                serving=states.get('cryptolabs-proxy',{})
                restored=(serving.get('id')==locals().get('source',{}).get('Id') or serving.get('id')==locals().get('recovered_id') and locals().get('recovery_verified',False)) and serving.get('running')
                try: _durable_private(backup/'outcome.json',_canonical({'state':'rolled_back' if restored else 'forward_repair_required','runtime':states,'candidate_auth_snapshot_retained':(backup/'candidate-auth.tar').exists()}))
                except OSError: pass
            reason=str(error) if isinstance(error,AdoptionError) else 'adoption_failed; inspect private recovery outcome for actual state'
            raise AdoptionError(reason) from None


# TRACEWEAVER: entrypoint=recover_adoption; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
    def recover_adoption(self, plan_id):
        """Reconcile a fixed journal and restore only proven pre-candidate phases."""
        if not isinstance(plan_id,str) or not re.fullmatch('[0-9a-f]{24}',plan_id):
            raise AdoptionError('invalid_plan_id')
        result={'state':'recovery-required','plan_id':plan_id}
        if os.geteuid()!=0: raise AdoptionError('standard_adoption_requires_root')
        from .cli import registry_lock
        try:
            with registry_lock(self.config_dir):
                backup=self.backup_root/plan_id
                def read(name):
                    path=backup/name
                    for parent in (self.backup_root,backup,path):
                        stat=parent.lstat()
                        if parent.is_symlink() or stat.st_uid!=os.getuid() or stat.st_mode & 0o077:
                            raise AdoptionError('unsafe_recovery_journal')
                    raw=path.read_bytes()
                    if len(raw)>MAX_CONFIG: raise AdoptionError('invalid_recovery_journal')
                    return json.loads(raw)
                plan=read('plan.json'); declaration=read('declaration.json')
                if plan.get('plan_id')!=plan_id or sha256(_canonical({k:v for k,v in plan.items() if k!='plan_id'}))[:24]!=plan_id:
                    return result
                if sha256(_canonical(declaration))!=plan['declaration_sha256']: return result
                try: outcome=read('outcome.json')
                except FileNotFoundError: outcome={}
                try: journal=read('phase.json')
                except FileNotFoundError: journal={}
                completed=outcome.get('state') in ('adopted','already_adopted') and self._already(declaration,plan_id)
                source=read('inspect.json')
                if _runtime_identity(source)!=plan['runtime_sha256']: return result
                expected=journal.get('restoration_auth',journal.get('prestop_auth'))
                if not isinstance(expected,dict): return result
                serving=self.engine.inspect('cryptolabs-proxy')
                restored=False
                evidence=None
                if journal.get('restoration_sha256'):
                    evidence=read('restoration.json')
                    observed=_restoration_evidence(self.engine,source,plan,expected,self.config_dir)
                    restored=(evidence==observed and journal['restoration_sha256']==sha256(_canonical(evidence)))
                # Preserve exclusions on uncertain candidate/recovery phases.
                restore_allowed=(journal.get('plan_id')==plan_id and journal.get('candidate_may_have_started') is False
                    and not journal.get('phase','').startswith('recovery-')
                    and serving and not serving.get('State',{}).get('Running')
                    and _runtime_identity(serving)==plan['runtime_sha256'])
                if not completed and not restored and not restore_allowed: return result
                # A killed owner can leave its fixed exclusion helper. The registry
                # lock proves that owner is no longer executing this adoption.
                helper_name='cryptolabs-adoption-lock-'+plan_id
                try: helper=self.engine.inspect(helper_name)
                except MigrationError as error:
                    if not str(error).endswith('HTTP 404'): return result
                    helper=None
                if helper:
                    auth=next(m for m in source['Mounts'] if m['Destination']=='/data/auth')
                    mounts=[m for m in helper.get('Mounts',[]) if m.get('Destination')=='/data/auth']
                    def mount_identity(m):
                        return (m.get('Type'),m.get('Name') if m.get('Type')=='volume' else m.get('Source'),m.get('Destination'),m.get('RW'))
                    command=helper.get('Config',{}).get('Cmd',[])
                    if (not journal.get('guard_id') or helper.get('Id')!=journal['guard_id']
                            or helper.get('Image')!=journal.get('candidate_image_id')
                            or helper.get('Config',{}).get('Labels',{}).get('io.cryptolabs.adoption.guard')!=plan_id
                            or helper.get('Config',{}).get('Entrypoint')!=['python3']
                            or len(command)!=4 or command[0]!='-c' or command[-2:]!=['/data/auth/update-jobs','/tmp/updater-held']
                            or len(mounts)!=1 or mount_identity(mounts[0])!=mount_identity(auth)):
                        return result
                    journal['phase']='recovery-guard-remove-requested'
                    _durable_private(backup/'phase.json',_canonical(journal))
                    self.engine.remove(helper['Id'])
                if completed: return {'state':'completed','plan_id':plan_id}
                if restored:
                    with self.engine.updater_guard(source,plan['image'],plan_id) as guard:
                        guard()
                        if load(declaration['release_selection_dir'])['selection_sha256']!=plan['selection_sha256']: return result
                        observed=_restoration_evidence(self.engine,source,plan,expected,self.config_dir)
                        if evidence!=observed or journal.get('restoration_sha256')!=sha256(_canonical(evidence)): return result
                        guard()
                    return {'state':'failed-restored','plan_id':plan_id}
                with self.engine.updater_guard(source,plan['image'],plan_id) as guard:
                    guard()
                    if load(declaration['release_selection_dir'])['selection_sha256']!=plan['selection_sha256']: return result
                    serving=self.engine.inspect('cryptolabs-proxy')
                    if serving.get('State',{}).get('Running') or _runtime_identity(serving)!=plan['runtime_sha256']: return result
                    archive=self.engine.archive_auth(source['Id'])
                    quiescent_auth=auth_state(archive)
                    prestop_auth_match=quiescent_auth==journal['prestop_auth']
                    expected=quiescent_auth
                    # This is the missing quiescent post-stop capture. It is kept
                    # for evidence, never restored over the current shared store.
                    _durable_private(backup/'auth.tar',archive)
                    previous=read('registry-snapshot.json')
                    allowed={str(self.config_dir/name) for name in ('services.yaml','config.yaml','nginx.conf')}
                    if set(previous)!=allowed: return result
                    old={Path(path):value.encode('latin1') if value is not None else None for path,value in previous.items()}
                    saved_sha=sha256(_canonical({p.name:sha256(data) if data is not None else None for p,data in old.items()}))
                    if saved_sha!=plan['registry_sha256']: return result
                    current=_snapshot_registry_files(ServiceRegistry(self.config_dir))
                    for path,data in current.items():
                        if path.name=='nginx.conf':
                            if sha256(data or b'') not in (sha256(old[path] or b''),plan['candidate_sha256']): return result
                        elif data!=old[path]: return result
                    if sha256(self.engine.read_config('cryptolabs-proxy')) not in (plan['config_sha256'],plan['candidate_sha256']): return result
                    def phase(name,**details):
                        journal.update(details); journal['phase']=name
                        _durable_private(backup/'phase.json',_canonical(journal))
                    def inspect_optional(name):
                        try: return self.engine.inspect(name)
                        except MigrationError as error:
                            if not str(error).endswith('HTTP 404'): raise
                            return None
                    def mutate(action,name,invoke,**details):
                        before=inspect_optional(name)
                        phase('recovery-'+action+'-requested',target=name,prior_id=before.get('Id') if before else None,**details)
                        invoke()
                        after=inspect_optional(name)
                        phase('recovery-'+action+'-done',target=name,observed_id=after.get('Id') if after else None,**details)
                        guard()
                    phase('recovery-startup-proof-requested',restoration_auth=expected,prestop_auth_match=prestop_auth_match)
                    self.engine.prove_recovery_auth(source,expected,plan_id)
                    phase('recovery-startup-proven',recovery_startup_proven=True)
                    if auth_state(self.engine.archive_auth(source['Id']))!=expected: return result
                    _restore_registry_files(old)
                    for path,data in old.items():
                        if data is not None: _durable_private(path,data)
                    clone=deepcopy(source)
                    nginx_mount=next((m for m in clone['Mounts'] if m['Destination']=='/etc/nginx/nginx.conf'),None)
                    nginx_path=nginx_mount['Source'] if nginx_mount and nginx_mount.get('Type')=='bind' else str(backup/'source.nginx.conf')
                    clone['Mounts']=[m for m in clone['Mounts'] if m['Destination'] not in ('/etc/nginx/nginx.conf',AUTH_OVERLAY)]
                    payload=build_recreate_request(clone,source['Image'],nginx_path)
                    if nginx_mount:
                        from .migration import _mount_request
                        payload['HostConfig']['Mounts'][-1]=_mount_request(nginx_mount)
                    payload['Config']['Env']=[e for e in source['Config'].get('Env',[]) if not e.startswith('FLEET_ADMIN_PASS=')]+['FLEET_ADMIN_PASS=']
                    # Preserve the exact original name/image, with installation
                    # authority disabled and its real initializer already proven.
                    retained='cryptolabs-proxy.original-'+plan_id
                    try: prior=self.engine.inspect(retained)
                    except MigrationError as error:
                        if not str(error).endswith('HTTP 404'): return result
                        prior=None
                    if prior: return result
                    for network in serving.get('NetworkSettings',{}).get('Networks',{}):
                        mutate('disconnect',source['Id'],lambda network=network:self.engine.disconnect(source['Id'],network))
                    mutate('rename',source['Id'],lambda:self.engine.rename(source['Id'],retained),rename_to=retained)
                    mutate('create','cryptolabs-proxy',lambda:self.engine.create('cryptolabs-proxy',payload))
                    recovered=self.engine.inspect('cryptolabs-proxy')
                    phase('recovery-source-created',recovery_container_id=recovered['Id'])
                    mutate('start',recovered['Id'],lambda:self.engine.start('cryptolabs-proxy'))
                    healthy=wait_for_container_healthy(self.engine,'cryptolabs-proxy',PROXY_READY_TIMEOUT)
                    if not healthy or auth_state(self.engine.archive_auth('cryptolabs-proxy'),allow_active_jobs=True)!=expected:
                        mutate('stop',recovered['Id'],lambda:self.engine.stop('cryptolabs-proxy'))
                        return result
                    evidence=_restoration_evidence(self.engine,source,plan,expected,self.config_dir)
                    _durable_private(backup/'restoration.json',_canonical(evidence))
                    phase('failed-restored',restoration_sha256=sha256(_canonical(evidence)))
                    _durable_private(backup/'outcome.json',_canonical({'state':'rolled_back','restoration_sha256':sha256(_canonical(evidence))}))
                    guard()
                return {'state':'failed-restored','plan_id':plan_id}
        except (OSError,ValueError,KeyError,MigrationError,TypeError,StopIteration):
            pass
        return result

    def reconfigure(self,config):
        """Ordinary setup after adoption keeps inspected state and session key."""
        try:
            registry=ServiceRegistry(self.config_dir)
            declaration=deepcopy(registry.config['standard_adoption']['declaration'])
            declaration.update(domain=config.domain,tls='letsencrypt' if config.use_letsencrypt else 'self-signed',services={n:{k:v for k,v in s.items() if k in ('container_name','path','port','display_name')} for n,s in registry.services.items()},obsolete_overlays=[],obsolete_owner_labels=[])
            if config.release_selection_dir: declaration['release_selection_dir']=str(config.release_selection_dir)
            if config.hostname_policy is not None: declaration['hostname_policy']=config.hostname_policy
            if config.http_policy is not None: declaration['http_policy']=config.http_policy
            source=self.engine.inspect('cryptolabs-proxy'); current={e.split('=',1)[0]:e.split('=',1)[1] for e in source['Config'].get('Env',[]) if '=' in e}
            environment={}
            for name,value in [('FLEET_ADMIN_USER',config.fleet_admin_user),('FLEET_ADMIN_PASS',config.fleet_admin_pass),('SITE_NAME',config.site_name),('WATCHDOG_API_KEY',config.watchdog_api_key),('WATCHDOG_URL',config.watchdog_url)]:
                if value and current.get(name)!=value: environment[name]=value
            # Session signing and internal authority keys are continuous. Their
            # default generated values in ProxyConfig are not rotation intent.
            normalized=_declaration(declaration)
            selected=targets(load(normalized['release_selection_dir']),self.engine.image(source['Image'])['Os']+'/'+self.engine.image(source['Image'])['Architecture'])['cryptolabs-proxy']
            health_current=True
            if normalized.get('hostname_policy') or normalized.get('http_policy'):
                # No-op is a positive preservation result; validate both the
                # runtime probe and its saved policy metadata before claiming it.
                runtime_health=_policy_healthcheck(source,normalized)
                recorded_health=registry.config['standard_adoption'].get('healthcheck')
                if recorded_health is None: raise AdoptionError('recorded_healthcheck_unmapped')
                saved_health=_policy_healthcheck({'Config':{'Healthcheck':recorded_health}},normalized)
                health_current=(runtime_health==source['Config'].get('Healthcheck') and saved_health==recorded_health and runtime_health==saved_health)
            labels=source['Config'].get('Labels') or {}
            if health_current and not environment and sha256(self.engine.read_config('cryptolabs-proxy'))==sha256(render_standard(normalized)) and labels.get('io.cryptolabs.update.reference')==selected['reference'] and labels.get('com.centurylinklabs.watchtower.enable')=='false':
                return True,'Adopted proxy configuration already current; state preserved'
            plan=self.plan(declaration,environment=environment)
            result=self.adopt(declaration,plan['plan_id'],environment=environment)
            return result['state']=='adopted',result['state']
        except (AdoptionError,SelectionError,KeyError,OSError):
            return False,'Adopted proxy reconfiguration failed; inspect private recovery outcome'


    def repeat_setup(self):
        """Repeat ordinary CLI setup without replacing customer defaults."""
        from .setup import ProxyConfig
        registry=ServiceRegistry(self.config_dir)
        source=self.engine.inspect('cryptolabs-proxy')
        environment={e.split('=',1)[0]:e.split('=',1)[1] for e in source['Config'].get('Env',[]) if '=' in e}
        config=ProxyConfig(registry.config['domain'],use_letsencrypt=registry.config.get('letsencrypt',False),fleet_admin_user=environment.get('FLEET_ADMIN_USER','admin'),fleet_admin_pass=environment.get('FLEET_ADMIN_PASS',''),site_name=environment.get('SITE_NAME',''),watchdog_api_key=environment.get('WATCHDOG_API_KEY',''),watchdog_url=environment.get('WATCHDOG_URL',''),release_selection_dir=Path(registry.config['release_selection_dir']),hostname_policy=registry.config.get('hostname_policy'),http_policy=registry.config.get('http_policy'))
        return self.reconfigure(config)
