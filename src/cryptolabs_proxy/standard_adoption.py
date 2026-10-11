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

from .config import get_jinja_env, validate_host_forward_groups, render_host_forward_groups, validate_acme_challenge, render_acme_challenge
from .custom_config import render_managed_vpm_config
from .migration import (DockerEngine, CustomConfigMigrator, MigrationError, SwitchController,
                        build_recreate_request, endpoint_configurations, wait_for_container_healthy,
                        wait_for_proxy_ready, PROXY_READY_TIMEOUT, _snapshot_registry_files,
                        _write_registry_backup, _restore_registry_files)
from .release_selection import load, targets, sha256, SelectionError
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
    if not isinstance(value,dict) or set(value)-required-{'host_forward_groups','acme_challenge'} or not required<=set(value) or type(value['schema_version']) is not int or value['schema_version']!=1:
        raise AdoptionError('declaration_schema_invalid')
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
    except ValueError as error: raise AdoptionError(str(error)) from None
    return {**deepcopy(value),'host_forward_groups':groups,'acme_challenge':acme,'release_selection_dir':str(Path(directory).resolve()),'services':services}


def render_standard(declaration):
    return get_jinja_env().get_template('nginx.conf.j2').render(domain=declaration['domain'],letsencrypt=declaration['tls']=='letsencrypt',services=declaration['services'],host_forward_groups=declaration.get('host_forward_groups',[]),acme_challenge=declaration.get('acme_challenge')).encode()


class AdoptionEngine(DockerEngine):
    """Existing Engine/switch safety with bounded archive and validation actions."""
    def prove_recovery_auth(self,source,expected,identity):
        """Execute the source image's auth startup with no network or ports.

        The restored store remains private until this actual old initializer
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

    def read_config(self,name):
        return CustomConfigMigrator(Path('/etc/cryptolabs-proxy'),Path('/etc/cryptolabs-proxy/migrations'),engine=self)._read_active_config(name)
    def image(self,reference): return json.loads(self._request('GET','/images/'+quote(reference,safe='')+'/json'))
    def pull(self,reference):
        # Keep registry errors/private transport bodies out of public output.
        self._request('POST','/images/create?fromImage='+quote(reference,safe=''),allowed=(200,))
    def validate(self,image,candidate,inspect,identity):
        CustomConfigMigrator(candidate.parent,candidate.parent,engine=self)._validate_candidate(image,candidate,inspect,identity)
    def anonymous_auth(self,name,tls):
        # Internal fixed executable probes both auth server and public Nginx.
        import subprocess
        probe="import http.client; c=http.client.HTTPConnection('127.0.0.1',8081,timeout=5); c.request('GET','/auth/exporters/authorize'); assert c.getresponse().status==401; c.close(); c=http.client.HTTPSConnection('127.0.0.1',443,context=__import__('ssl')._create_unverified_context(),timeout=5); c.request('GET','/api/versions'); assert c.getresponse().status==401; c.close(); c=http.client.HTTPSConnection('127.0.0.1',443,context=__import__('ssl')._create_unverified_context(),timeout=5); c.request('GET','/auth/vast-price-manager/session'); assert c.getresponse().status==404"
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
                        if words[1:] in ([declaration['domain']],['_']): words[1:]=['DECLARED_DOMAIN']
                        elif words[1:] not in [g['hostnames'] for g in declaration.get('host_forward_groups',[])]: raise AdoptionError('source_domain_unmapped')
                    if children is not None: visit(children)
            visit(nodes); return nodes
        actual=normalize(tree); expected=normalize(parse_nginx(render_standard(declaration)))
        if actual==expected: return 'standard'
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
        if any(actual==normalize(p) for p in profile_trees):
            required={'ipmi-monitor','dc-overview','grafana','prometheus','vastai-exporter','runpod-exporter'}
            if b'location = /vast-pricing' in active: required.add('vast-price-manager')
            if not required<=set(declaration['services']) or declaration['tls']!='self-signed': raise AdoptionError('legacy_services_or_tls_unmapped')
            for name in required:
                if any(declaration['services'][name][k]!=DEFAULT_SERVICES[name][k] for k in ('container_name','port','path')): raise AdoptionError('legacy_target_unmapped')
            return 'released-bootstrap-1.2.0'
        supported=[expected]+[normalize(p) for p in profile_trees]
        actual_words=list(_walk(actual)); actual_set={tuple(w) for w in actual_words}
        closest=min(supported,key=lambda profile:len(actual_set^{tuple(w) for w in _walk(profile)}))
        known={tuple(w) for w in _walk(closest)}
        mismatch=next((w for w in actual_words if tuple(w) not in known),['structural-order'])
        context=_safe(' '.join(mismatch) if mismatch[0]=='location' else mismatch[0])
        raise AdoptionError('unsupported_source_behavior: '+context+' requires a supported declarative product profile')

    def plan(self,settings,*,environment=None):
        declaration=_declaration(settings); source=self.engine.inspect('cryptolabs-proxy')
        if not source.get('State',{}).get('Running'): raise AdoptionError('source_not_running')
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
        snapshot=load(declaration['release_selection_dir']); image=self.engine.image(source['Image']); platform=image.get('Os','')+'/'+image.get('Architecture','')
        selected=targets(snapshot,platform); artifact=selected.get('cryptolabs-proxy')
        if not artifact or artifact['owner']!='proxy-updater': raise AdoptionError('approved_proxy_required')
        candidate=render_standard(declaration)
        registry=_snapshot_registry_files(ServiceRegistry(self.config_dir))
        registry_hash=sha256(_canonical({p.name:sha256(data) if data is not None else None for p,data in registry.items()}))
        plan={'container_id':source['Id'],'runtime_sha256':_runtime_identity(source),'config_sha256':sha256(active),'registry_sha256':registry_hash,
            'declaration_sha256':sha256(_canonical(declaration)),'candidate_sha256':sha256(candidate),'selection_id':snapshot['selection_id'],'selection_sha256':snapshot['selection_sha256'],
            'manifest_sha256':snapshot['manifest_sha256'],'image':artifact['reference'],'platform':platform,'origin':artifact['origin'],'source_profile':profile,
            'environment_sha256':sha256(_canonical(environment or {}))}
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
                write=CustomConfigMigrator._write_private
                write(backup/'inspect.json',_canonical(source)); write(backup/'source.nginx.conf',self.engine.read_config('cryptolabs-proxy')); _write_registry_backup(backup,previous)
                candidate=backup/'candidate.nginx.conf'; write(candidate,render_standard(declaration)); write(backup/'plan.json',_canonical(plan))
                self.engine.pull(plan['image']); artifact=self.engine.image(plan['image'])
                if plan['image'] not in artifact.get('RepoDigests',[]) or artifact.get('Os','')+'/'+artifact.get('Architecture','')!=plan['platform']: raise AdoptionError('candidate_artifact_mismatch')
                if self.engine.artifact_file_sha256(plan['image'],AUTH_OVERLAY,identity)!=sha256(Path(__file__).with_name('auth.py').read_bytes()): raise AdoptionError('candidate_auth_module_mismatch')
                for overlay in declaration['obsolete_overlays']:
                    if self.engine.artifact_file_sha256(plan['image'],overlay['destination'],identity)!=overlay['replacement_sha256']: raise AdoptionError('overlay_artifact_module_mismatch')
                    write(backup/'retired-auth.py',self.engine.overlay_bytes(overlay['destination']))
                self.engine.validate(plan['image'],candidate,source,identity)
                # Recheck source and all policy/file identities after pull/test.
                if self.plan(settings,environment=environment)!=plan: raise AdoptionError('preflight_changed')
                guard=exclusion.enter_context(self.engine.updater_guard(source,plan['image'],identity))
                # Reject queued/running jobs and take an identity while the
                # dispatch and operation authorities are both excluded.
                prestop_auth=auth_state(self.engine.archive_auth(plan['container_id']))
                if self.plan(settings,environment=environment)!=plan: raise AdoptionError('preflight_changed')
                clone=deepcopy(source); clone['Mounts']=[m for m in source['Mounts'] if m.get('Destination') not in ('/etc/nginx/nginx.conf','/etc/cryptolabs/releases') and m.get('Destination') not in {o['destination'] for o in declaration['obsolete_overlays']}]
                auth_mount=next(m for m in source['Mounts'] if m['Destination']=='/data/auth')
                clone['Mounts'].append({'Type':'bind','Source':declaration['release_selection_dir'],'Destination':'/etc/cryptolabs/releases','RW':False})
                nginx=self.config_dir/'nginx.conf'; request=build_recreate_request(clone,plan['image'],str(nginx))
                config=request['Config']; config['Labels']=deepcopy(config.get('Labels') or {})
                config['Labels'].update({'com.centurylinklabs.watchtower.enable':'false','io.cryptolabs.update.origin':plan['origin'],'io.cryptolabs.update.reference':plan['image']})
                for label in declaration['obsolete_owner_labels']: config['Labels'].pop(label,None)
                config['Env']=[e for e in config.get('Env',[]) if not e.startswith('RELEASE_SELECTION_REQUIRED=') and e.split('=',1)[0] not in (environment or {})]+['RELEASE_SELECTION_REQUIRED=true']+[k+'='+v for k,v in (environment or {}).items()]
                engine=self.engine; auth_copy=None; candidate_copy=None; candidate_started=False; recovered_id=None; recovery_expected=None; recovery_verified=False
                def restart_source(name):
                    nonlocal recovered_id,recovery_expected,recovery_verified
                    guard()
                    expected=auth_state(engine.archive_auth(name),allow_active_jobs=True)
                    recovery_expected=expected
                    # Immutable source environment cannot be edited by Docker.
                    # Prove its real startup, then recreate the original image
                    # with only obsolete installation authority disabled.
                    engine.prove_recovery_auth(source,expected,identity)
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
                    for network in engine.inspect(name).get('NetworkSettings',{}).get('Networks',{}): engine.disconnect(name,network)
                    engine.rename(name,'cryptolabs-proxy.original-'+identity)
                    engine.create(name,payload)
                    recovered_id=engine.inspect(name)['Id']
                    engine.start(name)
                    healthy=wait_for_container_healthy(engine,name,PROXY_READY_TIMEOUT)
                    if auth_state(engine.archive_auth(name),allow_active_jobs=True)!=expected:
                        engine.stop(name)
                        raise AdoptionError('source_recovery_unverified; forward_repair_required')
                    recovery_verified=healthy
                    if not healthy: engine.stop(name,ignore_missing=True)
                    guard()
                class StateSafeEngine:
                    def __getattr__(self,name): return getattr(engine,name)
                    def stop(self,name,ignore_missing=False):
                        nonlocal auth_copy,candidate_copy
                        guard()
                        stopping=engine.inspect(name)
                        engine.stop(name,ignore_missing=ignore_missing)
                        if stopping and stopping['Id'] not in (source['Id'],recovered_id) and candidate_started:
                            candidate_copy=engine.archive_auth(name); write(backup/'candidate-auth.tar',candidate_copy)
                        if name==plan['container_id'] and auth_copy is None:
                            try:
                                auth_copy=engine.archive_auth(name)
                                if auth_state(auth_copy)!=prestop_auth: raise AdoptionError('auth_store_changed_requires_quiescence')
                                write(backup/'auth.tar',auth_copy)
                                write(nginx,candidate.read_bytes())
                            except Exception:
                                _restore_registry_files(previous)
                                restart_source('cryptolabs-proxy')
                                raise AdoptionError('auth_snapshot_failed; '+('sanitized_source_recovered' if recovery_verified else 'forward_repair_required')) from None
                    def create(self,name,payload):
                        guard()
                        engine.create(name,payload)
                    def connect(self,name,network,endpoint):
                        guard()
                        # The generic switch requests source reconnect before
                        # start. Recovery deliberately defers that topology:
                        # the sanitized source is recreated with its original
                        # endpoints only after owned restore and startup proof.
                        if engine.inspect(name)['Id'] in (source['Id'],recovered_id): return
                        engine.connect(name,network,endpoint)
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
                        engine.start(name)
                        guard()
                def candidate_health(name):
                    guard()
                    ready=wait_for_proxy_ready(engine,name,lambda:engine.anonymous_auth(name,declaration['tls']),PROXY_READY_TIMEOUT)
                    if not ready: engine.stop(name,ignore_missing=True)
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
                registry.config['standard_adoption']={'plan_id':identity,'serving_sha256':_runtime_identity(engine.inspect('cryptolabs-proxy')),'declaration_sha256':plan['declaration_sha256'],'selection_sha256':plan['selection_sha256'],'auth_mount':{k:auth_mount[k] for k in ('Type','Name','Source','Destination') if k in auth_mount},'declaration':declaration}
                try: registry.save()
                except OSError:
                    write(backup/'outcome.json',_canonical({'state':'candidate_retained','reason':'registry_forward_repair_required'}))
                    return {'state':'candidate_retained','reason':'registry_forward_repair_required','plan_id':identity}
                result={'state':'adopted' if outcome.state=='applied' else 'candidate_retained','plan_id':identity,'positive_login_verified':False}
                try: write(backup/'outcome.json',_canonical(result))
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
                try: CustomConfigMigrator._write_private(backup/'outcome.json',_canonical({'state':'rolled_back' if restored else 'forward_repair_required','runtime':states,'candidate_auth_snapshot_retained':(backup/'candidate-auth.tar').exists()}))
                except OSError: pass
            reason=str(error) if isinstance(error,AdoptionError) else 'adoption_failed; inspect private recovery outcome for actual state'
            raise AdoptionError(reason) from None


    def reconfigure(self,config):
        """Ordinary setup after adoption keeps inspected state and session key."""
        try:
            registry=ServiceRegistry(self.config_dir)
            declaration=deepcopy(registry.config['standard_adoption']['declaration'])
            declaration.update(domain=config.domain,tls='letsencrypt' if config.use_letsencrypt else 'self-signed',services={n:{k:v for k,v in s.items() if k in ('container_name','path','port','display_name')} for n,s in registry.services.items()},obsolete_overlays=[],obsolete_owner_labels=[])
            if config.release_selection_dir: declaration['release_selection_dir']=str(config.release_selection_dir)
            source=self.engine.inspect('cryptolabs-proxy'); current={e.split('=',1)[0]:e.split('=',1)[1] for e in source['Config'].get('Env',[]) if '=' in e}
            environment={}
            for name,value in [('FLEET_ADMIN_USER',config.fleet_admin_user),('FLEET_ADMIN_PASS',config.fleet_admin_pass),('SITE_NAME',config.site_name),('WATCHDOG_API_KEY',config.watchdog_api_key),('WATCHDOG_URL',config.watchdog_url)]:
                if value and current.get(name)!=value: environment[name]=value
            # Session signing and internal authority keys are continuous. Their
            # default generated values in ProxyConfig are not rotation intent.
            normalized=_declaration(declaration)
            selected=targets(load(normalized['release_selection_dir']),self.engine.image(source['Image'])['Os']+'/'+self.engine.image(source['Image'])['Architecture'])['cryptolabs-proxy']
            labels=source['Config'].get('Labels') or {}
            if not environment and sha256(self.engine.read_config('cryptolabs-proxy'))==sha256(render_standard(normalized)) and labels.get('io.cryptolabs.update.reference')==selected['reference'] and labels.get('com.centurylinklabs.watchtower.enable')=='false':
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
        config=ProxyConfig(registry.config['domain'],use_letsencrypt=registry.config.get('letsencrypt',False),fleet_admin_user=environment.get('FLEET_ADMIN_USER','admin'),fleet_admin_pass=environment.get('FLEET_ADMIN_PASS',''),site_name=environment.get('SITE_NAME',''),watchdog_api_key=environment.get('WATCHDOG_API_KEY',''),watchdog_url=environment.get('WATCHDOG_URL',''),release_selection_dir=Path(registry.config['release_selection_dir']))
        return self.reconfigure(config)
