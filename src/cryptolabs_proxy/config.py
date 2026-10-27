# TRACEWEAVER: file-role=fleet-release-compose-consumer; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
"""Configuration management for CryptoLabs Proxy."""

import os
from pathlib import Path
from jinja2 import Environment, PackageLoader, select_autoescape

CONFIG_DIR = Path("/etc/cryptolabs-proxy")
_UNSET = object()


def get_jinja_env():
    """Get Jinja2 environment for templates."""
    return Environment(
        loader=PackageLoader("cryptolabs_proxy", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_nginx_config(config_dir: Path, domain: str, letsencrypt: bool = False, services: dict = None, *, host_forward_groups=None, acme_challenge=None, hostname_policy=_UNSET, http_policy=_UNSET):
    """Generate nginx.conf from template."""
    from .services import ServiceRegistry
    if host_forward_groups is None:
        host_forward_groups = ServiceRegistry(config_dir).config.get('host_forward_groups', [])
    if acme_challenge is None:
        acme_challenge = ServiceRegistry(config_dir).config.get('acme_challenge')
    if hostname_policy is _UNSET:
        hostname_policy = ServiceRegistry(config_dir).config.get("hostname_policy")
    hostname_policy = validate_hostname_policy(hostname_policy, domain)
    if http_policy is _UNSET:
        http_policy = ServiceRegistry(config_dir).config.get("http_policy")
    http_policy = validate_http_policy(http_policy, domain, acme_challenge)
    acme_challenge = validate_acme_challenge(acme_challenge)
    host_forward_groups = validate_host_forward_groups(host_forward_groups, domain)
    env = get_jinja_env()
    template = env.get_template("nginx.conf.j2")
    
    content = template.render(
        domain=domain,
        letsencrypt=letsencrypt,
        services=services or {},
        host_forward_groups=host_forward_groups,
        acme_challenge=acme_challenge,
        hostname_policy=hostname_policy,
        http_policy=http_policy,
    )
    
    (config_dir / "nginx.conf").write_text(content)


def render_vpm_fragment() -> str:
    """Render the exact VPM route shared by generated and custom configs."""
    return get_jinja_env().get_template("vast-price-manager.conf.j2").render()


def render_vpm_internal_auth_blocks() -> str:
    """Render public-Nginx blocks for Docker-only VPM Fleet auth endpoints."""
    return get_jinja_env().get_template("vast-price-manager-auth-blocks.conf.j2").render()


# TRACEWEAVER: entrypoint=generate_docker_compose; req=REQ-FLEETUPDATE-001; trace=TRACE-FLEETUPDATE-001; ver=VER-FLEETUPDATE-001
def generate_docker_compose(config_dir: Path, domain: str = None, use_letsencrypt: bool = False,
                            *, release_selection_dir=None, platform=None):
    """Generate docker-compose.yml from template."""
    env = get_jinja_env()
    template = env.get_template("docker-compose.yml.j2")
    from .release_selection import load, targets, SelectionError
    from .services import ServiceRegistry
    registry = ServiceRegistry(config_dir)
    if domain is None: domain = registry.config.get('domain')
    release_selection_dir = release_selection_dir or registry.config.get('release_selection_dir')
    http_policy = validate_http_policy(registry.config.get('http_policy'), domain, registry.config.get('acme_challenge'))
    healthcheck = policy_healthcheck(registry.config.get('standard_adoption',{}).get('healthcheck'),domain,registry.config.get('hostname_policy'),http_policy,letsencrypt=use_letsencrypt)
    health_command = healthcheck['Test'][1] if healthcheck else None
    proxy_image = 'ghcr.io/cryptolabsza/cryptolabs-proxy:latest'
    proxy_origin = None
    if release_selection_dir:
        selected = targets(load(release_selection_dir), platform)
        if 'cryptolabs-proxy' not in selected:
            raise SelectionError('proxy_required')
        proxy_image = selected['cryptolabs-proxy']['reference']
        proxy_origin = selected['cryptolabs-proxy']['origin']
    
    broker_enabled=registry.config.get('release_broker_enabled',False)
    if type(broker_enabled) is not bool: raise ValueError('release_broker_enabled must be boolean')
    content = template.render(
        release_broker_enabled=broker_enabled,
        domain=domain,
        use_letsencrypt=use_letsencrypt,
        release_selection_dir=str(Path(release_selection_dir).resolve()) if release_selection_dir else None,
        proxy_image=proxy_image,
        proxy_origin=proxy_origin,
        http_policy=http_policy,
        policy_healthcheck=health_command,
        policy_healthcheck_config=healthcheck,
    )
    
    (config_dir / "docker-compose.yml").write_text(content)


def validate_host_forward_groups(groups, domain):
    """Bounded declarative host forwarding; values never become raw directives."""
    import re
    import ipaddress
    from copy import deepcopy
    from urllib.parse import urlsplit
    host_pattern=re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
    if not isinstance(groups,list) or len(groups)>32: raise ValueError('invalid_host_forward_groups')
    seen={str(domain).lower()}; result=deepcopy(groups)
    tls_paths=re.compile(r'/etc/(?:nginx/ssl/[A-Za-z0-9_.-]+|letsencrypt/live/[a-z0-9.-]+/(?:fullchain|privkey)\.pem)')
    for group in result:
        required={'hostnames','http','https','certificate','certificate_key'}
        if not isinstance(group,dict) or set(group)-required-{'http2'} or not required<=set(group): raise ValueError('invalid_host_forward_group')
        hosts=group['hostnames']
        if not isinstance(hosts,list) or not 1<=len(hosts)<=64: raise ValueError('invalid_forward_hosts')
        for host in hosts:
            if not isinstance(host,str) or not host_pattern.fullmatch(host) or host in seen: raise ValueError('forward_hostname_collision_or_invalid')
            seen.add(host)
        for key in ('certificate','certificate_key'):
            path=group[key]
            if not isinstance(path,str) or not tls_paths.fullmatch(path) or any(part in ('.','..') for part in Path(path).parts): raise ValueError('invalid_forward_certificate_path')
        if 'http2' in group and type(group['http2']) is not bool: raise ValueError('invalid_forward_http2')
        for protocol in ('http','https'):
            settings=group[protocol]
            allowed={'origin','websocket','read_timeout_seconds','send_timeout_seconds','connect_timeout_seconds','buffering','max_body_size_mb','forwarded_proto'}
            if protocol=='https': allowed|={'verify_tls','sni','ca_certificate'}
            if not isinstance(settings,dict) or 'origin' not in settings or set(settings)-allowed: raise ValueError('invalid_forward_origin_fields')
            origin=settings['origin']
            if not isinstance(origin,str) or len(origin)>512 or any(c.isspace() for c in origin): raise ValueError('invalid_forward_origin')
            try:
                parsed=urlsplit(origin); port=parsed.port
                if parsed.scheme!=protocol or parsed.username is not None or parsed.password is not None or parsed.path or parsed.query or parsed.fragment or not parsed.hostname or port is not None and not 1<=port<=65535: raise ValueError()
                host=parsed.hostname
                try: ipaddress.ip_address(host)
                except ValueError:
                    if not host_pattern.fullmatch(host): raise ValueError()
                if any(c in origin for c in (';','{','}','\\','\x00','"',"'",'$')): raise ValueError()
            except (ValueError,TypeError): raise ValueError('invalid_forward_origin') from None
            for key in ('websocket','buffering','verify_tls','sni'):
                if key in settings and type(settings[key]) is not bool: raise ValueError('invalid_forward_boolean')
            for key,maximum in [('read_timeout_seconds',3600),('send_timeout_seconds',3600),('connect_timeout_seconds',3600),('max_body_size_mb',1024)]:
                if key in settings and (type(settings[key]) is not int or not 1<=settings[key]<=maximum): raise ValueError('invalid_forward_limit')
            if settings.get('forwarded_proto','scheme') not in ('scheme',protocol): raise ValueError('invalid_forward_proto_header')
            if 'ca_certificate' in settings:
                path=settings['ca_certificate']
                if path!='/etc/ssl/certs/ca-certificates.crt' and (not isinstance(path,str) or not tls_paths.fullmatch(path) or any(part in ('.','..') for part in Path(path).parts)): raise ValueError('invalid_forward_ca_path')
    return result


def render_host_forward_groups(groups, *, legacy_profile=False):
    return get_jinja_env().get_template('host-forwarding.conf.j2').render(host_forward_groups=groups,legacy_forward_profile=legacy_profile).encode()


def validate_acme_challenge(value):
    """Fixed ACME prefix proxy independent of the existing certificate authority."""
    if value is None: return None
    if not isinstance(value,dict) or not {'origin'}<=set(value) or set(value)-{'origin','connect_timeout_seconds','read_timeout_seconds'}: raise ValueError('invalid_acme_challenge')
    # Reuse the same bounded HTTP origin/timeout validator; no arbitrary paths.
    validate_host_forward_groups([{'hostnames':['acme.example.test'],'http':value,'https':{'origin':'https://acme.example.test'},'certificate':'/etc/nginx/ssl/server.crt','certificate_key':'/etc/nginx/ssl/server.key'}],'fleet.example.test')
    from copy import deepcopy
    return deepcopy(value)


def render_acme_challenge(value, *, legacy_profile=False):
    return get_jinja_env().get_template('acme-challenge.conf.j2').render(acme_challenge=value,legacy_forward_profile=legacy_profile).encode()


def validate_hostname_policy(policy, domain):
    """Only the observed literal-primary $host guard with fixed 444 is supported."""
    import re
    import ipaddress
    if policy is None:
        return None
    if not isinstance(policy, str) or policy != 'primary-only':
        raise ValueError('invalid_hostname_policy')
    literal = re.compile(r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+')
    if not isinstance(domain, str) or not literal.fullmatch(domain):
        raise ValueError('hostname_policy_requires_literal_domain')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return policy
    raise ValueError('hostname_policy_requires_literal_domain')


def validate_http_policy(policy, domain, acme_challenge=None):
    """Closed primary HTTPS redirect and local HTTP ACME transport."""
    if policy is None:
        return None
    if not isinstance(policy, str) or policy != 'redirect-primary-https':
        raise ValueError('invalid_http_policy')
    validate_hostname_policy('primary-only', domain)
    if acme_challenge is not None:
        raise ValueError('http_policy_local_acme_conflicts_with_upstream')
    return policy


def render_policy_healthcheck(domain, hostname_policy=None, http_policy=None, *, letsencrypt=False):
    """Public HTTPS loopback uses the declared Host/SNI; internal API stays checked.

    The stored certificate is the explicit local trust anchor. Hostname
    verification remains enabled; browser and forwarding trust are unchanged.
    """
    validate_hostname_policy(hostname_policy, domain)
    validate_http_policy(http_policy, domain)
    if hostname_policy is None and http_policy is None:
        return None
    validate_hostname_policy('primary-only', domain)
    certificate='/etc/letsencrypt/live/'+domain+'/fullchain.pem' if letsencrypt else '/etc/nginx/ssl/server.crt'
    return ('curl -fsS --cacert '+certificate+' --resolve '+domain+':443:127.0.0.1 https://'+domain+
            '/api/health && curl -f http://127.0.0.1:8080/api/health || exit 1')


def policy_healthcheck(current, domain, hostname_policy=None, http_policy=None, *, letsencrypt=False):
    """Keep the exact independently observed verified probe; map image defaults.

    Recognition compares fixed raw shell syntax, with spaces/tabs only. It
    never accepts arbitrary operations, flags, URLs, credentials or snippets.
    """
    from copy import deepcopy
    import re
    command=render_policy_healthcheck(domain,hostname_policy,http_policy,letsencrypt=letsencrypt)
    if command is None: return None
    default=['CMD-SHELL','curl -f http://localhost/api/health && curl -f http://localhost:8080/api/health || exit 1']
    if current is None: return {'Test':['CMD-SHELL',command]}
    fields={'Test','Interval','Timeout','StartPeriod','StartInterval','Retries'}
    if not isinstance(current,dict) or set(current)-fields or not isinstance(current.get('Test'),list): raise ValueError('source_healthcheck_unmapped')
    if any(type(v) is not int or not 0<=v<=2**63-1 for k,v in current.items() if k!='Test'): raise ValueError('source_healthcheck_unmapped')
    test=current['Test']
    trusted='curl -fsS --resolve '+domain+':443:127.0.0.1 https://'+domain+'/api/health >/dev/null && curl -fsS http://localhost:8080/api/health >/dev/null || exit 1'
    if len(test)==2 and test[0]=='CMD-SHELL' and isinstance(test[1],str) and len(test[1])<=4096:
        # Shell operators must remain operators, not quoted/escaped curl
        # arguments. Only spaces/tabs may vary in this closed raw skeleton.
        # The validated domain is escaped with every other literal position.
        skeleton=re.escape(trusted).replace(r'\ ',r'[ 	]+')
        if re.fullmatch(skeleton,test[1]): return deepcopy(current)
    if test not in (default,['CMD-SHELL',command]): raise ValueError('source_healthcheck_unmapped')
    result=deepcopy(current);result['Test']=['CMD-SHELL',command]
    return result
