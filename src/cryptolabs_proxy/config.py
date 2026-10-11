"""Configuration management for CryptoLabs Proxy."""

import os
from pathlib import Path
from jinja2 import Environment, PackageLoader, select_autoescape

CONFIG_DIR = Path("/etc/cryptolabs-proxy")


def get_jinja_env():
    """Get Jinja2 environment for templates."""
    return Environment(
        loader=PackageLoader("cryptolabs_proxy", "templates"),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def generate_nginx_config(config_dir: Path, domain: str, letsencrypt: bool = False, services: dict = None, *, host_forward_groups=None, acme_challenge=None):
    """Generate nginx.conf from template."""
    from .services import ServiceRegistry
    if host_forward_groups is None:
        host_forward_groups = ServiceRegistry(config_dir).config.get('host_forward_groups', [])
    if acme_challenge is None:
        acme_challenge = ServiceRegistry(config_dir).config.get('acme_challenge')
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
    )
    
    (config_dir / "nginx.conf").write_text(content)


def render_vpm_fragment() -> str:
    """Render the exact VPM route shared by generated and custom configs."""
    return get_jinja_env().get_template("vast-price-manager.conf.j2").render()


def render_vpm_internal_auth_blocks() -> str:
    """Render public-Nginx blocks for Docker-only VPM Fleet auth endpoints."""
    return get_jinja_env().get_template("vast-price-manager-auth-blocks.conf.j2").render()


def generate_docker_compose(config_dir: Path, domain: str = None, use_letsencrypt: bool = False,
                            *, release_selection_dir=None, platform=None):
    """Generate docker-compose.yml from template."""
    env = get_jinja_env()
    template = env.get_template("docker-compose.yml.j2")
    from .release_selection import load, targets, SelectionError
    from .services import ServiceRegistry
    release_selection_dir = release_selection_dir or ServiceRegistry(config_dir).config.get('release_selection_dir')
    proxy_image = 'ghcr.io/cryptolabsza/cryptolabs-proxy:latest'
    proxy_origin = None
    if release_selection_dir:
        selected = targets(load(release_selection_dir), platform)
        if 'cryptolabs-proxy' not in selected:
            raise SelectionError('proxy_required')
        proxy_image = selected['cryptolabs-proxy']['reference']
        proxy_origin = selected['cryptolabs-proxy']['origin']
    
    content = template.render(
        domain=domain,
        use_letsencrypt=use_letsencrypt,
        release_selection_dir=str(Path(release_selection_dir).resolve()) if release_selection_dir else None,
        proxy_image=proxy_image,
        proxy_origin=proxy_origin,
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
