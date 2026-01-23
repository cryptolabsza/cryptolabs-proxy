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


def generate_nginx_config(config_dir: Path, domain: str, letsencrypt: bool = False, services: dict = None):
    """Generate nginx.conf from template."""
    env = get_jinja_env()
    template = env.get_template("nginx.conf.j2")
    
    content = template.render(
        domain=domain,
        letsencrypt=letsencrypt,
        services=services or {},
    )
    
    (config_dir / "nginx.conf").write_text(content)


def generate_docker_compose(config_dir: Path, domain: str = None, use_letsencrypt: bool = False):
    """Generate docker-compose.yml from template."""
    env = get_jinja_env()
    template = env.get_template("docker-compose.yml.j2")
    
    content = template.render(
        domain=domain,
        use_letsencrypt=use_letsencrypt,
    )
    
    (config_dir / "docker-compose.yml").write_text(content)
