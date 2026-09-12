"""CryptoLabs Proxy CLI - Setup and manage the unified reverse proxy."""

import click
import copy
from contextlib import contextmanager
import fcntl
import os
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
import questionary
import yaml

from . import __version__
from .config import CONFIG_DIR, get_jinja_env, generate_nginx_config, generate_docker_compose
from .custom_config import (
    CustomConfigError,
    custom_config_settings,
    ensure_vpm_only_change,
    load_verified_baseline,
    render_managed_vpm_config,
)
from .services import DEFAULT_SERVICES, ServiceRegistry

console = Console()

# A registry mutation can invoke the proxy container, but each command is
# bounded so a stalled Docker daemon cannot indefinitely block other lifecycle
# operations waiting for the registry lock.
NGINX_COMMAND_TIMEOUT = 15

custom_style = questionary.Style([
    ('qmark', 'fg:cyan bold'),
    ('question', 'bold'),
    ('answer', 'fg:cyan bold'),
    ('pointer', 'fg:cyan bold'),
    ('highlighted', 'fg:cyan bold'),
    ('selected', 'fg:cyan'),
])


def check_root():
    """Ensure running as root."""
    if os.geteuid() != 0:
        console.print("[red]Error:[/red] This command must be run as root (sudo)")
        sys.exit(1)


def check_docker_installed() -> bool:
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            return False
        result = subprocess.run(["docker", "info"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def install_docker():
    """Install Docker using the official convenience script."""
    console.print("\n[bold]Installing Docker...[/bold]\n")
    
    try:
        with Progress(SpinnerColumn(), TextColumn("Downloading Docker installer..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(
                ["curl", "-fsSL", "https://get.docker.com", "-o", "/tmp/get-docker.sh"],
                check=True, capture_output=True
            )
        
        with Progress(SpinnerColumn(), TextColumn("Installing Docker..."), console=console) as progress:
            progress.add_task("", total=None)
            subprocess.run(["sh", "/tmp/get-docker.sh"], check=True, capture_output=True)
        
        subprocess.run(["systemctl", "start", "docker"], capture_output=True)
        subprocess.run(["systemctl", "enable", "docker"], capture_output=True)
        
        console.print("[green]✓[/green] Docker installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        console.print(f"[red]✗[/red] Docker installation failed: {e}")
        return False


def get_local_ip() -> str:
    """Get local IP address."""
    try:
        result = subprocess.run(
            ["hostname", "-I"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ips = result.stdout.strip().split()
            if ips:
                return ips[0]
    except:
        pass
    return "127.0.0.1"


def validate_nginx_config():
    """Validate the mounted proxy configuration before asking Nginx to reload."""
    try:
        result = subprocess.run(
            ["docker", "exec", "cryptolabs-proxy", "nginx", "-t"],
            capture_output=True,
            text=True,
            timeout=NGINX_COMMAND_TIMEOUT,
        )
        return result.returncode == 0, result.stderr or result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)


def reload_nginx_config():
    """Reload Nginx and return its output to the caller."""
    try:
        result = subprocess.run(
            ["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"],
            capture_output=True,
            text=True,
            timeout=NGINX_COMMAND_TIMEOUT,
        )
        return result.returncode == 0, result.stderr or result.stdout
    except (OSError, subprocess.SubprocessError) as error:
        return False, str(error)


def proxy_uses_generated_config(config_path: Path) -> bool:
    """Confirm the active container sees exactly the generated host config.

    The image's bundled nginx.conf is a bootstrap configuration. Lifecycle
    registration is supported only for deployments that mount the generated
    config into /etc/nginx/nginx.conf; otherwise a reload would not change the
    active routes.
    """
    try:
        result = subprocess.run(
            ["docker", "exec", "cryptolabs-proxy", "cat", "/etc/nginx/nginx.conf"],
            capture_output=True,
            text=True,
            timeout=NGINX_COMMAND_TIMEOUT,
        )
        return result.returncode == 0 and config_path.read_text() == result.stdout
    except (OSError, subprocess.SubprocessError):
        return False


@contextmanager
def registry_lock(config_dir: Path):
    """Serialize lifecycle changes to one generated proxy configuration.

    The lock deliberately covers registry loading through validation, reload,
    and rollback. Docker calls made during that interval use a timeout so a
    competing install or disable action is never held behind an unbounded
    command.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    lock_path = config_dir / ".registry.lock"
    with lock_path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _snapshot_files(paths):
    return {path: path.read_bytes() if path.exists() else None for path in paths}


def _restore_files(snapshot):
    for path, content in snapshot.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)


def apply_registry_change(registry: ServiceRegistry, services: dict):
    """Persist, validate, and reload a registry mutation with file rollback.

    The route remains active until Nginx successfully reloads. If validation or
    reload fails, registry/settings/config files are restored; a failed reload
    also triggers an old-config reload attempt to make the active state match
    the restored files.
    """
    nginx_path = registry.config_dir / "nginx.conf"
    snapshot = _snapshot_files([registry.services_file, registry.config_file, nginx_path])
    try:
        if custom_config_settings(registry.config):
            ensure_vpm_only_change(registry.services, services)
            baseline = load_verified_baseline(registry.config)
            rendered_config = render_managed_vpm_config(
                baseline,
                enabled="vast-price-manager" in services,
            )
        else:
            rendered_config = None
        registry.services = services
        registry.save()
        if rendered_config is None:
            generate_nginx_config(
                registry.config_dir,
                domain=registry.config.get("domain", get_local_ip()),
                letsencrypt=registry.config.get("letsencrypt", False),
                services=registry.services,
            )
        else:
            nginx_path.write_bytes(rendered_config)
        if not proxy_uses_generated_config(nginx_path):
            raise RuntimeError(
                "Proxy is not using the generated /etc/cryptolabs-proxy/nginx.conf; "
                "route change was not applied."
            )
        valid, validation_output = validate_nginx_config()
        if not valid:
            raise RuntimeError(f"Nginx configuration validation failed: {validation_output.strip()}")
        reloaded, reload_output = reload_nginx_config()
        if reloaded:
            return True, ""

        _restore_files(snapshot)
        rollback_ok, rollback_output = reload_nginx_config()
        detail = f"Nginx reload failed: {reload_output.strip()}"
        if not rollback_ok:
            detail += f"; rollback reload also failed: {rollback_output.strip()}"
        return False, detail
    except (OSError, RuntimeError, CustomConfigError) as error:
        _restore_files(snapshot)
        return False, str(error)


# Docker network subnet for UFW rules
DOCKER_NETWORK_SUBNET = "172.30.0.0/16"


def setup_ufw(
    tcp_ports: list = None,
    udp_ports: list = None,
    enable: bool = True,
    docker_subnet: str = DOCKER_NETWORK_SUBNET
) -> bool:
    """
    Configure UFW firewall.
    
    This is the central UFW management function used by all CryptoLabs products.
    Both dc-overview and ipmi-monitor delegate to this.
    
    Args:
        tcp_ports: List of TCP ports to allow (default: [22, 80, 443])
        udp_ports: List of UDP ports to allow (e.g., [69] for TFTP/PXE)
        enable: Whether to enable UFW after configuration
        docker_subnet: Docker network to allow (for container communication)
    
    Returns:
        True if successful, False otherwise
    """
    if tcp_ports is None:
        tcp_ports = [22, 80, 443]
    if udp_ports is None:
        udp_ports = []
    
    # Check if UFW is available
    result = subprocess.run(["which", "ufw"], capture_output=True)
    if result.returncode != 0:
        console.print("[yellow]⚠[/yellow] UFW not installed")
        console.print("[dim]Install with: apt install ufw[/dim]")
        return False
    
    # Check current status
    result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    if "Status: active" in result.stdout:
        console.print("[green]✓[/green] UFW already active, adding rules...")
    
    # Set default policies
    subprocess.run(["ufw", "default", "deny", "incoming"], capture_output=True)
    subprocess.run(["ufw", "default", "allow", "outgoing"], capture_output=True)
    
    # Allow TCP ports
    for port in tcp_ports:
        subprocess.run(["ufw", "allow", str(port)], capture_output=True)
    
    # Allow UDP ports
    for port in udp_ports:
        subprocess.run(["ufw", "allow", f"{port}/udp"], capture_output=True)
    
    # Allow Docker network
    if docker_subnet:
        subprocess.run(
            ["ufw", "allow", "from", docker_subnet, "comment", "Docker cryptolabs network"],
            capture_output=True
        )
    
    # Enable UFW
    if enable:
        result = subprocess.run(
            ["ufw", "--force", "enable"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[red]✗[/red] Failed to enable UFW: {result.stderr[:100]}")
            return False
    
    console.print("[green]✓[/green] UFW firewall configured")
    return True


def get_ufw_config_path() -> Path:
    """Get path to UFW configuration file."""
    return CONFIG_DIR / "ufw-ports.yaml"


def load_ufw_ports() -> dict:
    """Load UFW port configuration."""
    config_path = get_ufw_config_path()
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {"tcp": [22, 80, 443], "udp": []}


def save_ufw_ports(tcp_ports: list, udp_ports: list):
    """Save UFW port configuration."""
    config_path = get_ufw_config_path()
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        yaml.dump({"tcp": tcp_ports, "udp": udp_ports}, f)


@click.group()
@click.version_option(version=__version__, prog_name="cryptolabs-proxy")
def main():
    """CryptoLabs Proxy - Unified reverse proxy for CryptoLabs products."""
    pass


@main.command()
def setup():
    """Interactive setup wizard for the proxy."""
    check_root()
    
    console.print()
    console.print(Panel(
        "[bold cyan]CryptoLabs Proxy Setup[/bold cyan]\n\n"
        "Unified reverse proxy for CryptoLabs products.\n"
        "Provides fleet management dashboard with auto-detection of services.\n\n"
        "[dim]Press Ctrl+C to cancel at any time.[/dim]",
        border_style="cyan"
    ))
    console.print()
    
    # Check Docker
    if not check_docker_installed():
        console.print("[yellow]Docker is not installed.[/yellow]")
        install = questionary.confirm(
            "Install Docker now?",
            default=True,
            style=custom_style
        ).ask()
        
        if install:
            if not install_docker():
                console.print("[red]Cannot continue without Docker.[/red]")
                return
        else:
            console.print("[red]Cannot continue without Docker.[/red]")
            return
    else:
        console.print("[green]✓[/green] Docker is installed")
    
    local_ip = get_local_ip()
    
    # Domain setup
    console.print("\n[bold]Domain Configuration[/bold]\n")
    
    setup_ssl = questionary.confirm(
        "Configure HTTPS with SSL?",
        default=True,
        style=custom_style
    ).ask()
    
    domain = None
    use_letsencrypt = False
    
    if setup_ssl:
        domain = questionary.text(
            "Domain name (leave empty for IP-based access):",
            default="",
            style=custom_style
        ).ask()
        
        if domain:
            use_letsencrypt = questionary.confirm(
                f"Get Let's Encrypt certificate for {domain}?",
                default=True,
                style=custom_style
            ).ask()
    
    # Create config directory
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    
    # Initialize service registry
    registry = ServiceRegistry(CONFIG_DIR)
    registry.save()
    
    # Generate nginx config
    generate_nginx_config(
        CONFIG_DIR,
        domain=domain or local_ip,
        letsencrypt=use_letsencrypt,
        services=registry.services
    )
    console.print("[green]✓[/green] Nginx configuration generated")
    
    # Generate docker-compose
    generate_docker_compose(
        CONFIG_DIR,
        domain=domain,
        use_letsencrypt=use_letsencrypt
    )
    console.print("[green]✓[/green] Docker Compose configuration generated")
    
    # Generate SSL certs if needed
    if setup_ssl and not use_letsencrypt:
        from .ssl import generate_self_signed_cert
        generate_self_signed_cert(CONFIG_DIR / "ssl", domain or local_ip)
        console.print("[green]✓[/green] Self-signed certificate generated")
    
    # Pull and start
    console.print("\n[bold]Starting Proxy...[/bold]\n")
    
    with Progress(SpinnerColumn(), TextColumn("Pulling proxy image..."), console=console) as progress:
        progress.add_task("", total=None)
        subprocess.run(
            ["docker", "pull", "ghcr.io/cryptolabsza/cryptolabs-proxy:latest"],
            capture_output=True
        )
    
    subprocess.run(
        ["docker", "compose", "-f", str(CONFIG_DIR / "docker-compose.yml"), "up", "-d"],
        capture_output=True,
        cwd=str(CONFIG_DIR)
    )
    
    console.print("[green]✓[/green] Proxy started")
    
    # Summary
    console.print()
    console.print(Panel(
        "[bold green]✓ Setup Complete![/bold green]",
        border_style="green"
    ))
    
    if domain:
        url = f"https://{domain}/"
    elif setup_ssl:
        url = f"https://{local_ip}/"
    else:
        url = f"http://{local_ip}/"
    
    # Firewall setup
    console.print("\n[bold]Firewall Configuration[/bold]\n")
    
    enable_ufw = questionary.confirm(
        "Enable UFW firewall?",
        default=True,
        style=custom_style
    ).ask()
    
    tcp_ports = [22, 80, 443]
    udp_ports = []
    
    if enable_ufw:
        has_additional = questionary.confirm(
            "Do you have additional services needing ports? (e.g., Docker Registry, PXE)",
            default=False,
            style=custom_style
        ).ask()
        
        if has_additional:
            console.print("\n[dim]Examples: Docker Registry (5000), PXE web (3001, 8888)[/dim]")
            tcp_str = questionary.text(
                "Additional TCP ports (comma-separated):",
                default="",
                style=custom_style
            ).ask() or ""
            
            if tcp_str.strip():
                try:
                    extra_tcp = [int(p.strip()) for p in tcp_str.split(",") if p.strip().isdigit()]
                    tcp_ports.extend(extra_tcp)
                except ValueError:
                    pass
            
            console.print("\n[dim]Examples: TFTP/PXE (69), DNS (53)[/dim]")
            udp_str = questionary.text(
                "UDP ports (comma-separated):",
                default="",
                style=custom_style
            ).ask() or ""
            
            if udp_str.strip():
                try:
                    udp_ports = [int(p.strip()) for p in udp_str.split(",") if p.strip().isdigit()]
                except ValueError:
                    pass
        
        # Save and apply
        save_ufw_ports(tcp_ports, udp_ports)
        setup_ufw(tcp_ports=tcp_ports, udp_ports=udp_ports, enable=True)
    
    console.print(f"\n[bold]Fleet Management:[/bold] {url}")
    console.print(f"[bold]Config Directory:[/bold] {CONFIG_DIR}")
    console.print("\n[dim]Services will be auto-detected when they start.[/dim]")


@main.command()
@click.argument("service_name")
@click.argument("container_name")
@click.option("--path", "-p", default=None, help="URL path (e.g., /ipmi/)")
@click.option("--port", default=5000, help="Internal port")
@click.option("--display-name", "-n", default=None, help="Display name")
@click.option("--icon", "-i", default="🔧", help="Icon emoji")
@click.option("--description", "-d", default="", help="Service description")
def register(service_name, container_name, path, port, display_name, icon, description):
    """Register a service with the proxy."""
    check_root()
    with registry_lock(CONFIG_DIR):
        registry = ServiceRegistry(CONFIG_DIR)

        if path is None:
            path = f"/{service_name}/"
        services = copy.deepcopy(registry.services)
        service = copy.deepcopy(services.get(service_name, {}))
        defaults = DEFAULT_SERVICES.get(service_name, {})
        service.update({
            "container_name": container_name,
            "path": path,
            "port": port,
            "display_name": display_name or defaults.get("display_name") or service_name.replace("-", " ").title(),
            "icon": icon if icon != "🔧" else defaults.get("icon", icon),
            "description": description or defaults.get("description", ""),
        })
        # VPM registration is intentionally narrow: the route fragment has one
        # fixed container/path/port contract, so retain every canonical field
        # even when the installer invokes the generic CLI command.
        if service_name == "vast-price-manager":
            service = copy.deepcopy(defaults)
        services[service_name] = service
        applied, message = apply_registry_change(registry, services)
    if not applied:
        raise click.ClickException(message)
    console.print(f"[green]✓[/green] Registered {service_name} at {path}")


@main.command()
@click.argument("service_name")
def unregister(service_name):
    """Remove a service route while preserving unrelated proxy settings."""
    check_root()
    with registry_lock(CONFIG_DIR):
        registry = ServiceRegistry(CONFIG_DIR)
        if service_name not in registry.services:
            console.print(f"[yellow]•[/yellow] {service_name} is not registered")
            return

        services = copy.deepcopy(registry.services)
        del services[service_name]
        applied, message = apply_registry_change(registry, services)
    if not applied:
        raise click.ClickException(message)
    console.print(f"[green]✓[/green] Unregistered {service_name}")


@main.command()
def status():
    """Show status of all services."""
    registry = ServiceRegistry(CONFIG_DIR)
    health = registry.check_health()
    
    console.print("\n[bold]CryptoLabs Proxy Status[/bold]\n")
    
    # Proxy status
    proxy_running = health.get("proxy", {}).get("running", False)
    proxy_status = "[green]Running[/green]" if proxy_running else "[red]Stopped[/red]"
    console.print(f"  🔀 Proxy: {proxy_status}")
    
    console.print("\n[bold]Registered Services:[/bold]\n")
    
    for name, service in registry.services.items():
        svc_health = health.get(name, {})
        running = svc_health.get("running", False)
        healthy = svc_health.get("healthy", False)
        
        if running and healthy:
            status = "[green]✓ Healthy[/green]"
        elif running:
            status = "[yellow]⚠ Running[/yellow]"
        else:
            status = "[red]✗ Stopped[/red]"
        
        console.print(f"  {service.get('icon', '🔧')} {service.get('display_name', name)}: {status}")
        console.print(f"      Path: {service.get('path', '/')}")
    
    console.print()


@main.command()
def logs():
    """View proxy logs."""
    subprocess.run(["docker", "logs", "-f", "--tail", "100", "cryptolabs-proxy"])


@main.command()
def reload():
    """Reload nginx configuration."""
    check_root()
    result = subprocess.run(
        ["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        console.print("[green]✓[/green] Nginx reloaded")
    else:
        console.print(f"[red]✗[/red] Reload failed: {result.stderr}")


@main.group()
def firewall():
    """Manage UFW firewall rules."""
    pass


@firewall.command("status")
def firewall_status():
    """Show current firewall status and rules."""
    result = subprocess.run(["ufw", "status", "verbose"], capture_output=True, text=True)
    if result.returncode == 0:
        console.print("\n[bold]UFW Firewall Status[/bold]\n")
        console.print(result.stdout)
    else:
        console.print("[yellow]UFW not available[/yellow]")
    
    # Show saved config
    ports = load_ufw_ports()
    console.print("\n[bold]Configured Ports (cryptolabs-proxy)[/bold]")
    console.print(f"  TCP: {ports.get('tcp', [])}")
    console.print(f"  UDP: {ports.get('udp', [])}")


@firewall.command("add")
@click.argument("port", type=int)
@click.option("--udp", is_flag=True, help="Add as UDP port instead of TCP")
def firewall_add(port: int, udp: bool):
    """Add a port to the firewall allow list."""
    check_root()
    
    ports = load_ufw_ports()
    protocol = "udp" if udp else "tcp"
    port_list = ports.get(protocol, [])
    
    if port in port_list:
        console.print(f"[yellow]Port {port}/{protocol} already allowed[/yellow]")
        return
    
    port_list.append(port)
    ports[protocol] = port_list
    save_ufw_ports(ports.get("tcp", [22, 80, 443]), ports.get("udp", []))
    
    # Apply to UFW
    if udp:
        subprocess.run(["ufw", "allow", f"{port}/udp"], capture_output=True)
    else:
        subprocess.run(["ufw", "allow", str(port)], capture_output=True)
    
    console.print(f"[green]✓[/green] Added port {port}/{protocol}")


@firewall.command("remove")
@click.argument("port", type=int)
@click.option("--udp", is_flag=True, help="Remove UDP port instead of TCP")
def firewall_remove(port: int, udp: bool):
    """Remove a port from the firewall allow list."""
    check_root()
    
    ports = load_ufw_ports()
    protocol = "udp" if udp else "tcp"
    port_list = ports.get(protocol, [])
    
    if port not in port_list:
        console.print(f"[yellow]Port {port}/{protocol} not in allow list[/yellow]")
        return
    
    port_list.remove(port)
    ports[protocol] = port_list
    save_ufw_ports(ports.get("tcp", [22, 80, 443]), ports.get("udp", []))
    
    # Remove from UFW
    if udp:
        subprocess.run(["ufw", "delete", "allow", f"{port}/udp"], capture_output=True)
    else:
        subprocess.run(["ufw", "delete", "allow", str(port)], capture_output=True)
    
    console.print(f"[green]✓[/green] Removed port {port}/{protocol}")


@firewall.command("apply")
def firewall_apply():
    """Apply saved firewall configuration."""
    check_root()
    
    ports = load_ufw_ports()
    tcp_ports = ports.get("tcp", [22, 80, 443])
    udp_ports = ports.get("udp", [])
    
    setup_ufw(tcp_ports=tcp_ports, udp_ports=udp_ports, enable=True)
    
    console.print("\n[bold]Applied Ports:[/bold]")
    console.print(f"  TCP: {tcp_ports}")
    console.print(f"  UDP: {udp_ports}")


if __name__ == "__main__":
    main()
