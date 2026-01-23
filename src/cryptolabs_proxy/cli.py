"""CryptoLabs Proxy CLI - Setup and manage the unified reverse proxy."""

import click
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
from .services import ServiceRegistry

console = Console()

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
    
    registry = ServiceRegistry(CONFIG_DIR)
    
    if path is None:
        path = f"/{service_name}/"
    
    registry.add_service(
        name=service_name,
        container_name=container_name,
        path=path,
        port=port,
        display_name=display_name or service_name.replace("-", " ").title(),
        icon=icon,
        description=description
    )
    
    # Regenerate nginx config
    generate_nginx_config(
        CONFIG_DIR,
        domain=registry.config.get("domain", get_local_ip()),
        letsencrypt=registry.config.get("letsencrypt", False),
        services=registry.services
    )
    
    # Reload nginx
    subprocess.run(["docker", "exec", "cryptolabs-proxy", "nginx", "-s", "reload"], capture_output=True)
    
    console.print(f"[green]✓[/green] Registered {service_name} at {path}")


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


if __name__ == "__main__":
    main()
