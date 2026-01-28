# CryptoLabs Proxy

Unified reverse proxy and fleet management landing page for CryptoLabs products. **This is the central entry point** that manages authentication and routing for all CryptoLabs services.

## Architecture

```
                    ┌─────────────────────────────────┐
                    │      CryptoLabs Proxy           │
                    │   (Landing Page & Auth)         │
                    │                                 │
   User → HTTPS ───►│  ┌─────────────────────────┐   │
                    │  │ Unified Authentication  │   │
                    │  └─────────────────────────┘   │
                    │              │                  │
                    └──────────────┼──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
              ▼                    ▼                    ▼
        ┌──────────┐        ┌──────────┐        ┌──────────┐
        │  /ipmi/  │        │   /dc/   │        │/grafana/ │
        │   IPMI   │        │    DC    │        │ Grafana  │
        │ Monitor  │        │ Overview │        │          │
        └──────────┘        └──────────┘        └──────────┘
```

## Features

- **Fleet Management Dashboard** - Landing page showing all CryptoLabs services
- **Unified Authentication** - Single login for all services
- **Auto-Detection** - Automatically detects running services via Docker
- **Health Checks** - Real-time health status for all containers
- **Cross-Promotion** - Promotes other CryptoLabs products when not installed
- **SSL Support** - Let's Encrypt and self-signed certificate support
- **Subpath Routing** - Route to services via `/ipmi/`, `/dc/`, `/grafana/`, etc.

## Supported Services

| Service | Path | Description |
|---------|------|-------------|
| IPMI Monitor | `/ipmi/` | Server hardware monitoring |
| DC Overview | `/dc/` | Datacenter overview dashboard |
| Grafana | `/grafana/` | Metrics visualization |
| Prometheus | `/prometheus/` | Metrics collection (with auth) |

## Quick Start

The easiest way to deploy is through **DC Overview** or **IPMI Monitor** quickstart, which automatically sets up cryptolabs-proxy:

### Option 1: Deploy with DC Overview (Full Monitoring Stack)

```bash
# Install from dev branch
pip install git+https://github.com/cryptolabsza/dc-overview.git@dev --break-system-packages

# Run quickstart with config file
sudo dc-overview quickstart -c /path/to/config.yaml -y
```

### Option 2: Deploy with IPMI Monitor (IPMI/BMC Only)

```bash
# Install from dev branch
pip install git+https://github.com/cryptolabsza/ipmi-monitor.git@dev --break-system-packages

# Run quickstart with config file
sudo ipmi-monitor quickstart -c /path/to/config.yaml -y
```

### Option 3: Standalone Installation

```bash
pip install cryptolabs-proxy
sudo cryptolabs-proxy setup
```

## Authentication Configuration

Authentication credentials are configured via environment variables or through the quickstart config file:

| Variable | Description | Default |
|----------|-------------|---------|
| `FLEET_ADMIN_USER` | Admin username | `admin` |
| `FLEET_ADMIN_PASS` | Admin password | **Required** |
| `AUTH_SECRET_KEY` | Token signing key | Auto-generated |
| `AUTH_DATA_DIR` | Auth data directory | `/data/auth` |

**Important:** You must set `FLEET_ADMIN_PASS` - there is no default password.

When using the quickstart config file, set these in your YAML:

```yaml
fleet_admin_user: admin
fleet_admin_pass: YOUR_ADMIN_PASSWORD
```

## Manual Docker Deployment

```bash
docker run -d \
  --name cryptolabs-proxy \
  -p 80:80 -p 443:443 \
  -e FLEET_ADMIN_USER=admin \
  -e FLEET_ADMIN_PASS=YOUR_ADMIN_PASSWORD \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v cryptolabs_ssl:/etc/nginx/ssl \
  -v cryptolabs_auth:/data/auth \
  ghcr.io/cryptolabsza/cryptolabs-proxy:latest
```

## Configuration

Config files are stored in `/etc/cryptolabs-proxy/`:

```
/etc/cryptolabs-proxy/
├── nginx.conf          # Nginx configuration
├── services.yaml       # Registered services
└── ssl/                # SSL certificates
```

User authentication data is stored in `/data/auth/`:

```
/data/auth/
├── users.json          # User database (hashed passwords)
└── sessions/           # Active sessions
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Fleet management landing page |
| `GET /api/health` | Health status of all services |
| `GET /api/services` | List of registered services |
| `POST /auth/login` | Authentication endpoint |
| `POST /auth/logout` | Logout endpoint |

## Related Projects

| Project | Description |
|---------|-------------|
| [DC Overview](https://github.com/cryptolabsza/dc-overview) | Full datacenter monitoring with GPU metrics, Prometheus & Grafana |
| [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor) | IPMI/BMC hardware monitoring, SEL logs, ECC tracking |
| [DC Exporter](https://github.com/cryptolabsza/dc-exporter-releases) | Standalone GPU metrics exporter for Prometheus |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Links

- [CryptoLabs](https://cryptolabs.co.za)
- [Documentation](https://cryptolabs.co.za/dc-monitoring/)
