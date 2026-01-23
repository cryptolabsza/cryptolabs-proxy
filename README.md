# CryptoLabs Proxy

Unified reverse proxy and fleet management landing page for CryptoLabs products.

## Features

- **Fleet Management Dashboard** - Landing page showing all CryptoLabs services
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

```bash
# Install
pip install cryptolabs-proxy

# Setup (run as root)
sudo cryptolabs-proxy setup
```

## Usage with IPMI Monitor

When installing IPMI Monitor, the quickstart will automatically use cryptolabs-proxy:

```bash
pipx install ipmi-monitor
sudo ~/.local/bin/ipmi-monitor quickstart
```

## Usage with DC Overview

```bash
pipx install dc-overview
sudo ~/.local/bin/dc-overview quickstart
```

## Manual Docker Deployment

```bash
docker run -d \
  --name cryptolabs-proxy \
  -p 80:80 -p 443:443 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v cryptolabs_ssl:/etc/nginx/ssl \
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

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Fleet management landing page |
| `GET /api/health` | Health status of all services |
| `GET /api/services` | List of registered services |

## License

MIT License - See [LICENSE](LICENSE) for details.

## Links

- [CryptoLabs](https://cryptolabs.co.za)
- [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor)
- [DC Overview](https://github.com/cryptolabsza/dc-overview)
