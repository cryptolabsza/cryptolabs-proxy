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

- **cryptolabs-watchtower** - Auto-updates cryptolabs-proxy (primary) and other labeled containers (dc-overview, ipmi-monitor, etc.)
- **Fleet Management Dashboard** - Landing page showing all CryptoLabs services
- **Unified Authentication** - Single login for all services
- **Site Name Branding** - Customize landing page with your datacenter name
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
apt install pipx -y && pipx ensurepath
source ~/.bashrc
pipx install cryptolabs-proxy
sudo cryptolabs-proxy setup
```

## Authentication Configuration

Authentication credentials are configured via environment variables or through the quickstart config file:

| Variable | Description | Default |
|----------|-------------|---------|
| `FLEET_ADMIN_USER` | Admin username | `admin` |
| `FLEET_ADMIN_PASS` | Admin password | **Required** |
| `SITE_NAME` | Site name for landing page branding | `DC Overview` |
| `AUTH_SECRET_KEY` | Token signing key | Auto-generated |
| `AUTH_DATA_DIR` | Auth data directory | `/data/auth` |

**Important:** You must set `FLEET_ADMIN_PASS` - there is no default password.

When using the quickstart config file, set these in your YAML:

```yaml
site_name: My Datacenter       # Appears in landing page title
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

## DC Watchdog Integration

Fleet Management provides seamless integration with DC Watchdog for uptime monitoring.

### How It Works

When a user clicks "Enable DC Watchdog" in the Fleet Management UI:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  First-Time Setup (No API Key)                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. User clicks "Enable DC Watchdog"                                        │
│     └── Fleet checks /data/auth/watchdog_api_key → empty                   │
│                                                                              │
│  2. Redirect to WordPress signup:                                            │
│     https://cryptolabs.co.za/dc-watchdog-signup/                            │
│       ?redirect_uri=https://your-fleet.local/auth/watchdog/callback         │
│       &source=fleet_management                                               │
│                                                                              │
│  3. User logs in / creates account on WordPress                              │
│     └── Clicks "Start Free Trial"                                           │
│     └── WordPress generates API key (sk-ipmi-xxx)                           │
│                                                                              │
│  4. WordPress redirects back with API key:                                   │
│     https://your-fleet.local/auth/watchdog/callback?api_key=sk-ipmi-xxx     │
│                                                                              │
│  5. Fleet saves API key to /data/auth/watchdog_api_key                      │
│                                                                              │
│  6. Auto-SSO to DC Watchdog dashboard (no manual login needed!)             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│  Returning User (API Key Already Saved)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. User clicks "DC Watchdog" → API key loaded from storage                 │
│  2. Fleet generates signed SSO token (using API key as secret)              │
│  3. Redirect to watchdog.cryptolabs.co.za/auth/sso                          │
│  4. Instant dashboard access (no WordPress redirect!)                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### DC Watchdog Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /auth/watchdog/sso` | Generate SSO URL and redirect to DC Watchdog |
| `GET /auth/watchdog/sso-url` | Get SSO URL as JSON (for JavaScript) |
| `GET /auth/watchdog/callback` | OAuth-style callback from WordPress signup |
| `GET /auth/watchdog/status` | Check DC Watchdog configuration status |
| `POST /auth/watchdog/deploy-agents` | Deploy agents to all servers via dc-overview |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WATCHDOG_API_KEY` | Pre-configured API key (optional, requires SSO verification) | (none) |
| `WATCHDOG_URL` | DC Watchdog server URL | `https://watchdog.cryptolabs.co.za` |

### First-Time SSO Requirement

Even if `WATCHDOG_API_KEY` is provided via environment variable (e.g., from dc-overview quickstart), users must complete the SSO flow at least once to verify their account. This is enforced by:

1. **Persistent verification flag** (`/data/auth/watchdog_verified`) - Only set after SSO completion
2. **Status endpoint checks** - Returns `not_configured` until verification is complete
3. **UI enforcement** - Shows "Link Account" button until verified

This ensures users explicitly authorize DC Watchdog integration, even when API keys are pre-provisioned.

### Agent Deployment

Once DC Watchdog is enabled, you can deploy agents to all your servers:

1. Click "Deploy Agents" in the Fleet Management UI
2. Agents are installed via SSH to each configured server
3. Agents send heartbeats every 30 seconds to DC Watchdog
4. If a server stops responding, you get alerts via email, Telegram, push, or app

## Development Status

### Implemented Features ✓

| Feature | Status |
|---------|--------|
| Fleet Management landing page | ✓ Complete |
| Unified authentication | ✓ Complete |
| DC Watchdog SSO integration | ✓ Complete |
| First-time SSO verification enforcement | ✓ Complete |
| "Cloud Service" label for DC Watchdog | ✓ Complete |
| Duplicate card prevention (System Updates) | ✓ Complete |
| `key_invalid` state with "Re-link Account" prompt | ✓ Complete |
| Agent deployment status display | ✓ Complete |

### Pending Features (In Development)

| Feature | Status |
|---------|--------|
| Token renewal UI feedback | ⏳ Future |
| Subscription expiry warning banner | ⏳ Future |

## Related Projects

| Project | Description |
|---------|-------------|
| [DC Overview](https://github.com/cryptolabsza/dc-overview) | Full datacenter monitoring with GPU metrics, Prometheus & Grafana |
| [IPMI Monitor](https://github.com/cryptolabsza/ipmi-monitor) | IPMI/BMC hardware monitoring, SEL logs, ECC tracking |
| [DC Exporter](https://github.com/cryptolabsza/dc-exporter-releases) | Standalone GPU metrics exporter for Prometheus |
| [DC Watchdog](https://github.com/cryptolabsza/dc-watchdog) | External uptime monitoring with multi-channel alerts |

## Changelog

### v1.1.1 (Feb 2026) - DC Watchdog Integration

**SSO & Verification:**
- First-time SSO verification enforcement (even with pre-configured API key)
- Persistent verification flag (`/data/auth/watchdog_verified`)
- "Link Account" button until SSO is completed

**UI Improvements:**
- "Cloud Service" label for CryptoLabs-hosted services
- Fixed duplicate DC Watchdog cards in System Updates
- `key_invalid` state displays "Re-link Account" when API key expires
- `agents_installed` state shows installed agents waiting for heartbeats

**Backend:**
- Prioritized file-based API key storage over environment variables
- Added key validation against WordPress API
- Propagated `keyError` state to frontend for proper UI handling

### v1.0.0 (Jan 2026) - Initial Release

- Fleet Management landing page
- Unified authentication for all services
- DC Watchdog SSO flow
- Agent deployment via dc-overview

## License

MIT License - See [LICENSE](LICENSE) for details.

## Links

- [CryptoLabs](https://cryptolabs.co.za)
- [Documentation](https://cryptolabs.co.za/dc-monitoring/)
