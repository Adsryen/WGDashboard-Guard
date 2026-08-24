# WGDashboard-Guard

[中文 README](README.md) · English

A WireGuard web administration dashboard with network policy, forwarding audit, alerting, and deployment enhancements.

> This project is a community-maintained fork and secondary development based on [WGDashboard](https://github.com/donaldzou/WGDashboard). Many thanks to upstream author Donald Zou and the WGDashboard community for the original project and ongoing maintenance.

## Project scope

WGDashboard-Guard is not affiliated with the official WireGuard project and does not represent upstream WGDashboard. The main additions include:

- Network policy management and runtime synchronization
- Forwarded-flow audit records, fuzzy filtering, and alerts
- Tunnel-network and policy-target classification
- TOTP multi-factor authentication and trusted device sessions
- Optional HTTPS certificate loading
- Native systemd and Docker Compose deployment

## Quick deployment

### Option 1: Native Ubuntu/Debian installation

Run this on a fresh Ubuntu or Debian host. The installer installs Python, WireGuard tools, and dependencies, copies the current checkout to `/opt/WGDashboard`, creates a systemd service, and preserves existing configuration and data.

```bash
git clone https://github.com/Adsryen/WGDashboard-Guard.git
cd WGDashboard-Guard
sudo ./scripts/install.sh
```

Check the service:

```bash
sudo systemctl status wg-dashboard
sudo journalctl -u wg-dashboard -f
```

The default dashboard port is `10086`: `http://server-address:10086`.

Use another installation directory with:

```bash
sudo ./scripts/install.sh --install-dir /srv/WGDashboard
```

The installer preserves `src/wg-dashboard.ini`, `src/db/`, `src/download/`, `src/backup/`, `src/log/`, and `src/ssl/`.

### Option 2: Docker Compose

Docker Engine and Docker Compose v2 are required:

```bash
git clone https://github.com/Adsryen/WGDashboard-Guard.git
cd WGDashboard-Guard
cp docker/.env.example .env
docker compose --env-file .env -f docker/compose.yaml up -d --build
```

Open `http://server-address:10086` after the container becomes healthy.

```bash
docker compose --env-file .env -f docker/compose.yaml ps
docker compose --env-file .env -f docker/compose.yaml logs -f wgdashboard
docker compose --env-file .env -f docker/compose.yaml down
```

See [`docker/README.md`](docker/README.md) for Docker configuration details and [`docker/.env.example`](docker/.env.example) for the environment template.

## Configuration and security

- The dashboard defaults to HTTP. For production, put it behind an HTTPS reverse proxy or restrict the management port to VPN/LAN networks.
- `51820/udp` is the WireGuard port. The dashboard management port is normally `10086/tcp`; they are separate services.
- When TOTP is enabled, users can choose “Trust this device”. The trusted-session lifetime is configurable in Dashboard settings.
- Never commit `wg-dashboard.ini`, `.env`, TOTP secrets, private keys, or databases.
- Before installing a firewall restriction, confirm that the current management source is allowed so you do not lock yourself out.

See [`docs/network-audit.md`](docs/network-audit.md) for audit behavior and [`docs/network-policy.md`](docs/network-policy.md) for network policy behavior.

## Updating and backups

Native installation:

```bash
cd WGDashboard-Guard
git pull
sudo ./scripts/install.sh
```

Docker:

```bash
git pull
docker compose --env-file .env -f docker/compose.yaml up -d --build
```

Before upgrading, back up native configuration, databases, and WireGuard configurations, or the Docker `data`, `conf`, and `aconf` volumes.

## Development

Backend dependencies are listed in [`src/requirements.txt`](src/requirements.txt), and frontend sources are under `src/static/app/`. Before submitting changes, run at least:

```bash
python3 -m unittest discover -s tests
docker compose --env-file .env -f docker/compose.yaml config
```

## Upstream and license

- Upstream project: [WGDashboard](https://github.com/donaldzou/WGDashboard)
- Upstream website: [wgdashboard.dev](https://wgdashboard.dev)
- License: [Apache License 2.0](LICENSE)
- Security policy: [SECURITY.md](SECURITY.md)

Thanks again to the upstream WGDashboard project and its contributors. Guard audit, policy, and deployment enhancements are maintained in this repository.
