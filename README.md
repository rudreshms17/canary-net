# Canary-Net

Canary-Net is a lightweight honeypot monitoring platform that runs fake network services, captures suspicious activity, enriches alerts with behavioral context, and presents them through a real-time dashboard.

## What it does

The project combines:

- Honeypot canaries for SSH, FTP, HTTP, and SMB-style interactions
- A monitor service that receives and validates alerts
- An alert pipeline with encryption, dispatch, and SQLite persistence
- A Flask + Socket.IO dashboard for live alert viewing
- Threat enrichment modules for scoring, proxy detection, behavior classification, and GeoIP context

## Project layout

- [main.py](main.py) - startup entry point and service orchestration
- [config.yaml](config.yaml) - runtime configuration for ports, canaries, and paths
- [canaries/](canaries/) - fake services that emit alerts when probed or attacked
- [alert_engine/](alert_engine/) - alert dispatch, encryption, and UDP/TCP transport
- [monitor/](monitor/) - monitor and listener services
- [dashboard/](dashboard/) - Flask dashboard UI and API endpoints
- [shared/](shared/) - database, crypto, configuration, threat scoring, and enrichment helpers
- [tests/](tests/) - unit and integration tests

## Features

- Multiple canary services: SSH, FTP, HTTP, and SMB
- Encrypted alert delivery and local broadcast support
- SQLite-backed alert storage with duplicate protection
- Threat scoring and alert severity mapping
- Proxy/TOR/datacenter detection hints
- Behavior classification such as scanner, brute-force, bot, or human-like activity
- GeoIP enrichment support for country-level context
- Real-time dashboard updates via WebSocket
- Startup option to clear old alerts with --fresh

## Requirements

- Python 3.10+
- See [requirements.txt](requirements.txt) for the pinned dependency list

## Quick start

### 1. Create and activate a virtual environment

On Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate an encryption key (optional on first run)

```bash
python main.py --generate-key
```

### 4. Start the full stack

```bash
python main.py --all
```

### 5. Open the dashboard

The dashboard is typically available at:

```text
http://localhost:5000
```

## Useful startup options

```bash
python main.py --monitor-only
python main.py --canaries-only
python main.py --no-dashboard
python main.py --fresh
```

## Configuration

The runtime settings are defined in [config.yaml](config.yaml). You can adjust:

- monitor host and port
- broadcast and dashboard ports
- canary enablement and ports
- database and key file locations

## Notes

- The SSH canary uses an alternate port by default to avoid conflicts with system SSH services.
- The dashboard and monitor components are designed to run together for live alert visualization.
- The database is stored in the project root by default as alerts.db.

## Development

If you want to extend the system:

1. Add a new canary under [canaries/](canaries/)
2. Wire it into [main.py](main.py)
3. Optionally add new enrichment logic under [shared/](shared/)
4. Run the test suite with:

```bash
pytest
```
