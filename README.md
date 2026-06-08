# Canary-Net: Distributed Honeypot Network Monitor

A distributed honeypot monitoring system that deploys fake services (canaries) across a network, detects unauthorized access attempts, and alerts a central monitoring station with encrypted alert transmission.

## Project Overview

**Canary-Net** is a Python-based security monitoring framework consisting of:

- **Canaries**: Fake service listeners (SSH, FTP, HTTP) that mimic real services to detect reconnaissance and attack attempts
- **Alert Engine**: Encrypts and dispatches security alerts using AES-256-GCM
- **Central Monitor**: Aggregates and processes alerts from all canary services
- **Dashboard**: Real-time web UI for viewing alerts and security events
- **Shared Modules**: Common cryptographic utilities and data models

## Architecture

```
┌─────────────────────────────────────────────┐
│         Canary Services                     │
│  (SSH, FTP, HTTP on alternate ports)        │
└──────────────────┬──────────────────────────┘
                   │ (encrypted alerts)
┌──────────────────▼──────────────────────────┐
│      Alert Engine                           │
│  (Encryption + Dispatch)                    │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│    Central Monitor Server                   │
│  (Alert aggregation & processing)           │
└──────────────────┬──────────────────────────┘
                   │
┌──────────────────▼──────────────────────────┐
│    Dashboard (Flask + SocketIO)             │
│  (Real-time alert visualization)            │
└─────────────────────────────────────────────┘
```

## Project Structure

```
canary-net/
├── canaries/              # Honeypot services
│   ├── __init__.py
│   ├── ssh_canary.py      # SSH honeypot
│   ├── ftp_canary.py      # FTP honeypot
│   └── http_canary.py     # HTTP honeypot
├── alert_engine/          # Alert encryption & dispatch
│   ├── __init__.py
│   ├── crypto.py          # AES-256-GCM encryption
│   └── dispatcher.py      # Alert transmission
├── monitor/               # Central monitoring
│   ├── __init__.py
│   └── server.py          # Monitor server
├── dashboard/             # Web UI
│   ├── __init__.py
│   └── app.py             # Flask application
├── shared/                # Shared utilities
│   ├── __init__.py
│   └── models.py          # Data models
├── config.yaml            # Configuration (ports, keys, etc.)
├── requirements.txt       # Python dependencies
├── main.py               # Entry point
└── README.md             # This file
```

## Requirements

- **Python**: 3.11 or higher
- **Dependencies** (see requirements.txt):
  - `cryptography` - AES-256-GCM encryption
  - `flask` - Dashboard web framework
  - `flask-socketio` - Real-time WebSocket communication
  - `pyyaml` - Configuration file parsing
  - `scapy` - Network packet manipulation
  - `paramiko` - SSH protocol implementation
  - `pyftpdlib` - FTP server implementation
  - `colorama` - Terminal colors
  - `sqlalchemy` - Database ORM

## Installation

### 1. Clone/Navigate to Project
```bash
cd canary-net
```

### 2. Create Virtual Environment (Recommended)
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure System
Edit `config.yaml` to set:
- Monitor server host/port
- Canary service ports
- Encryption key (via environment variable)
- Dashboard settings

## Configuration

### config.yaml

Key configuration sections:

```yaml
monitor:
  host: 127.0.0.1      # Monitor bind address
  port: 5000           # Monitor port

canaries:
  ssh:
    port: 2222         # SSH honeypot port
  ftp:
    port: 2121         # FTP honeypot port
  http:
    port: 8080         # HTTP honeypot port

dashboard:
  host: 0.0.0.0
  port: 5001
```

### Environment Variables

```bash
# Set encryption key
export CANARY_ENCRYPTION_KEY=your-256-bit-key
```

## Usage

### Start All Services
```bash
python main.py --all
```

### Start Individual Services

```bash
# Monitor Server
python main.py --monitor

# Dashboard
python main.py --dashboard

# Canaries
python main.py --canaries
```

### Monitor Dashboard
Access the web UI at: `http://localhost:5001`

## Features

- ✅ **Multi-service honeypots** - SSH, FTP, HTTP services
- ✅ **Encrypted alerts** - AES-256-GCM encryption
- ✅ **Real-time monitoring** - WebSocket-based dashboard
- ✅ **Centralized logging** - SQLite alert database
- ✅ **Modular design** - Easy to extend with new canaries
- ✅ **Alert history** - Persistent storage and replay

## Development

### Add a New Canary Service

1. Create new file in `canaries/` (e.g., `dns_canary.py`)
2. Implement `AlertCanary` base interface
3. Register in `config.yaml`
4. Update `main.py` to instantiate new service

### Add Alert Handlers

```python
from monitor.server import MonitorServer

server = MonitorServer()

def my_handler(alert):
    print(f"Security Alert: {alert['event']}")

server.register_handler(my_handler)
```

## Security Considerations

- ⚠️ **Key Management**: Store encryption keys securely (use environment variables or key management services)
- ⚠️ **Network Security**: Run canaries behind firewalls; only expose through secure channels
- ⚠️ **Authentication**: Add authentication to dashboard before production deployment
- ⚠️ **Logging**: Configure appropriate log retention policies

## Troubleshooting

### Port Already in Use
```bash
# Windows
netstat -ano | findstr :PORT

# Linux/macOS
lsof -i :PORT
```

### Encryption Key Issues
Ensure `CANARY_ENCRYPTION_KEY` is properly set and 32 bytes (256-bit)

### Dashboard Connection Failed
Check that monitor server is running and accessible from dashboard host

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Built for enterprise security monitoring and threat detection**
