# Deployment Guide

This directory contains deployment automation for Canary-Net on both traditional Linux systems and containerized environments.

## Table of Contents

1. [Linux Deployment (deploy.sh)](#linux-deployment)
2. [Docker Deployment (docker-compose)](#docker-deployment)
3. [Network Configuration](#network-configuration)
4. [Troubleshooting](#troubleshooting)

---

## Linux Deployment

### Prerequisites

- **OS**: Ubuntu 20.04+, Debian 11+, CentOS 7+, or RHEL 8+
- **Python**: 3.11 or higher
- **Privileges**: Root access (for binding to ports < 1024) or custom port configuration
- **Disk Space**: 1 GB minimum for virtual environment + database

### Quick Start

```bash
# Download and execute the deployment script
git clone https://github.com/your-repo/canary-net.git
cd canary-net
chmod +x deploy.sh
sudo bash deploy.sh
```

### What deploy.sh Does

1. **Python Version Check**: Verifies Python 3.11+ is installed
2. **Virtual Environment**: Creates isolated Python environment at `./venv`
3. **Dependencies**: Installs all packages from `requirements.txt`
4. **Encryption Key**: Generates Fernet key for alert encryption
5. **Configuration**: Sets up `config.yaml` with defaults
6. **Systemd Service**: Creates `/etc/systemd/system/canary-net.service`
7. **Database Init**: Prepares SQLite database structure

### Post-Installation

**Start the service:**
```bash
sudo systemctl start canary-net
sudo systemctl enable canary-net      # Enable on boot
```

**Monitor service status:**
```bash
sudo systemctl status canary-net
sudo journalctl -u canary-net -f      # Follow logs
```

**Stop the service:**
```bash
sudo systemctl stop canary-net
```

### Manual Installation (Non-Root)

If you don't have root access, modify `config.yaml` to use high ports (>1024):

```yaml
canaries:
  ssh: { enabled: true, port: 2022, name: "PROD-SSH-01" }
  ftp: { enabled: true, port: 2121, name: "PROD-FTP-01" }
  http: { enabled: true, port: 8080, name: "PROD-WEB-01" }
  smb: { enabled: true, port: 4450, name: "PROD-FILE-01" }
```

Then run manually:
```bash
source venv/bin/activate
python main.py --all
```

---

## Docker Deployment

### Prerequisites

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **Host Requirements**:
  - 1 GB RAM
  - 1 vCPU
  - Port 5000 accessible (dashboard)

### Quick Start

```bash
cd canary-net
docker-compose up -d
```

### Container Architecture

**Two-container microservices setup:**

1. **Canary Container** (`canary-net-canaries`)
   - Runs all honeypot listeners (SSH, FTP, HTTP, SMB)
   - Sends alerts to monitor via TCP/UDP
   - Resource limits: 2 vCPU, 512 MB RAM

2. **Monitor Container** (`canary-net-monitor`)
   - Central alert receiver and processor
   - Flask dashboard on port 5000
   - Database management
   - Resource limits: 2 vCPU, 512 MB RAM

3. **Shared Volume** (`canary-data`)
   - SQLite database (`alerts.db`)
   - Encryption key (`canary.key`)
   - Mounted at `/app/data` in both containers

### Docker Commands

**Start services:**
```bash
docker-compose up -d
```

**Check status:**
```bash
docker-compose ps
```

**View logs:**
```bash
# All containers
docker-compose logs -f

# Specific service
docker-compose logs -f canary
docker-compose logs -f monitor
```

**Stop services:**
```bash
docker-compose down
```

**Stop and remove volumes (WARNING: loses data):**
```bash
docker-compose down -v
```

### Accessing Dashboard

- **Local**: http://localhost:5000
- **Remote**: http://<host-ip>:5000

### Custom Configuration

Edit `config.yaml` before starting containers:

```bash
# Edit configuration
nano config.yaml

# Restart services with new config
docker-compose down
docker-compose up -d
```

### Persistent Storage

By default, data is stored in a temporary volume (tmpfs). For persistent storage, modify `docker-compose.yml`:

```yaml
volumes:
  canary-data:
    driver: local
    # Data persists in Docker volume (host path: /var/lib/docker/volumes/)
```

To use a specific host directory:

```yaml
volumes:
  canary-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /path/to/canary-data
```

### Network Modes

**Default (Bridge Network):**
- Containers communicate via `canary-network`
- Canary service exposes ports: 21, 22, 8080, 4450
- Monitor dashboard on port 5000

**Host Network (Security NOT recommended):**
```yaml
services:
  canary:
    network_mode: host
  monitor:
    network_mode: host
```

---

## Network Configuration

### Port Mappings

| Service | Port | Type | Access | Purpose |
|---------|------|------|--------|---------|
| SSH Canary | 22 | TCP | External | SSH honeypot |
| FTP Canary | 21 | TCP | External | FTP honeypot |
| HTTP Canary | 8080 | TCP | External | Web honeypot |
| SMB Canary | 4450 | TCP | External | SMB honeypot |
| Monitor TCP | 9999 | TCP | Internal | Alert receiver |
| UDP Broadcast | 9998 | UDP | Internal | Alert broadcast |
| Dashboard | 5000 | TCP | External | Web UI |

### Firewall Rules

**Allow inbound (Linux with ufw):**
```bash
sudo ufw allow 22/tcp     # SSH honeypot
sudo ufw allow 21/tcp     # FTP honeypot
sudo ufw allow 8080/tcp   # HTTP honeypot
sudo ufw allow 4450/tcp   # SMB honeypot
sudo ufw allow 5000/tcp   # Dashboard
```

**Docker-specific:**
- Docker automatically manages iptables rules
- Use `docker-compose.yml` to control port exposure
- Remove ports from `ports:` section to disable external access

### Multi-Host Deployment

For distributed honeypots across multiple hosts:

1. **Central Monitor Host**:
   ```bash
   docker-compose up monitor
   # Exposes 5000, 9999, 9998
   ```

2. **Canary Hosts** (multiple):
   Modify `docker-compose.yml` monitor host reference:
   ```yaml
   environment:
     MONITOR_HOST: "central-monitor.example.com"
   ```

---

## Troubleshooting

### Deploy Script Issues

**"Python 3 is not installed"**
```bash
# Install Python 3.11+
# Ubuntu/Debian:
sudo apt-get update
sudo apt-get install python3.11 python3.11-venv python3.11-dev

# CentOS/RHEL:
sudo yum install python3.11 python3.11-devel
```

**"This script is not running as root"**
- Use `sudo bash deploy.sh` for privileged ports
- Or modify `config.yaml` to use ports >= 1024

**"Failed to generate encryption key"**
```bash
# Check venv activation
source venv/bin/activate

# Try manual key generation
python main.py --generate-key

# Check permissions
ls -la canary.key
```

### Docker Issues

**"Cannot start service canary: bind failed"**
- Port already in use:
  ```bash
  # Check listening ports
  sudo netstat -tlnp | grep -E ':(21|22|8080|5000)'
  
  # Kill conflicting process or change docker-compose.yml ports
  ```

**"Volume mount permission denied"**
```bash
# Fix volume permissions
docker-compose down
sudo chown -R 1000:1000 ./canary-data
docker-compose up -d
```

**"Container exits immediately"**
```bash
# Check logs
docker-compose logs canary
docker-compose logs monitor

# Verify config.yaml syntax
python -c "import yaml; yaml.safe_load(open('config.yaml'))"
```

**"Dashboard not accessible"**
```bash
# Check if monitor container is running
docker-compose ps

# Test connectivity from host
curl http://localhost:5000

# Check container logs
docker-compose logs monitor | grep -i error
```

### Systemd Service Issues

**"Service fails to start"**
```bash
# Check service status and error messages
sudo systemctl status canary-net
sudo journalctl -u canary-net -n 50

# Verify service file
sudo cat /etc/systemd/system/canary-net.service
```

**"Permission denied when accessing config.yaml"**
```bash
# Fix file permissions
sudo chown canary:canary /opt/canary-net/config.yaml
sudo chmod 640 /opt/canary-net/config.yaml
```

**"Port 22/21 already in use"**
```bash
# Find process using port
sudo lsof -i :22
sudo lsof -i :21

# Kill process (e.g., existing SSH server)
sudo systemctl stop ssh
# Or modify config.yaml to use different ports
```

### Performance Issues

**"High CPU usage"**
- Check alert volume: `journalctl -u canary-net | grep ALERT`
- Verify network stability
- Monitor database size: `ls -lh alerts.db`

**"Dashboard slow**
- Clear old alerts: Archive/delete from dashboard
- Check database: `sqlite3 alerts.db "SELECT COUNT(*) FROM alerts;"`
- Increase resource limits in `docker-compose.yml`

---

## Security Considerations

1. **Isolation**: Run honeypots in network-isolated environment
2. **Firewall**: Restrict dashboard access to trusted IPs only
3. **Encryption**: Keys are auto-generated; back them up securely
4. **Logs**: Monitor and archive alert logs regularly
5. **Updates**: Keep Python packages updated (`pip install --upgrade`)

---

## Next Steps

1. **Customize Configuration**: Edit `config.yaml` for your environment
2. **Monitor Dashboard**: Access at http://localhost:5000
3. **Check Integration Tests**: `pytest tests/test_integration.py -v`
4. **Deploy Monitoring**: Integrate with SIEM/SOC tools
5. **Document Changes**: Maintain configuration backups

---

## Support

For issues or questions:
- Check logs: `journalctl -u canary-net -f` or `docker-compose logs -f`
- Run tests: `pytest tests/ -v`
- Review configuration: `config.yaml`
- Check documentation: `README.md`
