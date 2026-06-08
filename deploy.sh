#!/bin/bash

##############################################################################
# Canary-Net Deployment Script
# Deploys the distributed honeypot network on Linux/macOS
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
PYTHON_MIN_VERSION="3.11"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
SERVICE_NAME="canary-net"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

##############################################################################
# Utility Functions
##############################################################################

print_header() {
    echo -e "\n${BLUE}════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

##############################################################################
# Prerequisites Check
##############################################################################

check_python_version() {
    print_info "Checking Python version..."
    
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        echo "Please install Python 3.11 or higher from https://www.python.org"
        exit 1
    fi
    
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$PYTHON_MINOR" -lt 11 ]; then
        print_error "Python $PYTHON_VERSION detected, but Python 3.11+ is required"
        exit 1
    fi
    
    print_success "Python $PYTHON_VERSION detected (meets requirement)"
}

check_root_privileges() {
    print_info "Checking privilege level..."
    
    if [ "$EUID" -ne 0 ]; then
        print_warning "This script is not running as root"
        echo "Running honeypot canaries on ports < 1024 (SSH:22, FTP:21) requires root privileges"
        echo "You can either:"
        echo "  1. Run this script with sudo: sudo bash deploy.sh"
        echo "  2. Modify config.yaml to use ports >= 1024 (e.g., 2022, 2121)"
        echo ""
        read -p "Continue without root? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Running with root privileges"
    fi
}

check_dependencies() {
    print_info "Checking system dependencies..."
    
    local required_tools=("curl" "git")
    local missing_tools=()
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        print_warning "Some optional tools are missing: ${missing_tools[@]}"
        echo "These are used for development/monitoring but not required for deployment"
    else
        print_success "All recommended tools are available"
    fi
}

##############################################################################
# Virtual Environment Setup
##############################################################################

setup_virtualenv() {
    print_header "Setting up Python Virtual Environment"
    
    if [ -d "$VENV_DIR" ]; then
        print_info "Virtual environment already exists at $VENV_DIR"
        read -p "Remove existing and create new? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Removing existing virtual environment..."
            rm -rf "$VENV_DIR"
        else
            print_info "Using existing virtual environment"
            return
        fi
    fi
    
    print_info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    print_success "Virtual environment created"
    
    # Activate virtual environment
    source "$VENV_DIR/bin/activate"
    print_success "Virtual environment activated"
    
    # Upgrade pip
    print_info "Upgrading pip..."
    python -m pip install --upgrade pip --quiet
    print_success "pip upgraded"
}

install_dependencies() {
    print_header "Installing Python Dependencies"
    
    if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
        print_error "requirements.txt not found in $SCRIPT_DIR"
        exit 1
    fi
    
    source "$VENV_DIR/bin/activate"
    
    print_info "Installing packages from requirements.txt..."
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
    
    print_success "All dependencies installed"
}

##############################################################################
# Encryption Key Generation
##############################################################################

generate_encryption_key() {
    print_header "Generating Encryption Key"
    
    source "$VENV_DIR/bin/activate"
    
    if [ -f "$SCRIPT_DIR/canary.key" ]; then
        print_warning "Encryption key already exists at $SCRIPT_DIR/canary.key"
        read -p "Regenerate key? This will invalidate old alerts! (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Keeping existing key"
            return
        fi
        rm "$SCRIPT_DIR/canary.key"
    fi
    
    print_info "Generating new encryption key..."
    cd "$SCRIPT_DIR"
    python main.py --generate-key
    
    if [ -f "$SCRIPT_DIR/canary.key" ]; then
        print_success "Encryption key generated"
    else
        print_error "Failed to generate encryption key"
        exit 1
    fi
}

##############################################################################
# Configuration Setup
##############################################################################

setup_configuration() {
    print_header "Configuring Canary-Net"
    
    if [ ! -f "$SCRIPT_DIR/config.yaml" ]; then
        print_warning "config.yaml not found - will be auto-generated on first run"
        return
    fi
    
    print_success "Configuration file exists at $SCRIPT_DIR/config.yaml"
    echo "To modify settings, edit config.yaml before starting the service"
}

##############################################################################
# Systemd Service Setup (for Linux)
##############################################################################

setup_systemd_service() {
    print_header "Setting up Systemd Service"
    
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root - skipping systemd service setup"
        print_info "To install the service later, run: sudo bash deploy.sh"
        return
    fi
    
    print_info "Creating systemd service file..."
    
    # Get the username running the script
    SCRIPT_USER=$(logname 2>/dev/null || echo "root")
    if [ -z "$SCRIPT_USER" ]; then
        SCRIPT_USER="root"
    fi
    
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Canary-Net Distributed Honeypot Network
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SCRIPT_USER
WorkingDirectory=$SCRIPT_DIR
Environment="PATH=$VENV_DIR/bin"
ExecStart=$VENV_DIR/bin/python $SCRIPT_DIR/main.py --all
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SCRIPT_DIR

[Install]
WantedBy=multi-user.target
EOF
    
    # Set proper permissions
    chmod 644 "$SERVICE_FILE"
    
    # Reload systemd daemon
    systemctl daemon-reload
    
    print_success "Systemd service file created at $SERVICE_FILE"
}

##############################################################################
# Database Initialization
##############################################################################

initialize_database() {
    print_header "Initializing Database"
    
    source "$VENV_DIR/bin/activate"
    
    cd "$SCRIPT_DIR"
    print_info "Database will be created automatically on first run"
    print_success "Database initialization prepared"
}

##############################################################################
# Post-Installation Instructions
##############################################################################

print_post_install_instructions() {
    print_header "Deployment Complete!"
    
    echo -e "${GREEN}Canary-Net has been successfully deployed!${NC}\n"
    
    echo -e "${YELLOW}Quick Start:${NC}"
    if [ "$EUID" -eq 0 ]; then
        echo "  1. Enable and start the service:"
        echo "     ${BLUE}systemctl enable canary-net${NC}"
        echo "     ${BLUE}systemctl start canary-net${NC}"
        echo ""
        echo "  2. Check service status:"
        echo "     ${BLUE}systemctl status canary-net${NC}"
        echo ""
        echo "  3. View service logs:"
        echo "     ${BLUE}journalctl -u canary-net -f${NC}"
    else
        echo "  1. Activate virtual environment:"
        echo "     ${BLUE}source $VENV_DIR/bin/activate${NC}"
        echo ""
        echo "  2. Start the honeypot:"
        echo "     ${BLUE}cd $SCRIPT_DIR && python main.py --all${NC}"
    fi
    
    echo -e "\n${YELLOW}Configuration:${NC}"
    echo "  • Edit ${BLUE}$SCRIPT_DIR/config.yaml${NC} to customize settings"
    echo "  • Canary names and ports can be modified before first run"
    echo "  • Default dashboard: ${BLUE}http://localhost:5000${NC}"
    
    echo -e "\n${YELLOW}Monitoring:${NC}"
    echo "  • Monitor Server: tcp://0.0.0.0:9999"
    echo "  • UDP Broadcast: 0.0.0.0:9998"
    echo "  • Dashboard: http://0.0.0.0:5000"
    
    echo -e "\n${YELLOW}Canary Services:${NC}"
    echo "  • SSH:  tcp://0.0.0.0:22   (PROD-SSH-01)"
    echo "  • FTP:  tcp://0.0.0.0:21   (PROD-FTP-01)"
    echo "  • HTTP: tcp://0.0.0.0:8080 (PROD-WEB-01)"
    echo "  • SMB:  tcp://0.0.0.0:4450 (PROD-FILE-01)"
    
    echo -e "\n${YELLOW}Documentation:${NC}"
    echo "  • README: $SCRIPT_DIR/README.md"
    echo "  • Config: $SCRIPT_DIR/config.yaml"
    
    echo -e "\n${YELLOW}Support:${NC}"
    echo "  • Check logs for errors: journalctl -u canary-net"
    echo "  • Run tests: pytest tests/test_integration.py -v"
    echo "  • View dashboard: http://$(hostname -I | awk '{print $1}'):5000"
    
    echo -e "\n${GREEN}Happy honeypotting!${NC}\n"
}

##############################################################################
# Main Deployment Flow
##############################################################################

main() {
    print_header "🚨 Canary-Net Deployment Script"
    
    echo "This script will:"
    echo "  1. Verify Python 3.11+ is installed"
    echo "  2. Check system privileges"
    echo "  3. Create a Python virtual environment"
    echo "  4. Install all dependencies"
    echo "  5. Generate encryption keys"
    echo "  6. Create systemd service (Linux only)"
    echo ""
    read -p "Continue with deployment? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_warning "Deployment cancelled"
        exit 0
    fi
    
    # Execute deployment steps
    check_python_version
    check_dependencies
    check_root_privileges
    setup_virtualenv
    install_dependencies
    setup_configuration
    generate_encryption_key
    initialize_database
    setup_systemd_service
    
    # Print instructions
    print_post_install_instructions
}

# Run main function
main "$@"
