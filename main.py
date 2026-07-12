"""
Canary-Net Main Entry Point
Orchestrates all services: canaries, monitor, alert engine, and dashboard
"""

import sys
import logging
import argparse
import signal
import time
import threading
from pathlib import Path
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for graceful shutdown
ACTIVE_SERVICES = {
    'canaries': [],
    'monitor_server': None,
    'udp_listener': None,
    'database': None
}


def print_banner(cfg):
    """Print ASCII art startup banner with service info"""
    banner = f"""
{Fore.RED}
   _____ ___    ___   ___  ________   __
  / ____// _ |  / _ \\ / _ \\/ ____/ /  / /
 / /    / __ | / /_/ / /_//___ \\/ _ \\/ /
/ /___ / ___ |/ _, _/ __, /___/ / __/  /
\\____//_/ |_/_/ |_/_/ |_/_____/\\___/_/
{Style.RESET_ALL}

{Fore.YELLOW}🚨 Canary-Net Distributed Honeypot Network{Style.RESET_ALL}
{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}

{Fore.GREEN}Active Canaries:{Style.RESET_ALL}
"""
    
    enabled_canaries = cfg.get_enabled_canaries()
    for service_name, config_dict in enabled_canaries.items():
        name = config_dict.get('name', service_name.upper())
        port = config_dict.get('port', '?')
        banner += f"  • {Fore.CYAN}{name:<20}{Style.RESET_ALL} on port {Fore.YELLOW}{port}{Style.RESET_ALL}\n"
    
    monitor_host = cfg.get_monitor_host()
    monitor_port = cfg.get_monitor_port()
    banner += f"\n{Fore.GREEN}Monitor Server:{Style.RESET_ALL}\n"
    banner += f"  • {Fore.CYAN}tcp://{monitor_host}:{monitor_port}{Style.RESET_ALL}\n"
    
    dashboard_port = cfg.get_dashboard_port()
    banner += f"\n{Fore.GREEN}Dashboard:{Style.RESET_ALL}\n"
    banner += f"  • {Fore.CYAN}http://0.0.0.0:{dashboard_port}{Style.RESET_ALL}\n"
    
    banner += f"\n{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET_ALL}\n"
    
    print(banner)


def generate_encryption_key(cfg):
    """Generate and save encryption key"""
    from shared.crypto import AlertCrypto
    
    key_path = cfg.get_key_path()
    
    if Path(key_path).exists():
        print(f"{Fore.YELLOW}[*] Encryption key already exists at {key_path}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Generating encryption key...{Style.RESET_ALL}")
    AlertCrypto.generate_key(key_path)
    print(f"{Fore.GREEN}[+] Encryption key generated and saved to {key_path}{Style.RESET_ALL}")


def initialize_database(cfg, args):
    """Initialize database"""
    from shared.db import CanaryDB
    
    db_path = cfg.get_db_path()
    print(f"{Fore.CYAN}[*] Initializing database at {db_path}...{Style.RESET_ALL}")

    if args.fresh:
        try:
            import os
            if os.path.exists(db_path):
                os.remove(db_path)
                print("[+] Old database deleted")
            print("[+] Fresh start — clean database")
        except Exception as e:
            print(f"[-] Could not delete database: {e}")
    
    db = CanaryDB(db_path)
    ACTIVE_SERVICES['database'] = db
    
    print(f"{Fore.GREEN}[+] Database initialized{Style.RESET_ALL}")
    return db


def initialize_crypto(cfg):
    """Initialize encryption"""
    from shared.crypto import AlertCrypto
    
    key_path = cfg.get_key_path()
    print(f"{Fore.CYAN}[*] Loading encryption key from {key_path}...{Style.RESET_ALL}")
    
    crypto = AlertCrypto(key_path=key_path)
    print(f"{Fore.GREEN}[+] Encryption initialized (Fernet AES-128){Style.RESET_ALL}")
    return crypto


def start_monitor_server(cfg, crypto, db, emit_callback=None):
    """Start TCP monitor server"""
    from monitor.monitor_server import MonitorServer
    
    host = cfg.get_monitor_host()
    port = cfg.get_monitor_port()
    
    print(f"{Fore.CYAN}[*] Starting Monitor Server on tcp://{host}:{port}...{Style.RESET_ALL}")
    
    monitor = MonitorServer(
        host=host,
        port=port,
        crypto=crypto,
        db=db,
        emit_callback=emit_callback
    )
    monitor.start()
    ACTIVE_SERVICES['monitor_server'] = monitor
    
    print(f"{Fore.GREEN}[+] Monitor Server listening on tcp://{host}:{port}{Style.RESET_ALL}")
    return monitor


def start_udp_listener(cfg, crypto):
    """Start UDP broadcast listener"""
    from monitor.udp_listener import UDPListener
    
    port = cfg.get_broadcast_port()
    
    print(f"{Fore.CYAN}[*] Starting UDP Listener on port {port}...{Style.RESET_ALL}")
    
    listener = UDPListener(port=port, crypto=crypto)
    listener.start()
    ACTIVE_SERVICES['udp_listener'] = listener
    
    print(f"{Fore.GREEN}[+] UDP Listener active on port {port}{Style.RESET_ALL}")
    return listener


def start_alert_manager(db, crypto):
    """Initialize alert manager"""
    from alert_engine.alert_manager import AlertManager
    
    print(f"{Fore.CYAN}[*] Initializing Alert Manager...{Style.RESET_ALL}")
    
    alert_manager = AlertManager(db=db, crypto=crypto)
    
    print(f"{Fore.GREEN}[+] Alert Manager ready{Style.RESET_ALL}")
    return alert_manager


def start_canaries(cfg, alert_manager):
    """Start enabled honeypot canaries"""
    from canaries.ssh_canary import SSHCanary
    from canaries.ftp_canary import FTPCanary
    from canaries.http_canary import HTTPCanary
    from canaries.smb_canary import SMBCanary
    from shared.fake_data import generate_fake_data_for_canary
    
    enabled_canaries = cfg.get_enabled_canaries()
    started_canaries = []
    
    for service_name, canary_config in enabled_canaries.items():
        port = canary_config.get('port')
        name = canary_config.get('name', service_name.upper())
        
        try:
            print(f"{Fore.CYAN}[*] Starting {name} on port {port}...{Style.RESET_ALL}")
            
            # Generate fake data for this canary
            fake_data = generate_fake_data_for_canary(name)
            
            if service_name == 'ssh':
                canary = SSHCanary(
                    port=port,
                    name=name,
                    fake_data=fake_data,
                    alert_callback=alert_manager.on_alert
                )
            elif service_name == 'ftp':
                canary = FTPCanary(
                    port=port,
                    name=name,
                    fake_data=fake_data,
                    alert_callback=alert_manager.on_alert
                )
            elif service_name == 'http':
                canary = HTTPCanary(
                    port=port,
                    name=name,
                    fake_data=fake_data,
                    alert_callback=alert_manager.on_alert
                )
            elif service_name == 'smb':
                canary = SMBCanary(
                    port=port,
                    name=name,
                    fake_data=fake_data,
                    alert_callback=alert_manager.on_alert
                )
            else:
                print(f"{Fore.YELLOW}[!] Unknown canary type: {service_name}{Style.RESET_ALL}")
                continue
            
            canary.daemon = True
            canary.start()
            started_canaries.append(canary)
            
            print(f"{Fore.GREEN}[+] {name} started on port {port}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to start {name}: {e}{Style.RESET_ALL}")
    
    ACTIVE_SERVICES['canaries'] = started_canaries
    print(f"{Fore.GREEN}[+] Started {len(started_canaries)}/{len(enabled_canaries)} canaries{Style.RESET_ALL}")
    
    return started_canaries


def start_dashboard(cfg):
    """Start Flask dashboard with SocketIO"""
    from dashboard.app import create_app
    
    port = cfg.get_dashboard_port()
    
    print(f"{Fore.CYAN}[*] Initializing Flask Dashboard...{Style.RESET_ALL}")
    
    # Create app and inject services
    app, socketio = create_app(cfg)
    
    # Inject active services into app context
    app.monitor_server = ACTIVE_SERVICES['monitor_server']
    app.alert_manager = None  # Will be set if available
    app.database = ACTIVE_SERVICES['database']
    
    def run_dashboard():
        socketio.run(
            app,
            host='0.0.0.0',
            port=port,
            debug=False,
            use_reloader=False,
            log_output=False
        )
    
    # Run dashboard in separate daemon thread
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    
    print(f"{Fore.GREEN}[+] Dashboard running at http://localhost:{port}{Style.RESET_ALL}")
    
    return app, socketio


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) for graceful shutdown"""
    print(f"\n\n{Fore.YELLOW}[*] Received shutdown signal...{Style.RESET_ALL}")
    shutdown()


def shutdown():
    """Gracefully shutdown all services"""
    print(f"{Fore.CYAN}[*] Stopping all services...{Style.RESET_ALL}")
    
    # Stop canaries
    for canary in ACTIVE_SERVICES['canaries']:
        try:
            if hasattr(canary, 'stop'):
                canary.stop()
        except Exception as e:
            logger.error(f"Error stopping canary: {e}")
    
    # Stop monitor server
    if ACTIVE_SERVICES['monitor_server']:
        try:
            if hasattr(ACTIVE_SERVICES['monitor_server'], 'stop'):
                ACTIVE_SERVICES['monitor_server'].stop()
        except Exception as e:
            logger.error(f"Error stopping monitor: {e}")
    
    # Stop UDP listener
    if ACTIVE_SERVICES['udp_listener']:
        try:
            if hasattr(ACTIVE_SERVICES['udp_listener'], 'stop'):
                ACTIVE_SERVICES['udp_listener'].stop()
        except Exception as e:
            logger.error(f"Error stopping UDP listener: {e}")
    
    # Close database
    if ACTIVE_SERVICES['database']:
        try:
            ACTIVE_SERVICES['database'].close()
        except Exception as e:
            logger.error(f"Error closing database: {e}")
    
    print(f"{Fore.GREEN}[+] All services stopped{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Goodbye!{Style.RESET_ALL}")
    sys.exit(0)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🚨 Canary-Net Distributed Honeypot Network',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --all                        # Start all services
  python main.py --monitor-only               # Start monitor server only
  python main.py --canaries-only              # Start canaries only
  python main.py --generate-key               # Generate encryption key
  python main.py --config ./custom.yaml       # Use custom config file
        """
    )
    
    parser.add_argument('--config', default='config.yaml', help='Configuration file path')
    parser.add_argument('--generate-key', action='store_true', help='Generate encryption key')
    parser.add_argument('--all', action='store_true', help='Start all services')
    parser.add_argument('--monitor-only', action='store_true', help='Start monitor server and UDP listener only')
    parser.add_argument('--canaries-only', action='store_true', help='Start canaries only')
    parser.add_argument('--no-dashboard', action='store_true', help='Skip dashboard startup')
    parser.add_argument(
        '--fresh',
        action='store_true',
        help='Clear all alerts on startup'
    )
    
    args = parser.parse_args()
    
    # Load configuration
    try:
        from shared.config import Config, ConfigError
        
        cfg = Config(args.config)
    except ImportError:
        print(f"{Fore.RED}[-] Failed to import Config class{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Configuration error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    
    # Handle --generate-key
    if args.generate_key:
        try:
            generate_encryption_key(cfg)
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating key: {e}{Style.RESET_ALL}")
            sys.exit(1)
        return
    
    # Print banner
    print_banner(cfg)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        # Initialize core services
        db = initialize_database(cfg, args)
        crypto = initialize_crypto(cfg)
        alert_manager = start_alert_manager(db, crypto)
        
        # Start monitor and UDP listener
        if args.all or args.monitor_only:
            print(f"\n{Fore.YELLOW}Starting Monitor Services:{Style.RESET_ALL}")
            monitor = start_monitor_server(cfg, crypto, db)
            udp_listener = start_udp_listener(cfg, crypto)
        
        # Start canaries
        if args.all or args.canaries_only:
            print(f"\n{Fore.YELLOW}Starting Honeypot Canaries:{Style.RESET_ALL}")
            canaries = start_canaries(cfg, alert_manager)
        
        # Start dashboard
        if args.all and not args.no_dashboard:
            print(f"\n{Fore.YELLOW}Starting Dashboard:{Style.RESET_ALL}")
            try:
                app, socketio = start_dashboard(cfg)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Dashboard startup warning: {e}{Style.RESET_ALL}")
        
        # Summary
        print(f"\n{Fore.GREEN}╔════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║     [+] Canary-Net is running and monitoring...        ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}║     Press Ctrl+C to stop                              ║{Style.RESET_ALL}")
        print(f"{Fore.GREEN}╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        # Keep main thread alive
        while True:
            time.sleep(1)
    
    except KeyboardInterrupt:
        shutdown()
    except Exception as e:
        print(f"{Fore.RED}[-] Fatal error: {e}{Style.RESET_ALL}")
        logger.error(f"Fatal error", exc_info=True)
        shutdown()


if __name__ == '__main__':
    main()
