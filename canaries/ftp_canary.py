"""
FTP Honeypot Canary
Fake FTP server that logs and alerts on connection attempts
"""

import logging
from typing import Callable, Dict, Any
import threading
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.filesystems import AbstractedFS

from .base_canary import BaseCanary

logger = logging.getLogger(__name__)


class PermissiveAuthorizer(DummyAuthorizer):
    """Custom authorizer that logs all authentication attempts"""
    
    canary_instance = None
    
    def validate_authentication(self, username, password, handler):
        """Override to log authentication attempts and allow all"""
        if self.canary_instance:
            # Trigger alert for login attempt
            behavior_msg = f"ftp_login_attempt: username={username} password={password}"
            self.canary_instance._trigger_alert(
                attacker_ip=handler.remote_ip,
                attacker_port=handler.remote_port,
                behavior=behavior_msg,
                fake_data_touched=False
            )
            
            logger.warning(
                f"[FTP] Login attempt: {username}:{password} "
                f"from {handler.remote_ip}:{handler.remote_port}"
            )
        
        # Always return False to reject the login, but we've already logged it
        return False


class FakeFTPFS(AbstractedFS):
    """Fake filesystem for FTP server with honeypot files"""
    
    FAKE_FILES = {
        'Q3_financials.xlsx': 1024576,      # 1MB
        'employee_records.csv': 512000,     # 512KB
        'backup_keys.txt': 2048,            # 2KB
        'system_config.ini': 4096,          # 4KB
    }
    
    def __init__(self, root, cmd_channel):
        super().__init__(root, cmd_channel)
    
    def listdir(self, path):
        """Return fake directory listing"""
        return list(self.FAKE_FILES.keys())


class CanaryFTPHandler(FTPHandler):
    """Custom FTP handler for FTP honeypot"""
    
    # Class variable to store reference to the canary instance
    canary_instance = None


class FTPCanary(BaseCanary):
    """
    FTP Honeypot Service
    
    Presents a fake FTP server that logs all authentication attempts
    and alerts on suspicious activity.
    """
    
    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """
        Initialize FTP Canary
        
        Args:
            port: Port to listen on
            name: Canary name
            fake_data: Fake data dictionary
            alert_callback: Alert callback function
        """
        super().__init__(port, name, fake_data, alert_callback)
        self.ftp_server = None
        self.server_thread = None
        
        # Set class variable for handler access
        CanaryFTPHandler.canary_instance = self
    
    def start(self):
        """Start the FTP honeypot server"""
        try:
            # Create a permissive authorizer that logs auth attempts
            authorizer = PermissiveAuthorizer()
            authorizer.canary_instance = self
            
            # Create custom FTP handler with our banner
            handler = CanaryFTPHandler
            handler.authorizer = authorizer
            handler.banner = "220 FileServer-PROD-v2.1 FTP Server ready"
            handler.canary_instance = self
            
            # Create FTP server
            self.ftp_server = FTPServer(
                ('0.0.0.0', self.port),
                handler
            )
            
            # Run server in background thread
            self.server_thread = threading.Thread(
                target=self._run_server,
                daemon=True
            )
            self.server_thread.start()
            
            self.running = True
            logger.info(
                f"[{self.name}] FTP Honeypot started on port {self.port} "
                f"with banner: 'FileServer-PROD-v2.1 FTP Server ready'"
            )
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to start FTP server: {e}", exc_info=True)
            self.running = False
    
    def _run_server(self):
        """Run the FTP server (called in background thread)"""
        try:
            self.ftp_server.serve_forever(timeout=1, blocking=True)
        except Exception as e:
            logger.error(f"[{self.name}] FTP server error: {e}", exc_info=True)
    
    def stop(self):
        """Stop the FTP honeypot server"""
        try:
            if self.ftp_server:
                self.ftp_server.close_all()
            
            self.running = False
            logger.info(f"[{self.name}] FTP Honeypot stopped")
        
        except Exception as e:
            logger.error(f"[{self.name}] Error stopping FTP server: {e}", exc_info=True)
