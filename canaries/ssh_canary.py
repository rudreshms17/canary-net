"""
SSH Honeypot Canary
Fake SSH server that logs and alerts on connection attempts
"""

import logging
from typing import Callable, Dict, Any
import threading
import socket
import paramiko
from paramiko import ServerInterface, Transport, RSAKey
import io

from .base_canary import BaseCanary

logger = logging.getLogger(__name__)


class SSHServerInterface(ServerInterface):
    """Custom SSH server interface that captures authentication attempts"""
    
    def __init__(self, canary_instance, client_ip: str, client_port: int):
        """
        Initialize SSH server interface
        
        Args:
            canary_instance: Reference to SSHCanary instance for alert triggering
            client_ip: Connecting client IP address
            client_port: Connecting client port
        """
        self.canary_instance = canary_instance
        self.client_ip = client_ip
        self.client_port = client_port
        self.client_version = None
    
    def check_auth_password(self, username: str, password: str) -> int:
        """
        Handle password authentication attempt
        
        Args:
            username: Username attempting to authenticate
            password: Password provided
            
        Returns:
            paramiko.AUTH_FAILED to reject authentication
        """
        # Record the authentication attempt
        behavior_msg = (
            f"ssh_password_auth_attempt: username={username} password={password} "
            f"client_version={self.client_version}"
        )
        
        self.canary_instance._trigger_alert(
            attacker_ip=self.client_ip,
            attacker_port=self.client_port,
            behavior=behavior_msg,
            fake_data_touched=False
        )
        
        logger.warning(
            f"[SSH] Password auth attempt: {username}:{password} "
            f"from {self.client_ip}:{self.client_port} "
            f"client={self.client_version}"
        )
        
        # Always reject
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        """
        Handle public key authentication attempt
        
        Args:
            username: Username attempting to authenticate
            key: Public key being used
            
        Returns:
            paramiko.AUTH_FAILED to reject authentication
        """
        # Get key fingerprint
        key_fingerprint = paramiko.py3compat.b(key.get_fingerprint()).hex()
        key_type = key.get_name()
        
        behavior_msg = (
            f"ssh_pubkey_auth_attempt: username={username} "
            f"key_type={key_type} key_fingerprint={key_fingerprint} "
            f"client_version={self.client_version}"
        )
        
        self.canary_instance._trigger_alert(
            attacker_ip=self.client_ip,
            attacker_port=self.client_port,
            behavior=behavior_msg,
            fake_data_touched=False
        )
        
        logger.warning(
            f"[SSH] Public key auth attempt: {username} ({key_type}) "
            f"from {self.client_ip}:{self.client_port} "
            f"fingerprint={key_fingerprint} client={self.client_version}"
        )
        
        # Always reject
        return paramiko.AUTH_FAILED
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Reject any channel requests"""
        logger.debug(f"[SSH] Channel request rejected: {kind}")
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_subsystem_request(self, channel, name: str) -> bool:
        """Reject subsystem requests"""
        return False
    
    def check_channel_shell_request(self, channel) -> bool:
        """Reject shell requests"""
        return False
    
    def check_channel_exec_request(self, channel, command: str) -> bool:
        """Reject command execution"""
        return False


class SSHCanary(BaseCanary):
    """
    SSH Honeypot Service
    
    Presents a fake SSH server that captures authentication attempts,
    client information, and SSH protocol details.
    """
    
    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """
        Initialize SSH Canary
        
        Args:
            port: Port to listen on
            name: Canary name
            fake_data: Fake data dictionary
            alert_callback: Alert callback function
        """
        super().__init__(port, name, fake_data, alert_callback)
        self.listen_socket = None
        self.server_thread = None
        
        # Generate RSA host key for SSH server
        self._host_key = self._generate_host_key()
    
    def _generate_host_key(self) -> RSAKey:
        """Generate a fake RSA host key for the SSH server"""
        try:
            # Generate a 2048-bit RSA key
            return RSAKey.generate(2048)
        except Exception as e:
            logger.error(f"[{self.name}] Failed to generate host key: {e}")
            # Fallback: create a minimal key
            return None
    
    def start(self):
        """Start the SSH honeypot server"""
        try:
            # Create listening socket
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind(('0.0.0.0', self.port))
            self.listen_socket.listen(5)
            
            self.running = True
            
            # Start server thread
            self.server_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(
                f"[{self.name}] SSH Honeypot started on 0.0.0.0:{self.port} "
                f"with banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'"
            )
        
        except Exception as e:
            logger.error(f"[{self.name}] Failed to start SSH server: {e}", exc_info=True)
            self.running = False
    
    def _accept_connections(self):
        """Accept and handle incoming SSH connections"""
        while self.running:
            try:
                # Accept incoming connection
                client_socket, addr = self.listen_socket.accept()
                client_ip, client_port = addr
                
                # Handle connection in a separate thread
                handler_thread = threading.Thread(
                    target=self._handle_ssh_connection,
                    args=(client_socket, client_ip, client_port),
                    daemon=True
                )
                handler_thread.start()
            
            except socket.timeout:
                continue
            except OSError:
                # Socket closed
                break
            except Exception as e:
                if self.running:
                    logger.error(f"[{self.name}] Error accepting connection: {e}")
    
    def _handle_ssh_connection(self, client_socket: socket.socket, client_ip: str, client_port: int):
        """
        Handle individual SSH connection
        
        Args:
            client_socket: Connected socket
            client_ip: Client IP address
            client_port: Client port
        """
        transport = None
        try:
            # Set socket timeout
            client_socket.settimeout(10)
            
            # Create SSH transport with custom banner
            transport = Transport(client_socket)
            transport.set_server_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
            
            # Set host key
            if self._host_key:
                transport.add_server_key(self._host_key)
            
            # Create server interface
            server_interface = SSHServerInterface(self, client_ip, client_port)
            
            # Start SSH server on this transport
            transport.start_server(server=server_interface)
            
            # Keep transport alive briefly to allow auth attempts
            # then close (since we reject everything anyway)
            transport.accept(timeout=5)
            
        except paramiko.SSHException as e:
            logger.debug(f"[{self.name}] SSH exception from {client_ip}:{client_port}: {e}")
        except socket.timeout:
            logger.debug(f"[{self.name}] Connection timeout from {client_ip}:{client_port}")
        except Exception as e:
            logger.debug(f"[{self.name}] Error handling SSH connection: {e}")
        finally:
            try:
                if transport:
                    transport.close()
                client_socket.close()
            except:
                pass
    
    def stop(self):
        """Stop the SSH honeypot server"""
        try:
            self.running = False
            
            if self.listen_socket:
                self.listen_socket.close()
            
            logger.info(f"[{self.name}] SSH Honeypot stopped")
        
        except Exception as e:
            logger.error(f"[{self.name}] Error stopping SSH server: {e}", exc_info=True)
