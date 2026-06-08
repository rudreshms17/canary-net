"""
Monitor Server
Central monitoring server that receives encrypted alerts from canaries
"""

import logging
import socket
import struct
import threading
from typing import Optional, Callable, Dict, Any
from colorama import Fore, Back, Style, init

from shared.crypto import AlertCrypto, CanaryCryptoError
from shared.db import AlertDatabase

# Initialize colorama
init(autoreset=True)

logger = logging.getLogger(__name__)


class MonitorServer:
    """
    Central Monitor Server
    
    Receives encrypted alerts from canary services via TCP.
    Validates, decrypts, persists, and broadcasts alerts to dashboard.
    """
    
    def __init__(
        self,
        host: str,
        port: int,
        crypto: AlertCrypto,
        db: AlertDatabase,
        emit_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None
    ):
        """
        Initialize Monitor Server
        
        Args:
            host: Host to bind to (e.g., 0.0.0.0)
            port: Port to listen on
            crypto: AlertCrypto instance for decryption
            db: AlertDatabase instance for persistence
            emit_callback: Optional callback to emit SocketIO events
                          Called as: emit_callback('new_alert', alert_dict)
        """
        self.host = host
        self.port = port
        self.crypto = crypto
        self.db = db
        self.emit_callback = emit_callback
        
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        self.client_threads = []
        
        # Statistics
        self.alerts_received = 0
        self.alerts_valid = 0
        self.alerts_invalid = 0
        self.alerts_decryption_failed = 0
        
        logger.info(f"[MonitorServer] Initialized on {host}:{port}")
    
    def start(self):
        """
        Start the monitor server
        
        Runs TCP server in background thread, accepting multiple client connections
        """
        if self.running:
            logger.warning("[MonitorServer] Server already running")
            return
        
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1)  # Timeout to allow graceful shutdown
            
            self.running = True
            
            # Start server thread
            self.server_thread = threading.Thread(
                target=self._accept_connections,
                daemon=True
            )
            self.server_thread.start()
            
            logger.info(
                f"[MonitorServer] ✓ Started on {self.host}:{self.port}"
            )
        
        except Exception as e:
            logger.error(
                f"[MonitorServer] Failed to start server: {e}",
                exc_info=True
            )
            self.running = False
    
    def _accept_connections(self):
        """
        Accept incoming client connections (runs in background thread)
        
        Spawns a new thread for each client connection
        """
        while self.running:
            try:
                # Accept incoming connection
                try:
                    client_socket, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                
                client_ip, client_port = client_addr
                logger.debug(f"[MonitorServer] New connection from {client_ip}:{client_port}")
                
                # Handle connection in separate thread
                handler_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_addr),
                    daemon=True
                )
                handler_thread.start()
                self.client_threads.append(handler_thread)
            
            except OSError:
                # Socket closed
                break
            except Exception as e:
                if self.running:
                    logger.error(f"[MonitorServer] Error accepting connection: {e}")
    
    def _handle_client(self, conn: socket.socket, addr: tuple):
        """
        Handle individual client connection
        
        Reads encrypted alert, validates, decrypts, persists, and broadcasts.
        
        Args:
            conn: Connected socket
            addr: Client address (ip, port)
        """
        client_ip, client_port = addr
        
        try:
            conn.settimeout(10)  # 10 second timeout
            
            # Read 4-byte length prefix (big-endian)
            length_data = conn.recv(4)
            
            if len(length_data) < 4:
                logger.warning(
                    f"[MonitorServer] Incomplete length header from {client_ip}:{client_port}"
                )
                return
            
            message_length = struct.unpack('>I', length_data)[0]
            
            # Sanity check on message length (max 10MB)
            if message_length <= 0 or message_length > 10 * 1024 * 1024:
                logger.warning(
                    f"[MonitorServer] Invalid message length {message_length} from {client_ip}:{client_port}"
                )
                return
            
            logger.debug(
                f"[MonitorServer] Receiving {message_length} bytes from {client_ip}:{client_port}"
            )
            
            # Read full encrypted payload
            encrypted_payload = b''
            while len(encrypted_payload) < message_length:
                chunk = conn.recv(min(4096, message_length - len(encrypted_payload)))
                if not chunk:
                    logger.warning(
                        f"[MonitorServer] Connection closed by {client_ip}:{client_port} "
                        f"(received {len(encrypted_payload)}/{message_length} bytes)"
                    )
                    return
                encrypted_payload += chunk
            
            # Increment counter
            self.alerts_received += 1
            
            # Decrypt alert
            try:
                alert = self.crypto.decrypt(encrypted_payload)
                logger.debug(
                    f"[MonitorServer] Decrypted alert from {client_ip}:{client_port}: "
                    f"{alert.get('canary_name', 'UNKNOWN')}"
                )
            except CanaryCryptoError as e:
                self.alerts_decryption_failed += 1
                logger.warning(
                    f"[MonitorServer] Decryption failed from {client_ip}:{client_port}: {e}"
                )
                return
            except Exception as e:
                self.alerts_decryption_failed += 1
                logger.error(
                    f"[MonitorServer] Unexpected error decrypting alert: {e}"
                )
                return
            
            # Validate alert schema
            required_fields = ['canary_name', 'attacker_ip', 'timestamp']
            missing_fields = [f for f in required_fields if f not in alert]
            
            if missing_fields:
                self.alerts_invalid += 1
                logger.warning(
                    f"[MonitorServer] Invalid alert schema from {client_ip}:{client_port}: "
                    f"missing {missing_fields}"
                )
                return
            
            # Save to database
            try:
                self.db.log_alert(alert)
                logger.debug(
                    f"[MonitorServer] Alert saved to database: {alert.get('alert_id', 'N/A')}"
                )
            except Exception as e:
                logger.error(
                    f"[MonitorServer] Failed to save alert to database: {e}"
                )
            
            # Increment valid counter
            self.alerts_valid += 1
            
            # Emit SocketIO event to dashboard
            if self.emit_callback:
                try:
                    self.emit_callback('new_alert', alert)
                    logger.debug("[MonitorServer] SocketIO event emitted")
                except Exception as e:
                    logger.warning(f"[MonitorServer] Failed to emit SocketIO event: {e}")
            
            # Log alert to console
            self._print_alert_received(alert, client_ip, client_port)
        
        except socket.timeout:
            logger.debug(f"[MonitorServer] Connection timeout from {client_ip}:{client_port}")
        except Exception as e:
            logger.error(
                f"[MonitorServer] Error handling client {client_ip}:{client_port}: {e}",
                exc_info=True
            )
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _print_alert_received(self, alert: dict, client_ip: str, client_port: int):
        """
        Print colorized alert received notification
        
        Args:
            alert: Alert dictionary
            client_ip: Client IP address
            client_port: Client port
        """
        try:
            canary_name = alert.get('canary_name', 'UNKNOWN')
            attacker_ip = alert.get('attacker_ip', 'UNKNOWN')
            attacker_port = alert.get('attacker_port', '?')
            behavior = alert.get('behavior', 'UNKNOWN')
            timestamp = alert.get('timestamp', '')
            
            output = []
            output.append("")
            output.append("─" * 80)
            output.append(
                f"📡 {Fore.GREEN}{Style.BRIGHT}RECEIVED{Style.RESET_ALL} from "
                f"{Fore.CYAN}{client_ip}:{client_port}{Style.RESET_ALL}"
            )
            output.append(
                f"   Canary:  {Fore.RED}{Style.BRIGHT}{canary_name}{Style.RESET_ALL}"
            )
            output.append(
                f"   Attack:  {Fore.RED}{attacker_ip}:{attacker_port}{Style.RESET_ALL}"
            )
            output.append(
                f"   Behavior: {behavior[:60]}"
            )
            output.append(
                f"   Time: {Fore.YELLOW}{timestamp}{Style.RESET_ALL}"
            )
            output.append("─" * 80)
            
            print("\n".join(output))
        
        except Exception as e:
            logger.debug(f"[MonitorServer] Error printing alert: {e}")
    
    def get_statistics(self) -> dict:
        """
        Get server statistics
        
        Returns:
            Dictionary with alert counts
        """
        return {
            "alerts_received": self.alerts_received,
            "alerts_valid": self.alerts_valid,
            "alerts_invalid": self.alerts_invalid,
            "alerts_decryption_failed": self.alerts_decryption_failed,
            "db_total_alerts": self.db.get_alert_count()
        }
    
    def stop(self):
        """Stop the monitor server"""
        try:
            self.running = False
            
            if self.server_socket:
                self.server_socket.close()
            
            # Wait for threads to finish
            if self.server_thread:
                self.server_thread.join(timeout=2)
            
            logger.info("[MonitorServer] ✓ Stopped")
        
        except Exception as e:
            logger.error(f"[MonitorServer] Error stopping server: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.stop()
