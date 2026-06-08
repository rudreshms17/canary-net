"""
UDP Listener for Broadcast Alerts
Secondary confirmation channel for UDP broadcast alerts
"""

import logging
import socket
import struct
import threading
from typing import Optional, Callable
from colorama import Fore, Back, Style, init

from shared.crypto import AlertCrypto, CanaryCryptoError

# Initialize colorama
init(autoreset=True)

logger = logging.getLogger(__name__)


class UDPListener:
    """
    UDP Broadcast Alert Listener
    
    Listens for encrypted UDP broadcast alerts sent by UDPBroadcaster.
    Decrypts, validates, and logs alerts to console.
    Secondary confirmation channel - does NOT persist to database.
    """
    
    CARY_MAGIC = b'CARY'  # 4-byte magic header
    
    def __init__(self, port: int, crypto: AlertCrypto):
        """
        Initialize UDP Listener
        
        Args:
            port: Port to listen on (e.g., 5555)
            crypto: AlertCrypto instance for decryption
        """
        self.port = port
        self.crypto = crypto
        
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.listener_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.packets_received = 0
        self.packets_valid = 0
        self.packets_invalid = 0
        self.packets_decryption_failed = 0
        
        logger.info(f"[UDPListener] Initialized on port {port}")
    
    def start(self):
        """
        Start the UDP listener
        
        Runs in background daemon thread, listening for broadcast packets
        """
        if self.running:
            logger.warning("[UDPListener] Listener already running")
            return
        
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Enable SO_REUSEPORT for multiple listeners (if supported)
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, OSError):
                # SO_REUSEPORT not supported on all platforms
                pass
            
            # Bind to any interface on the broadcast port
            self.socket.bind(('0.0.0.0', self.port))
            self.socket.settimeout(1)  # Timeout to allow graceful shutdown
            
            self.running = True
            
            # Start listener thread (daemon)
            self.listener_thread = threading.Thread(
                target=self._listen,
                daemon=True
            )
            self.listener_thread.start()
            
            logger.info(
                f"[UDPListener] ✓ Started listening on 0.0.0.0:{self.port}"
            )
        
        except Exception as e:
            logger.error(
                f"[UDPListener] Failed to start listener: {e}",
                exc_info=True
            )
            self.running = False
    
    def _listen(self):
        """
        Listen for incoming UDP broadcast packets (runs in background thread)
        
        Packet format: [b'CARY' - 4 bytes] + [length - 4 bytes big-endian] + [encrypted payload]
        """
        while self.running:
            try:
                # Receive UDP packet
                data, addr = self.socket.recvfrom(10 * 1024 * 1024)  # Max 10MB
                
                # Parse and process
                self._process_packet(data, addr)
            
            except socket.timeout:
                continue
            except OSError:
                # Socket closed
                break
            except Exception as e:
                if self.running:
                    logger.error(f"[UDPListener] Error receiving packet: {e}")
    
    def _process_packet(self, data: bytes, addr: tuple):
        """
        Process incoming UDP packet
        
        Args:
            data: Raw packet data
            addr: Source address (ip, port)
        """
        src_ip, src_port = addr
        
        try:
            # Increment counter
            self.packets_received += 1
            
            # Validate minimum length: 4 (CARY) + 4 (length) = 8 bytes
            if len(data) < 8:
                logger.debug(
                    f"[UDPListener] Packet too short ({len(data)} bytes) from {src_ip}:{src_port}"
                )
                return
            
            # Parse magic header
            magic = data[:4]
            
            if magic != self.CARY_MAGIC:
                logger.debug(
                    f"[UDPListener] Invalid magic header from {src_ip}:{src_port}: "
                    f"{magic.hex()}"
                )
                return
            
            # Parse length prefix (big-endian)
            try:
                message_length = struct.unpack('>I', data[4:8])[0]
            except struct.error as e:
                logger.debug(
                    f"[UDPListener] Failed to parse length prefix from {src_ip}:{src_port}: {e}"
                )
                return
            
            # Validate length
            payload_start = 8
            payload_end = payload_start + message_length
            
            if payload_end > len(data):
                logger.debug(
                    f"[UDPListener] Incomplete payload from {src_ip}:{src_port}: "
                    f"expected {message_length}, got {len(data) - payload_start}"
                )
                return
            
            encrypted_payload = data[payload_start:payload_end]
            
            logger.debug(
                f"[UDPListener] Decrypting {message_length} bytes from {src_ip}:{src_port}"
            )
            
            # Decrypt alert
            try:
                alert = self.crypto.decrypt(encrypted_payload)
            except CanaryCryptoError as e:
                self.packets_decryption_failed += 1
                logger.debug(
                    f"[UDPListener] Decryption failed from {src_ip}:{src_port}: {e}"
                )
                return
            except Exception as e:
                self.packets_decryption_failed += 1
                logger.error(
                    f"[UDPListener] Unexpected error decrypting alert: {e}"
                )
                return
            
            # Validate alert schema (basic validation - just check for required fields)
            required_fields = ['canary_name']
            missing_fields = [f for f in required_fields if f not in alert]
            
            if missing_fields:
                self.packets_invalid += 1
                logger.debug(
                    f"[UDPListener] Invalid alert schema from {src_ip}:{src_port}: "
                    f"missing {missing_fields}"
                )
                return
            
            # Increment valid counter
            self.packets_valid += 1
            
            # Log alert to console (secondary confirmation)
            self._print_broadcast_alert(alert, src_ip, src_port)
        
        except Exception as e:
            logger.error(
                f"[UDPListener] Error processing packet from {src_ip}:{src_port}: {e}",
                exc_info=True
            )
    
    def _print_broadcast_alert(self, alert: dict, src_ip: str, src_port: int):
        """
        Print colorized broadcast alert notification to console
        
        Args:
            alert: Alert dictionary
            src_ip: Source IP address
            src_port: Source port
        """
        try:
            canary_name = alert.get('canary_name', 'UNKNOWN')
            attacker_ip = alert.get('attacker_ip', 'UNKNOWN')
            behavior = alert.get('behavior', 'N/A')
            
            output = (
                f"\n{Fore.CYAN}{Style.BRIGHT}📡 BROADCAST ALERT{Style.RESET_ALL} "
                f"from {Fore.YELLOW}{src_ip}:{src_port}{Style.RESET_ALL}: "
                f"{Fore.RED}{canary_name}{Style.RESET_ALL} triggered by "
                f"{Fore.RED}{attacker_ip}{Style.RESET_ALL}"
            )
            
            print(output)
        
        except Exception as e:
            logger.debug(f"[UDPListener] Error printing alert: {e}")
    
    def get_statistics(self) -> dict:
        """
        Get listener statistics
        
        Returns:
            Dictionary with packet counts
        """
        return {
            "packets_received": self.packets_received,
            "packets_valid": self.packets_valid,
            "packets_invalid": self.packets_invalid,
            "packets_decryption_failed": self.packets_decryption_failed
        }
    
    def stop(self):
        """Stop the UDP listener"""
        try:
            self.running = False
            
            if self.socket:
                self.socket.close()
            
            # Wait for thread to finish
            if self.listener_thread:
                self.listener_thread.join(timeout=2)
            
            logger.info("[UDPListener] ✓ Stopped")
        
        except Exception as e:
            logger.error(f"[UDPListener] Error stopping listener: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.stop()
