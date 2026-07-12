"""
UDP Broadcaster
Sends encrypted alerts via UDP broadcast for local network detection
"""

import logging
import socket
import struct
from typing import Optional
from shared.crypto import AlertCrypto, CanaryCryptoError

logger = logging.getLogger(__name__)

# Magic header for CARY (Canary Alert Relay) protocol
CARY_MAGIC = b'CARY'


class UDPBroadcaster:
    """
    Broadcast encrypted alerts via UDP
    
    Uses UDP broadcast (255.255.255.255) for fire-and-forget alert delivery
    to all systems on the local network segment. Non-blocking, best-effort.
    """
    
    def __init__(self, port: int, crypto):
        """
        Initialize UDP Broadcaster
        
        Args:
            port: Port to broadcast alerts on
            crypto: AlertCrypto instance for encryption
        """
        self.port = port
        self.crypto = crypto
        self.socket: Optional[socket.socket] = None
        self._init_socket()
        
        logger.debug(
            f"[UDPBroadcaster] Initialized for broadcast on port {port}"
        )
    
    def _init_socket(self) -> bool:
        """
        Initialize UDP socket with broadcast capability
        
        Returns:
            True if socket initialized successfully, False otherwise
        """
        try:
            # Create UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Enable broadcast
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Set non-blocking mode (fire-and-forget)
            self.socket.setblocking(False)
            
            logger.debug("[UDPBroadcaster] Socket initialized with SO_BROADCAST")
            return True
        
        except Exception as e:
            logger.error(f"[UDPBroadcaster] Failed to initialize socket: {e}", exc_info=True)
            return False
    
    def broadcast(self, alert: dict) -> bool:
        """
        Broadcast alert via UDP
        
        Non-blocking, fire-and-forget operation. Alert is encrypted and sent
        to the broadcast address (255.255.255.255) on the configured port.
        
        Message format:
        - 4 bytes: Magic header b'CARY'
        - 4 bytes (big-endian): Length of encrypted payload
        - N bytes: Encrypted alert data
        
        Args:
            alert: Alert dictionary to broadcast
            
        Returns:
            True if successfully sent, False otherwise
        """
        try:
            # Encrypt the alert
            try:
                encrypted_alert = self.crypto.encrypt(alert)
                logger.debug(
                    f"[UDPBroadcaster] Encrypted alert ({len(encrypted_alert)} bytes): "
                    f"{alert.get('canary_name', 'unknown')} - "
                    f"{alert.get('behavior', 'unknown')[:50]}"
                )
            except CanaryCryptoError as e:
                logger.error(f"[UDPBroadcaster] Failed to encrypt alert: {e}")
                return False
            
            # Build message: MAGIC_HEADER + LENGTH + ENCRYPTED_DATA
            alert_length = len(encrypted_alert)
            length_prefix = struct.pack('>I', alert_length)
            message = CARY_MAGIC + length_prefix + encrypted_alert
            
            logger.debug(
                f"[UDPBroadcaster] Broadcasting {len(message)} bytes "
                f"(magic={len(CARY_MAGIC)} + length={len(length_prefix)} + payload={alert_length})"
            )
            
            # Send via UDP broadcast (non-blocking, best-effort)
            self.socket.sendto(message, ('255.255.255.255', self.port))
            
            logger.debug(
                f"[UDPBroadcaster] ✓ Alert broadcast successfully "
                f"on port {self.port}: "
                f"{alert.get('canary_name', 'unknown')} - "
                f"{alert.get('behavior', 'unknown')[:60]}"
            )
            return True
        
        except BlockingIOError:
            # Non-blocking socket would block (buffer full) - acceptable for best-effort
            logger.warning(
                f"[UDPBroadcaster] Broadcast buffer full (non-blocking) - alert dropped: "
                f"{alert.get('canary_name', 'unknown')}"
            )
            return False
        
        except socket.error as e:
            logger.warning(
                f"[UDPBroadcaster] Socket error during broadcast: {e}"
            )
            return False
        
        except Exception as e:
            logger.error(
                f"[UDPBroadcaster] Unexpected error during broadcast: {e}",
                exc_info=True
            )
            return False
    
    def close(self):
        """Close the UDP socket"""
        try:
            if self.socket:
                self.socket.close()
            logger.info("[UDPBroadcaster] Socket closed")
        except Exception as e:
            logger.warning(f"[UDPBroadcaster] Error closing socket: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.close()
