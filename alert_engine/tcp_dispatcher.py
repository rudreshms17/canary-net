"""
TCP Alert Dispatcher
Sends encrypted alerts to central monitor over TCP with retry logic
"""

import logging
import socket
import time
import struct
import threading
from typing import Optional
from shared.crypto import AlertCrypto, CanaryCryptoError

logger = logging.getLogger(__name__)


class TCPDispatcher:
    """
    Dispatch encrypted alerts to central monitor via TCP
    
    Uses persistent connection with automatic reconnection.
    Implements retry logic with exponential backoff for reliability.
    """
    
    def __init__(self, host: str, port: int, crypto):
        """
        Initialize TCP Dispatcher
        
        Args:
            host: Hostname or IP of central monitor
            port: Port number of central monitor
            crypto: AlertCrypto instance for encryption
        """
        self.host = host
        self.port = port
        self.crypto = crypto
        self.socket = None
        self.lock = threading.Lock()
        self.connected = False
        
        logger.info(
            f"[TCPDispatcher] Initialized with monitor at {host}:{port}"
        )
    
    def _connect(self) -> bool:
        """
        Establish TCP connection to monitor
        
        Returns:
            True if successfully connected, False otherwise
        """
        try:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)  # 5 second timeout
            
            logger.debug(
                f"[TCPDispatcher] Connecting to {self.host}:{self.port}..."
            )
            
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            logger.info(
                f"[TCPDispatcher] Connected to monitor at {self.host}:{self.port}"
            )
            
            return True
        
        except socket.timeout:
            logger.warning(
                f"[TCPDispatcher] Connection timeout to {self.host}:{self.port}"
            )
            self.connected = False
            return False
        
        except ConnectionRefusedError:
            logger.warning(
                f"[TCPDispatcher] Connection refused by {self.host}:{self.port}"
            )
            self.connected = False
            return False
        
        except OSError as e:
            logger.warning(
                f"[TCPDispatcher] Failed to connect: {e}"
            )
            self.connected = False
            return False
        
        except Exception as e:
            logger.error(
                f"[TCPDispatcher] Unexpected error during connection: {e}",
                exc_info=True
            )
            self.connected = False
            return False
    
    def _send_encrypted_alert(self, encrypted_data: bytes) -> bool:
        """
        Send encrypted alert data over socket with length prefix
        
        Message format:
        - 4 bytes (big-endian): Length of encrypted payload
        - N bytes: Encrypted payload
        
        Args:
            encrypted_data: Encrypted alert bytes
            
        Returns:
            True if successfully sent, False otherwise
        """
        try:
            # Create length prefix (4 bytes, big-endian)
            length = len(encrypted_data)
            length_prefix = struct.pack('>I', length)
            
            # Send length prefix + payload
            message = length_prefix + encrypted_data
            
            logger.debug(
                f"[TCPDispatcher] Sending {length} bytes of encrypted alert "
                f"({len(message)} with prefix)"
            )
            
            self.socket.sendall(message)
            
            logger.debug("[TCPDispatcher] Alert sent successfully")
            return True
        
        except socket.timeout:
            logger.warning("[TCPDispatcher] Send timeout - monitor not responding")
            self.connected = False
            return False
        
        except ConnectionResetError:
            logger.warning("[TCPDispatcher] Connection reset by monitor")
            self.connected = False
            return False
        
        except BrokenPipeError:
            logger.warning("[TCPDispatcher] Broken pipe - connection lost")
            self.connected = False
            return False
        
        except Exception as e:
            logger.error(
                f"[TCPDispatcher] Error sending alert: {e}",
                exc_info=True
            )
            self.connected = False
            return False
    
    def dispatch(self, alert: dict) -> bool:
        """
        Dispatch alert to monitor with retry logic
        
        Implements 3 retry attempts with 2-second backoff:
        - Attempt 1: Immediate
        - Attempt 2: After 2 seconds
        - Attempt 3: After 4 seconds
        
        Args:
            alert: Alert dictionary to dispatch
            
        Returns:
            True if alert was successfully dispatched, False otherwise
        """
        try:
            # Encrypt the alert
            try:
                encrypted_alert = self.crypto.encrypt(alert)
                logger.debug(
                    f"[TCPDispatcher] Encrypted alert ({len(encrypted_alert)} bytes): "
                    f"{alert.get('canary_name', 'unknown')} - "
                    f"{alert.get('behavior', 'unknown')}"
                )
            except CanaryCryptoError as e:
                logger.error(f"[TCPDispatcher] Failed to encrypt alert: {e}")
                return False
            
            # Retry logic: 3 attempts with 2-second backoff
            max_retries = 3
            backoff_seconds = 2
            
            for attempt in range(1, max_retries + 1):
                logger.debug(
                    f"[TCPDispatcher] Dispatch attempt {attempt}/{max_retries}"
                )
                
                # Ensure connection is established
                if not self.connected:
                    if not self._connect():
                        if attempt < max_retries:
                            logger.debug(
                                f"[TCPDispatcher] Connection failed, retrying in {backoff_seconds}s..."
                            )
                            time.sleep(backoff_seconds)
                        continue
                
                # Try to send the alert
                if self._send_encrypted_alert(encrypted_alert):
                    logger.info(
                        f"[TCPDispatcher] ✓ Alert dispatched successfully "
                        f"(attempt {attempt}/{max_retries}): "
                        f"{alert.get('canary_name', 'unknown')} - "
                        f"{alert.get('behavior', 'unknown')[:60]}"
                    )
                    return True
                
                # If send failed and we have retries left, backoff and retry
                if attempt < max_retries:
                    logger.warning(
                        f"[TCPDispatcher] Send failed on attempt {attempt}, "
                        f"retrying in {backoff_seconds}s..."
                    )
                    time.sleep(backoff_seconds)
            
            # All retries exhausted
            logger.error(
                f"[TCPDispatcher] ✗ Failed to dispatch alert after {max_retries} attempts: "
                f"{alert.get('canary_name', 'unknown')} - "
                f"{alert.get('behavior', 'unknown')[:60]}"
            )
            return False
        
        except Exception as e:
            logger.error(
                f"[TCPDispatcher] Unexpected error during dispatch: {e}",
                exc_info=True
            )
            return False
    
    def close(self):
        """Close the TCP connection"""
        try:
            if self.socket:
                self.socket.close()
            self.connected = False
            logger.info("[TCPDispatcher] Connection closed")
        except Exception as e:
            logger.warning(f"[TCPDispatcher] Error closing connection: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.close()
