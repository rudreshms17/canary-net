"""
Base Canary Class
Abstract base class for all honeypot canary services
"""

from abc import ABC, abstractmethod
import threading
import logging
from datetime import datetime, timezone
from typing import Callable, Dict, Any

logger = logging.getLogger(__name__)


class BaseCanary(ABC):
    """
    Abstract base class for honeypot canary services
    
    All canary implementations must inherit from this class and implement
    the start() and stop() abstract methods.
    """
    
    def __init__(
        self,
        port: int,
        name: str,
        fake_data: dict,
        alert_callback: Callable[[Dict[str, Any]], None]
    ):
        """
        Initialize a canary service
        
        Args:
            port: Port number to listen on
            name: Friendly name for this canary (e.g., 'SSH-Honeypot-1')
            fake_data: Dictionary of fake data to track if touched
                      (e.g., {'creds': 'admin:password123'})
            alert_callback: Callable that receives alert dict when triggered
        """
        self.port = port
        self.name = name
        self.fake_data = fake_data
        self.alert_callback = alert_callback
        self.running = False
        self._lock = threading.Lock()
    
    @abstractmethod
    def start(self):
        """
        Start the canary listener
        
        This method must be implemented by subclasses to begin listening
        for incoming connections on the specified port.
        """
        pass
    
    @abstractmethod
    def stop(self):
        """
        Stop the canary listener
        
        This method must be implemented by subclasses to cleanly shut down
        the listener and release resources.
        """
        pass
    
    def _trigger_alert(
        self,
        attacker_ip: str,
        attacker_port: int,
        behavior: str,
        fake_data_touched: bool = False
    ):
        """
        Trigger an alert when suspicious activity is detected
        
        Thread-safe method that records the incident and dispatches alert
        to the configured callback.
        
        Args:
            attacker_ip: IP address of the attacker
            attacker_port: Source port of the attacker
            behavior: Description of suspicious behavior detected
                     (e.g., 'invalid_login_attempt', 'banner_probe', 'payload_sent')
            fake_data_touched: Whether fake data was accessed/interacted with
        """
        with self._lock:
            try:
                # Record timestamp in UTC ISO 8601 format
                timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', '') + "Z"
                
                # Build alert dictionary
                alert = {
                    "canary_name": self.name,
                    "port": self.port,
                    "attacker_ip": attacker_ip,
                    "attacker_port": attacker_port,
                    "behavior": behavior,
                    "timestamp": timestamp,
                    "fake_data_touched": fake_data_touched
                }
                
                # Log the alert locally
                logger.warning(
                    f"[{self.name}] ALERT: {behavior} from {attacker_ip}:{attacker_port}"
                )
                
                # Dispatch alert via callback
                self.alert_callback(alert)
                
            except Exception as e:
                logger.error(f"Error triggering alert: {e}", exc_info=True)
