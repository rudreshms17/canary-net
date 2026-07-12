"""
Alert Manager
Central alert handling with multi-channel dispatch and persistence
"""

import logging
import uuid
import threading
from datetime import datetime
from colorama import Fore, Back, Style, init

from alert_engine.tcp_dispatcher import TCPDispatcher
from alert_engine.udp_broadcaster import UDPBroadcaster
from shared.config import Config
from shared.db import CanaryDB

# Initialize colorama (auto-reset=True handles color reset automatically)
init(autoreset=True)

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Central alert management system
    
    Handles alert processing, enrichment, and multi-channel dispatch:
    - TCP to central monitor (reliable, authenticated)
    - UDP broadcast to LAN (best-effort, fast)
    - SQLite local backup (persistent)
    - Console output (real-time visibility)
    
    Thread-safe for concurrent alert handling from multiple canaries.
    """
    
    def __init__(self, db, crypto):
        """
        Initialize Alert Manager
        
        Args:
            db: CanaryDB database instance for alert persistence
            crypto: AlertCrypto instance for alert encryption
        """
        self.db = db
        self.crypto = crypto
        
        # Load configuration to get monitor host/port
        cfg = Config()
        
        # Initialize TCP dispatcher for central monitor
        try:
            monitor_host = cfg.get_monitor_host()
            monitor_port = cfg.get_monitor_port()
            self.tcp_dispatcher = TCPDispatcher(
                host=monitor_host,
                port=monitor_port,
                crypto=crypto
            )
        except Exception as e:
            logger.warning(f"[AlertManager] Failed to initialize TCP dispatcher: {e}")
            self.tcp_dispatcher = None
        
        # Initialize UDP broadcaster for LAN alerts
        try:
            broadcast_port = cfg.get_broadcast_port()
            self.udp_broadcaster = UDPBroadcaster(
                port=broadcast_port,
                crypto=crypto
            )
        except Exception as e:
            logger.warning(f"[AlertManager] Failed to initialize UDP broadcaster: {e}")
            self.udp_broadcaster = None
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Statistics
        self.alerts_processed = 0
        self.tcp_sent = 0
        self.udp_sent = 0
        self.db_logged = 0
        
        logger.debug(
            "[AlertManager] Initialized with "
            f"TCP={self.tcp_dispatcher is not None}, "
            f"UDP={self.udp_broadcaster is not None}"
        )
    
    def on_alert(self, alert: dict) -> bool:
        """
        Receive alert from a canary and process it
        
        This method is called by canaries when they detect an attack.
        It's an alias for handle_alert() for consistency with event handlers.
        
        Args:
            alert: Alert dictionary from canary
            
        Returns:
            True if processed successfully, False otherwise
        """
        return self.handle_alert(alert)
    
    def handle_alert(self, alert: dict) -> bool:
        """
        Handle incoming alert from canary
        
        Processes alert through all channels:
        1. Add unique alert_id (UUID4)
        2. Dispatch via TCP to central monitor
        3. Broadcast via UDP to local network
        4. Write to SQLite backup
        5. Print colorized summary to console
        
        Thread-safe for concurrent calls from multiple canary threads.
        
        Args:
            alert: Alert dictionary from canary
            
        Returns:
            True if processed successfully, False otherwise
        """
        try:
            with self.lock:
                # Generate unique alert ID
                alert_id = str(uuid.uuid4())
                alert['alert_id'] = alert_id
                
                # Add processing timestamp if not present
                if 'timestamp' not in alert:
                    alert['timestamp'] = datetime.utcnow().isoformat() + 'Z'
                
                # Increment counter
                self.alerts_processed += 1
                
                # Log to console (immediate visibility)
                self._print_alert_summary(alert)
                
                # TCP dispatch (reliable)
                if self.tcp_dispatcher:
                    if self.tcp_dispatcher.dispatch(alert):
                        self.tcp_sent += 1
                    else:
                        logger.warning(
                            f"[AlertManager] TCP dispatch failed for alert {alert_id}"
                        )
                
                # UDP broadcast (best-effort)
                if self.udp_broadcaster:
                    if self.udp_broadcaster.broadcast(alert):
                        self.udp_sent += 1
                    else:
                        logger.debug(
                            f"[AlertManager] UDP broadcast failed for alert {alert_id}"
                        )
                
                # Database logging (backup)
                if self.db.log_alert(alert):
                    self.db_logged += 1
                else:
                    logger.warning(
                        f"[AlertManager] Database logging failed for alert {alert_id}"
                    )
                
                logger.debug(
                    f"[AlertManager] ✓ Alert processed: {alert_id} "
                    f"from {alert.get('canary_name')} "
                    f"({alert.get('attacker_ip')})"
                )
                
                return True
        
        except Exception as e:
            logger.error(
                f"[AlertManager] Error handling alert: {e}",
                exc_info=True
            )
            return False
    
    def _print_alert_summary(self, alert: dict):
        """
        Print colorized alert summary to console
        
        Uses colorama for cross-platform colored output:
        - RED: Canary name, attacker IP
        - YELLOW: Timestamp
        - Default: Other information
        
        Args:
            alert: Alert dictionary
        """
        try:
            canary_name = alert.get('canary_name', 'UNKNOWN')
            attacker_ip = alert.get('attacker_ip', 'UNKNOWN')
            attacker_port = alert.get('attacker_port', '?')
            port = alert.get('port', '?')
            behavior = alert.get('behavior', 'UNKNOWN')
            timestamp = alert.get('timestamp', '')
            alert_id = alert.get('alert_id', '')
            
            # Build colorized output
            output = []
            output.append("")  # Blank line for readability
            output.append("=" * 80)
            
            # Header with timestamp
            output.append(
                f"🚨  {Fore.RED}{Style.BRIGHT}ALERT{Style.RESET_ALL} "
                f"[{Fore.YELLOW}{timestamp}{Style.RESET_ALL}]"
            )
            
            # Canary and attacker info
            output.append(
                f"   Canary:  {Fore.RED}{Style.BRIGHT}{canary_name}{Style.RESET_ALL}"
            )
            output.append(
                f"   Port:    {port}"
            )
            output.append(
                f"   Attacker: {Fore.RED}{attacker_ip}:{attacker_port}{Style.RESET_ALL}"
            )
            
            # Behavior
            output.append(
                f"   Behavior: {behavior[:70]}"
            )
            
            # Alert ID
            output.append(
                f"   Alert ID: {alert_id}"
            )
            
            output.append("=" * 80)
            output.append("")
            
            # Print to console
            print("\n".join(output))
        
        except Exception as e:
            logger.warning(f"[AlertManager] Error printing alert summary: {e}")
    
    def get_statistics(self) -> dict:
        """
        Get alert handling statistics
        
        Returns:
            Dictionary with processing statistics
        """
        with self.lock:
            return {
                "alerts_processed": self.alerts_processed,
                "tcp_sent": self.tcp_sent,
                "udp_sent": self.udp_sent,
                "db_logged": self.db_logged,
                "db_total_alerts": self.db.get_alert_count()
            }
    
    def close(self):
        """Close all resources"""
        try:
            if self.tcp_dispatcher:
                self.tcp_dispatcher.close()
            
            if self.udp_broadcaster:
                self.udp_broadcaster.close()
            
            if self.db:
                self.db.close()
            
            logger.info("[AlertManager] All resources closed")
        
        except Exception as e:
            logger.error(f"[AlertManager] Error closing resources: {e}")
    
    def __del__(self):
        """Cleanup on object destruction"""
        self.close()
