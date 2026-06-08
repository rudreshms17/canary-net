"""
Central monitor server
Listens for alerts from canary services
"""

import logging
from typing import List, Callable

logger = logging.getLogger(__name__)


class MonitorServer:
    """Central monitoring server"""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5000):
        self.host = host
        self.port = port
        self.running = False
        self.alert_handlers: List[Callable] = []
        self.alert_history = []
    
    def start(self):
        """Start monitor server"""
        logger.info(f"Starting Monitor Server on {self.host}:{self.port}")
        self.running = True
    
    def stop(self):
        """Stop monitor server"""
        logger.info("Stopping Monitor Server")
        self.running = False
    
    def register_handler(self, handler: Callable):
        """Register alert handler"""
        self.alert_handlers.append(handler)
    
    def process_alert(self, alert_data: dict):
        """Process incoming alert"""
        self.alert_history.append(alert_data)
        logger.warning(f"ALERT RECEIVED: {alert_data}")
        
        for handler in self.alert_handlers:
            try:
                handler(alert_data)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
