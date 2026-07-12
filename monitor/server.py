"""
Central monitor server
Listens for alerts from canary services
"""

import logging
from datetime import datetime
from typing import List, Callable

from shared.behavior_classifier import BehaviorClassifier
from shared.geoip_service import GeoIPService
from shared.proxy_detector import ProxyDetector
from shared.threat_scorer import ThreatScorer

logger = logging.getLogger(__name__)


class MonitorServer:
    """Central monitoring server"""

    def __init__(self, host: str = "0.0.0.0", port: int = 5000):
        self.host = host
        self.port = port
        self.running = False
        self.alert_handlers: List[Callable] = []
        self.alert_history = []
        self.threat_scorer = ThreatScorer()
        self.proxy_detector = ProxyDetector()
        self.behavior_classifier = BehaviorClassifier()
        self.geoip_service = GeoIPService()
        self.ip_sessions = {}

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

    def enrich_alert(self, alert: dict) -> dict:
        """Enrich an alert with scoring, proxy, geo, and behavior context."""
        ip = alert.get("ip", "")

        try:
            session = self.ip_sessions.get(ip)
            if session is None:
                session = {
                    "total_attempts": 0,
                    "unique_ports": set(),
                    "unique_services": set(),
                    "last_seen": None,
                    "avg_interval_ms": 0.0,
                }

            now = datetime.utcnow()
            session["total_attempts"] += 1
            port = alert.get("port")
            if port is not None:
                session["unique_ports"].add(port)
            service = alert.get("service")
            if service is not None:
                session["unique_services"].add(service)

            last_seen = session.get("last_seen")
            if last_seen is not None:
                interval_ms = (now - last_seen).total_seconds() * 1000
                total_attempts = session["total_attempts"]
                session["avg_interval_ms"] = (
                    (session["avg_interval_ms"] * (total_attempts - 1)) + interval_ms
                ) / total_attempts
            else:
                session["avg_interval_ms"] = 0.0

            session["last_seen"] = now
            self.ip_sessions[ip] = session
        except Exception as exc:
            logger.error(f"Error updating IP sessions: {exc}")

        try:
            threat_score = self.threat_scorer.score(alert)
            proxy_bonus = self.proxy_detector.get_score_bonus(ip)
            total_score = min(100, threat_score + proxy_bonus)
            alert["threat_score"] = total_score
            alert["threat_level"] = self.threat_scorer.get_threat_level(total_score)
        except Exception as exc:
            logger.error(f"Error computing threat score: {exc}")

        try:
            proxy_info = self.proxy_detector.check_ip(ip)
            alert["is_proxy"] = proxy_info.get("is_proxy", False)
            alert["is_tor"] = proxy_info.get("is_tor", False)
            alert["is_datacenter"] = proxy_info.get("is_datacenter", False)
            alert["risk_level"] = proxy_info.get("risk_level", "UNKNOWN")
        except Exception as exc:
            logger.error(f"Error enriching proxy info: {exc}")

        try:
            geo_info = self.geoip_service.lookup(ip)
            alert["geo_country"] = geo_info.get("country", "Unknown")
            alert["geo_country_code"] = geo_info.get("country_code", "??")
            alert["geo_city"] = geo_info.get("city", "Unknown")
            alert["geo_lat"] = geo_info.get("lat", 0.0)
            alert["geo_lon"] = geo_info.get("lon", 0.0)
            alert["geo_isp"] = geo_info.get("isp", "Unknown")
        except Exception as exc:
            logger.error(f"Error enriching geo info: {exc}")

        try:
            session_data = self.ip_sessions.get(ip)
            if session_data is None:
                session_data = {"total_attempts": 0, "unique_ports_hit": 0, "unique_services_hit": 0, "avg_interval_ms": 0.0}
            behavior_session = {
                "total_attempts": session_data.get("total_attempts", 0),
                "unique_ports_hit": len(session_data.get("unique_ports", set())),
                "unique_services_hit": len(session_data.get("unique_services", set())),
                "avg_interval_ms": session_data.get("avg_interval_ms", 0.0),
            }
            behavior = self.behavior_classifier.classify(behavior_session)
            alert["behavior"] = behavior
            alert["behavior_description"] = self.behavior_classifier.get_risk_description(behavior)
        except Exception as exc:
            logger.error(f"Error classifying behavior: {exc}")

        return alert

    def process_alert(self, alert_data: dict):
        """Process incoming alert"""
        enriched_alert = self.enrich_alert(alert_data)
        self.alert_history.append(enriched_alert)
        logger.warning(f"ALERT RECEIVED: {enriched_alert}")

        for handler in self.alert_handlers:
            try:
                handler(enriched_alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}")
