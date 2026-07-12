"""
Alert Database Module
SQLAlchemy-based alert logging for Canary-Net with SQLite backend
"""

import logging
import json
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, Index, Float, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func

logger = logging.getLogger(__name__)

Base = declarative_base()


class Alert(Base):
    """
    SQLAlchemy Alert model
    Represents a security alert from a canary service
    """
    __tablename__ = 'alerts'
    
    # Columns
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(36), unique=True, nullable=False, index=True)  # UUID
    canary_name = Column(String(255), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    attacker_ip = Column(String(45), nullable=False, index=True)  # IPv6 support
    attacker_port = Column(Integer, nullable=True)
    behavior = Column(Text, nullable=True, default='UNKNOWN')
    threat_score = Column(Integer, nullable=False, default=0)
    threat_level = Column(Text, nullable=True, default='INFO')
    is_proxy = Column(Integer, nullable=False, default=0)
    is_tor = Column(Integer, nullable=False, default=0)
    is_datacenter = Column(Integer, nullable=False, default=0)
    geo_country = Column(Text, nullable=True)
    geo_country_code = Column(Text, nullable=True)
    geo_city = Column(Text, nullable=True)
    geo_lat = Column(Float, nullable=True)
    geo_lon = Column(Float, nullable=True)
    geo_isp = Column(Text, nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    fake_data_touched = Column(Text, nullable=True, default='false')
    acknowledged = Column(Boolean, default=False, nullable=False, index=True)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'canary_name': self.canary_name,
            'port': self.port,
            'attacker_ip': self.attacker_ip,
            'attacker_port': self.attacker_port,
            'behavior': self.behavior,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level,
            'is_proxy': self.is_proxy,
            'is_tor': self.is_tor,
            'is_datacenter': self.is_datacenter,
            'geo_country': self.geo_country,
            'geo_country_code': self.geo_country_code,
            'geo_city': self.geo_city,
            'geo_lat': self.geo_lat,
            'geo_lon': self.geo_lon,
            'geo_isp': self.geo_isp,
            'timestamp': self.timestamp.isoformat() + 'Z' if self.timestamp else None,
            'fake_data_touched': self.fake_data_touched,
            'acknowledged': self.acknowledged
        }


class CanaryDB:
    """
    Canary Alert Database
    
    SQLAlchemy-based database for persistent alert storage.
    Provides thread-safe CRUD operations and advanced querying.
    """
    
    def __init__(self, db_path: str = "alerts.db"):
        """
        Initialize Canary Database
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        
        # Create engine and session factory
        db_url = f"sqlite:///{str(self.db_path)}"
        self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
        self._migrate_schema()
        
        logger.debug(f"[CanaryDB] Initialized at {self.db_path}")

    def _migrate_schema(self) -> None:
        """Add any missing alert columns for existing SQLite databases."""
        try:
            with self.engine.connect() as connection:
                existing_columns = {
                    row[1]
                    for row in connection.execute(text("PRAGMA table_info(alerts)")).fetchall()
                }

                for column_name, definition in [
                    ("threat_score", "INTEGER DEFAULT 0"),
                    ("threat_level", "TEXT DEFAULT 'INFO'"),
                    ("behavior", "TEXT DEFAULT 'UNKNOWN'"),
                    ("is_proxy", "INTEGER DEFAULT 0"),
                    ("is_tor", "INTEGER DEFAULT 0"),
                    ("is_datacenter", "INTEGER DEFAULT 0"),
                    ("geo_country", "TEXT"),
                    ("geo_country_code", "TEXT"),
                    ("geo_city", "TEXT"),
                    ("geo_lat", "REAL"),
                    ("geo_lon", "REAL"),
                    ("geo_isp", "TEXT"),
                ]:
                    if column_name not in existing_columns:
                        connection.execute(text(f"ALTER TABLE alerts ADD COLUMN {column_name} {definition}"))

                connection.commit()
        except Exception as e:
            logger.error(f"[CanaryDB] Failed to migrate alert schema: {e}", exc_info=True)
    
    def _get_session(self) -> Session:
        """Get database session"""
        return self.SessionLocal()

    def clear_all_alerts(self) -> None:
        """Delete all alerts from the database."""
        with self._lock:
            session = self._get_session()
            try:
                session.execute(text("DELETE FROM alerts"))
                session.commit()
                print("[CanaryDB] All alerts cleared")
            finally:
                session.close()
    
    def save_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Save alert to database
        
        Args:
            alert: Alert dictionary with required fields:
                   alert_id, canary_name, attacker_ip, timestamp, etc.
            
        Returns:
            True if successfully saved, False otherwise
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                alert_id = alert.get('alert_id')

                if not alert_id:
                    logger.warning("[CanaryDB] Skipping alert without alert_id")
                    return False

                existing = session.query(Alert).filter_by(alert_id=alert_id).first()
                if existing:
                    logger.debug(f"[CanaryDB] Duplicate alert skipped: {alert_id}")
                    return True
                
                # Parse timestamp if it's a string
                timestamp = alert.get('timestamp')
                if isinstance(timestamp, str):
                    # Remove 'Z' suffix if present
                    timestamp = timestamp.rstrip('Z')
                    timestamp = datetime.fromisoformat(timestamp)
                
                # Create alert record
                alert_record = Alert(
                    alert_id=alert_id,
                    canary_name=alert.get('canary_name'),
                    port=alert.get('port'),
                    attacker_ip=alert.get('attacker_ip'),
                    attacker_port=alert.get('attacker_port'),
                    behavior=alert.get('behavior', 'UNKNOWN'),
                    threat_score=int(alert.get('threat_score', 0) or 0),
                    threat_level=str(alert.get('threat_level', 'INFO')),
                    is_proxy=int(alert.get('is_proxy', 0) or 0),
                    is_tor=int(alert.get('is_tor', 0) or 0),
                    is_datacenter=int(alert.get('is_datacenter', 0) or 0),
                    geo_country=alert.get('geo_country'),
                    geo_country_code=alert.get('geo_country_code'),
                    geo_city=alert.get('geo_city'),
                    geo_lat=alert.get('geo_lat'),
                    geo_lon=alert.get('geo_lon'),
                    geo_isp=alert.get('geo_isp'),
                    timestamp=timestamp or datetime.utcnow(),
                    fake_data_touched=str(alert.get('fake_data_touched', 'false')).lower(),
                    acknowledged=False
                )
                
                session.add(alert_record)
                session.commit()
                
                logger.debug(f"[CanaryDB] Saved alert: {alert.get('alert_id')}")
                return True
        
        except Exception as e:
            logger.error(f"[CanaryDB] Failed to save alert: {e}", exc_info=True)
            return False
        
        finally:
            if session:
                session.close()
    
    def get_all_alerts(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Get all alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries ordered by timestamp DESC
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                alerts = session.query(Alert)\
                    .order_by(Alert.timestamp.desc())\
                    .limit(limit)\
                    .all()
                
                return [alert.to_dict() for alert in alerts]
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error fetching all alerts: {e}")
            return []
        
        finally:
            if session:
                session.close()
    
    def get_alerts_by_ip(self, ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get alerts from specific attacker IP
        
        Args:
            ip: Attacker IP address
            limit: Maximum number of alerts to return
            
        Returns:
            List of alert dictionaries ordered by timestamp DESC
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                alerts = session.query(Alert)\
                    .filter(Alert.attacker_ip == ip)\
                    .order_by(Alert.timestamp.desc())\
                    .limit(limit)\
                    .all()
                
                return [alert.to_dict() for alert in alerts]
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error fetching alerts by IP: {e}")
            return []
        
        finally:
            if session:
                session.close()
    
    def get_unacknowledged(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get unacknowledged alerts
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of unacknowledged alert dictionaries ordered by timestamp DESC
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                alerts = session.query(Alert)\
                    .filter(Alert.acknowledged == False)\
                    .order_by(Alert.timestamp.desc())\
                    .limit(limit)\
                    .all()
                
                return [alert.to_dict() for alert in alerts]
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error fetching unacknowledged alerts: {e}")
            return []
        
        finally:
            if session:
                session.close()
    
    def acknowledge(self, alert_id: str) -> bool:
        """
        Mark alert as acknowledged
        
        Args:
            alert_id: UUID of alert to acknowledge
            
        Returns:
            True if successfully acknowledged, False otherwise
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                alert = session.query(Alert)\
                    .filter(Alert.alert_id == alert_id)\
                    .first()
                
                if not alert:
                    logger.warning(f"[CanaryDB] Alert not found: {alert_id}")
                    return False
                
                alert.acknowledged = True
                session.commit()
                
                logger.debug(f"[CanaryDB] Acknowledged alert: {alert_id}")
                return True
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error acknowledging alert: {e}")
            return False
        
        finally:
            if session:
                session.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics
        
        Returns:
            Dictionary with:
            - total: Total alert count
            - unacknowledged: Count of unacknowledged alerts
            - by_canary: Dict of canary_name -> count
            - by_attacker: Dict of attacker_ip -> count
            - last_24h: Alert count from last 24 hours
        """
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                # Total count
                total = session.query(func.count(Alert.id)).scalar() or 0
                
                # Unacknowledged count
                unacknowledged = session.query(func.count(Alert.id))\
                    .filter(Alert.acknowledged == False)\
                    .scalar() or 0
                
                # By canary name
                by_canary = {}
                canary_counts = session.query(Alert.canary_name, func.count(Alert.id))\
                    .group_by(Alert.canary_name)\
                    .all()
                for canary, count in canary_counts:
                    by_canary[canary] = count
                
                # By attacker IP
                by_attacker = {}
                attacker_counts = session.query(Alert.attacker_ip, func.count(Alert.id))\
                    .group_by(Alert.attacker_ip)\
                    .all()
                for ip, count in attacker_counts:
                    by_attacker[ip] = count
                
                # Last 24 hours
                cutoff_time = datetime.utcnow() - timedelta(hours=24)
                last_24h = session.query(func.count(Alert.id))\
                    .filter(Alert.timestamp >= cutoff_time)\
                    .scalar() or 0
                
                return {
                    'total': total,
                    'unacknowledged': unacknowledged,
                    'by_canary': by_canary,
                    'by_attacker': by_attacker,
                    'last_24h': last_24h
                }
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error getting statistics: {e}")
            return {
                'total': 0,
                'unacknowledged': 0,
                'by_canary': {},
                'by_attacker': {},
                'last_24h': 0
            }
        
        finally:
            if session:
                session.close()
    
    # Legacy methods for backward compatibility
    
    def log_alert(self, alert: Dict[str, Any]) -> bool:
        """Legacy method - delegates to save_alert"""
        return self.save_alert(alert)
    
    def get_alerts_by_attacker(self, attacker_ip: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Legacy method - delegates to get_alerts_by_ip"""
        return self.get_alerts_by_ip(attacker_ip, limit)
    
    def get_alerts_by_canary(self, canary_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get alerts by canary name"""
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                alerts = session.query(Alert)\
                    .filter(Alert.canary_name == canary_name)\
                    .order_by(Alert.timestamp.desc())\
                    .limit(limit)\
                    .all()
                
                return [alert.to_dict() for alert in alerts]
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error fetching alerts by canary: {e}")
            return []
        
        finally:
            if session:
                session.close()
    
    def get_recent_alerts(self, hours: int = 24, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        session = None
        try:
            with self._lock:
                session = self._get_session()
                
                cutoff_time = datetime.utcnow() - timedelta(hours=hours)
                
                alerts = session.query(Alert)\
                    .filter(Alert.timestamp >= cutoff_time)\
                    .order_by(Alert.timestamp.desc())\
                    .limit(limit)\
                    .all()
                
                return [alert.to_dict() for alert in alerts]
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error fetching recent alerts: {e}")
            return []
        
        finally:
            if session:
                session.close()
    
    def get_alert_count(self) -> int:
        """Get total alert count"""
        session = None
        try:
            with self._lock:
                session = self._get_session()
                count = session.query(func.count(Alert.id)).scalar() or 0
                return count
        
        except Exception as e:
            logger.error(f"[CanaryDB] Error getting alert count: {e}")
            return 0
        
        finally:
            if session:
                session.close()
    
    def close(self):
        """Close database connection"""
        try:
            self.engine.dispose()
            logger.debug("[CanaryDB] Database closed")
        except Exception as e:
            logger.error(f"[CanaryDB] Error closing database: {e}")


# Alias for backward compatibility
AlertDatabase = CanaryDB
