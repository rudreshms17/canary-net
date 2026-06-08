"""
Unit tests for CanaryDB SQLAlchemy database
Tests schema, CRUD operations, querying, and statistics
"""

import pytest
import tempfile
import threading
from pathlib import Path
from datetime import datetime, timedelta
from uuid import uuid4

from shared.db import CanaryDB, Alert, Base


class TestCanaryDBInitialization:
    """Test CanaryDB initialization"""
    
    def test_init_creates_database(self):
        """Test database initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            assert db_path.exists()
            db.close()
    
    def test_init_creates_tables(self):
        """Test that schema tables are created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            session = db._get_session()
            # Should not raise exception
            session.query(Alert).count()
            session.close()
            
            db.close()


class TestAlertSchema:
    """Test Alert model schema"""
    
    def test_alert_columns_exist(self):
        """Test that all required columns exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            # Get column names
            columns = [col.name for col in Alert.__table__.columns]
            
            required_columns = [
                'id', 'alert_id', 'canary_name', 'port', 'attacker_ip',
                'attacker_port', 'behavior', 'timestamp', 'fake_data_touched',
                'acknowledged'
            ]
            
            for col in required_columns:
                assert col in columns
            
            db.close()
    
    def test_alert_id_unique(self):
        """Test that alert_id is unique"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            # Check if unique constraint exists
            alert_id_col = Alert.__table__.columns['alert_id']
            assert alert_id_col.unique
            
            db.close()
    
    def test_alert_acknowledged_default_false(self):
        """Test that acknowledged defaults to False"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            ack_col = Alert.__table__.columns['acknowledged']
            assert ack_col.default is not None
            
            db.close()


class TestCanaryDBSaveAlert:
    """Test save_alert method"""
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield CanaryDB(str(db_path))
    
    def test_save_alert_success(self, db):
        """Test saving alert to database"""
        alert = {
            "alert_id": str(uuid4()),
            "canary_name": "SSH-01",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 12345,
            "behavior": "ssh_password_attempt",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        result = db.save_alert(alert)
        
        assert result == True
        assert db.get_alert_count() == 1
    
    def test_save_alert_without_timestamp(self, db):
        """Test saving alert without timestamp (auto-filled)"""
        alert = {
            "alert_id": str(uuid4()),
            "canary_name": "FTP-01",
            "attacker_ip": "192.168.1.101"
        }
        
        result = db.save_alert(alert)
        
        assert result == True
    
    def test_save_multiple_alerts(self, db):
        """Test saving multiple alerts"""
        for i in range(5):
            alert = {
                "alert_id": str(uuid4()),
                "canary_name": f"SSH-{i}",
                "attacker_ip": f"192.168.1.{100+i}",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            db.save_alert(alert)
        
        assert db.get_alert_count() == 5


class TestCanaryDBGetAllAlerts:
    """Test get_all_alerts method"""
    
    @pytest.fixture
    def db_with_alerts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            # Add test data
            for i in range(3):
                alert = {
                    "alert_id": str(uuid4()),
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": f"192.168.1.{100+i}",
                    "timestamp": (datetime.utcnow() - timedelta(hours=i)).isoformat() + "Z"
                }
                db.save_alert(alert)
            
            yield db
    
    def test_get_all_alerts(self, db_with_alerts):
        """Test retrieving all alerts"""
        alerts = db_with_alerts.get_all_alerts()
        
        assert len(alerts) == 3
        assert all('alert_id' in a for a in alerts)
        assert all('canary_name' in a for a in alerts)
    
    def test_get_all_alerts_ordered_by_timestamp_desc(self, db_with_alerts):
        """Test alerts are ordered by timestamp DESC"""
        alerts = db_with_alerts.get_all_alerts()
        
        timestamps = [a['timestamp'] for a in alerts]
        # Verify descending order
        for i in range(len(timestamps) - 1):
            assert timestamps[i] >= timestamps[i+1]
    
    def test_get_all_alerts_respects_limit(self, db_with_alerts):
        """Test limit parameter"""
        alerts = db_with_alerts.get_all_alerts(limit=2)
        
        assert len(alerts) == 2


class TestCanaryDBGetAlertsByIP:
    """Test get_alerts_by_ip method"""
    
    @pytest.fixture
    def db_with_alerts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            attacker_ip = "203.0.113.45"
            
            # Add alerts from same IP
            for i in range(3):
                alert = {
                    "alert_id": str(uuid4()),
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": attacker_ip,
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                db.save_alert(alert)
            
            # Add alerts from different IP
            alert = {
                "alert_id": str(uuid4()),
                "canary_name": "FTP-01",
                "attacker_ip": "10.0.0.1",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            db.save_alert(alert)
            
            yield db, attacker_ip
    
    def test_get_alerts_by_ip(self, db_with_alerts):
        """Test retrieving alerts by attacker IP"""
        db, attacker_ip = db_with_alerts
        
        alerts = db.get_alerts_by_ip(attacker_ip)
        
        assert len(alerts) == 3
        assert all(a['attacker_ip'] == attacker_ip for a in alerts)
    
    def test_get_alerts_by_ip_nonexistent(self, db_with_alerts):
        """Test querying nonexistent IP"""
        db, _ = db_with_alerts
        
        alerts = db.get_alerts_by_ip("1.2.3.4")
        
        assert len(alerts) == 0


class TestCanaryDBGetUnacknowledged:
    """Test get_unacknowledged method"""
    
    @pytest.fixture
    def db_with_mixed_alerts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            alert_ids = []
            
            # Add 3 unacknowledged alerts
            for i in range(3):
                alert_id = str(uuid4())
                alert_ids.append(alert_id)
                alert = {
                    "alert_id": alert_id,
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": f"192.168.1.{i}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                db.save_alert(alert)
            
            # Add 2 acknowledged alerts
            for i in range(2):
                alert_id = str(uuid4())
                alert = {
                    "alert_id": alert_id,
                    "canary_name": f"FTP-{i}",
                    "attacker_ip": f"10.0.0.{i}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                db.save_alert(alert)
                db.acknowledge(alert_id)
            
            yield db, alert_ids
    
    def test_get_unacknowledged(self, db_with_mixed_alerts):
        """Test retrieving unacknowledged alerts"""
        db, alert_ids = db_with_mixed_alerts
        
        alerts = db.get_unacknowledged()
        
        assert len(alerts) == 3
        assert all(a['acknowledged'] == False for a in alerts)
    
    def test_unacknowledged_ordered_by_timestamp_desc(self, db_with_mixed_alerts):
        """Test unacknowledged alerts are ordered DESC"""
        db, _ = db_with_mixed_alerts
        
        alerts = db.get_unacknowledged()
        
        timestamps = [a['timestamp'] for a in alerts]
        for i in range(len(timestamps) - 1):
            assert timestamps[i] >= timestamps[i+1]


class TestCanaryDBAcknowledge:
    """Test acknowledge method"""
    
    @pytest.fixture
    def db_with_alert(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            alert_id = str(uuid4())
            alert = {
                "alert_id": alert_id,
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            db.save_alert(alert)
            
            yield db, alert_id
    
    def test_acknowledge_alert(self, db_with_alert):
        """Test acknowledging an alert"""
        db, alert_id = db_with_alert
        
        result = db.acknowledge(alert_id)
        
        assert result == True
        
        # Verify it's acknowledged
        alerts = db.get_all_alerts()
        assert alerts[0]['acknowledged'] == True
    
    def test_acknowledge_nonexistent_alert(self, db_with_alert):
        """Test acknowledging nonexistent alert"""
        db, _ = db_with_alert
        
        result = db.acknowledge(str(uuid4()))
        
        assert result == False
    
    def test_acknowledge_removes_from_unacknowledged(self, db_with_alert):
        """Test acknowledged alert no longer in unacknowledged"""
        db, alert_id = db_with_alert
        
        db.acknowledge(alert_id)
        
        unack = db.get_unacknowledged()
        assert len(unack) == 0


class TestCanaryDBGetStats:
    """Test get_stats method"""
    
    @pytest.fixture
    def db_with_stats_data(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CanaryDB(str(db_path))
            
            # Add alerts from different canaries and attackers
            canaries = ["SSH-01", "FTP-01", "HTTP-01"]
            attackers = ["192.168.1.100", "192.168.1.101", "203.0.113.45"]
            
            for i in range(9):
                alert = {
                    "alert_id": str(uuid4()),
                    "canary_name": canaries[i % 3],
                    "attacker_ip": attackers[i % 3],
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                db.save_alert(alert)
            
            # Add old alert (outside 24h window)
            old_alert = {
                "alert_id": str(uuid4()),
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "timestamp": (datetime.utcnow() - timedelta(hours=25)).isoformat() + "Z"
            }
            db.save_alert(old_alert)
            
            # Acknowledge some
            session = db._get_session()
            session.query(Alert).limit(2).update({"acknowledged": True})
            session.commit()
            session.close()
            
            yield db
    
    def test_get_stats_structure(self, db_with_stats_data):
        """Test stats dictionary structure"""
        stats = db_with_stats_data.get_stats()
        
        assert 'total' in stats
        assert 'unacknowledged' in stats
        assert 'by_canary' in stats
        assert 'by_attacker' in stats
        assert 'last_24h' in stats
    
    def test_get_stats_total(self, db_with_stats_data):
        """Test total alert count in stats"""
        stats = db_with_stats_data.get_stats()
        
        assert stats['total'] == 10  # 9 recent + 1 old
    
    def test_get_stats_unacknowledged(self, db_with_stats_data):
        """Test unacknowledged count in stats"""
        stats = db_with_stats_data.get_stats()
        
        assert stats['unacknowledged'] == 8  # 10 total - 2 acknowledged
    
    def test_get_stats_by_canary(self, db_with_stats_data):
        """Test canary breakdown in stats"""
        stats = db_with_stats_data.get_stats()
        
        by_canary = stats['by_canary']
        assert 'SSH-01' in by_canary
        assert 'FTP-01' in by_canary
        assert 'HTTP-01' in by_canary
        assert sum(by_canary.values()) == 10
    
    def test_get_stats_by_attacker(self, db_with_stats_data):
        """Test attacker breakdown in stats"""
        stats = db_with_stats_data.get_stats()
        
        by_attacker = stats['by_attacker']
        assert '192.168.1.100' in by_attacker
        assert '192.168.1.101' in by_attacker
        assert '203.0.113.45' in by_attacker
        assert sum(by_attacker.values()) == 10
    
    def test_get_stats_last_24h(self, db_with_stats_data):
        """Test last 24 hours count in stats"""
        stats = db_with_stats_data.get_stats()
        
        assert stats['last_24h'] == 9  # 10 total - 1 old


class TestCanaryDBThreadSafety:
    """Test thread safety"""
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield CanaryDB(str(db_path))
    
    def test_concurrent_saves(self, db):
        """Test concurrent save operations"""
        results = []
        
        def save_alerts(thread_id):
            for i in range(10):
                alert = {
                    "alert_id": str(uuid4()),
                    "canary_name": f"Thread-{thread_id}",
                    "attacker_ip": f"192.168.{thread_id}.{i}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                result = db.save_alert(alert)
                results.append(result)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=save_alerts, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert all(results)  # All saves successful
        assert db.get_alert_count() == 50
    
    def test_concurrent_queries(self, db):
        """Test concurrent query operations"""
        # Add some data first
        for i in range(10):
            alert = {
                "alert_id": str(uuid4()),
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            db.save_alert(alert)
        
        results = []
        
        def query_alerts():
            for _ in range(5):
                alerts = db.get_all_alerts()
                results.append(len(alerts))
        
        threads = []
        for i in range(3):
            t = threading.Thread(target=query_alerts)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert all(r == 10 for r in results)


class TestCanaryDBLegacyCompat:
    """Test backward compatibility with old API"""
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield CanaryDB(str(db_path))
    
    def test_log_alert_legacy(self, db):
        """Test legacy log_alert method"""
        alert = {
            "alert_id": str(uuid4()),
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        result = db.log_alert(alert)
        
        assert result == True
        assert db.get_alert_count() == 1
    
    def test_get_alerts_by_attacker_legacy(self, db):
        """Test legacy get_alerts_by_attacker method"""
        alert = {
            "alert_id": str(uuid4()),
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        db.save_alert(alert)
        
        alerts = db.get_alerts_by_attacker("192.168.1.100")
        
        assert len(alerts) == 1
    
    def test_alert_database_alias(self):
        """Test AlertDatabase alias exists"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            from shared.db import AlertDatabase
            
            db = AlertDatabase(str(db_path))
            
            assert isinstance(db, CanaryDB)
            db.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
