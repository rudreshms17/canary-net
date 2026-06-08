"""
Unit tests for Alert Manager and Alert Database
Tests alert handling, persistence, and multi-channel dispatch
"""

import pytest
import tempfile
import threading
import time
import uuid
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from alert_engine.alert_manager import AlertManager
from alert_engine.tcp_dispatcher import TCPDispatcher
from alert_engine.udp_broadcaster import UDPBroadcaster
from shared.crypto import AlertCrypto
from shared.db import AlertDatabase


# ========================
# AlertDatabase Tests
# ========================

class TestAlertDatabaseInitialization:
    """Test AlertDatabase initialization"""
    
    def test_init_creates_database(self):
        """Test that database is created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            assert db_path.exists()
    
    def test_init_creates_schema(self):
        """Test that database schema is created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            import sqlite3
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
                assert cursor.fetchone() is not None
    
    def test_init_creates_indexes(self):
        """Test that database indexes are created"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            import sqlite3
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
                indexes = [row[0] for row in cursor.fetchall()]
                assert len(indexes) >= 3


class TestAlertDatabaseOperations:
    """Test Alert Database operations"""
    
    def test_log_alert_success(self):
        """Test logging alert to database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            alert = {
                "alert_id": str(uuid.uuid4()),
                "canary_name": "SSH-01",
                "port": 2222,
                "attacker_ip": "192.168.1.100",
                "attacker_port": 12345,
                "behavior": "test_behavior",
                "timestamp": "2024-06-08T14:00:00Z",
                "fake_data_touched": False
            }
            
            result = db.log_alert(alert)
            
            assert result == True
    
    def test_get_alerts_by_attacker(self):
        """Test retrieving alerts by attacker IP"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            # Log multiple alerts
            attacker_ip = "192.168.1.100"
            for i in range(3):
                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": attacker_ip,
                    "attacker_port": 12345 + i,
                    "behavior": f"test_{i}",
                    "timestamp": "2024-06-08T14:00:00Z"
                }
                db.log_alert(alert)
            
            # Query by attacker
            alerts = db.get_alerts_by_attacker(attacker_ip)
            
            assert len(alerts) == 3
            assert all(a['attacker_ip'] == attacker_ip for a in alerts)
    
    def test_get_alerts_by_canary(self):
        """Test retrieving alerts by canary name"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            canary_name = "FTP-01"
            for i in range(3):
                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "canary_name": canary_name,
                    "attacker_ip": f"192.168.1.{100+i}",
                    "behavior": f"test_{i}",
                    "timestamp": "2024-06-08T14:00:00Z"
                }
                db.log_alert(alert)
            
            # Query by canary
            alerts = db.get_alerts_by_canary(canary_name)
            
            assert len(alerts) == 3
            assert all(a['canary_name'] == canary_name for a in alerts)
    
    def test_get_recent_alerts(self):
        """Test retrieving recent alerts"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            alert = {
                "alert_id": str(uuid.uuid4()),
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "behavior": "test",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
            db.log_alert(alert)
            
            alerts = db.get_recent_alerts(hours=1)
            
            assert len(alerts) == 1
            assert alerts[0]['alert_id'] == alert['alert_id']
    
    def test_get_alert_count(self):
        """Test getting alert count"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            assert db.get_alert_count() == 0
            
            for i in range(5):
                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": "192.168.1.100",
                    "behavior": "test",
                    "timestamp": "2024-06-08T14:00:00Z"
                }
                db.log_alert(alert)
            
            assert db.get_alert_count() == 5
    
    def test_thread_safe_operations(self):
        """Test thread-safe database operations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = AlertDatabase(str(db_path))
            
            # Log alerts from multiple threads
            def log_alert(thread_id):
                for i in range(10):
                    alert = {
                        "alert_id": str(uuid.uuid4()),
                        "canary_name": f"Thread-{thread_id}",
                        "attacker_ip": f"192.168.1.{thread_id}",
                        "behavior": f"test_{i}",
                        "timestamp": "2024-06-08T14:00:00Z"
                    }
                    db.log_alert(alert)
            
            threads = [threading.Thread(target=log_alert, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Should have 50 total alerts (5 threads * 10 alerts)
            assert db.get_alert_count() == 50


# ========================
# AlertManager Tests
# ========================

class TestAlertManagerInitialization:
    """Test AlertManager initialization"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing AlertCrypto"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_init_without_dispatchers(self):
        """Test initialization without dispatchers"""
        manager = AlertManager()
        
        assert manager.tcp_dispatcher is None
        assert manager.udp_broadcaster is None
        assert manager.alert_db is not None
        assert manager.alerts_processed == 0
    
    def test_init_with_tcp_dispatcher(self, crypto):
        """Test initialization with TCP dispatcher"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        manager = AlertManager(tcp_dispatcher=dispatcher)
        
        assert manager.tcp_dispatcher == dispatcher
        
        dispatcher.close()
    
    def test_init_with_udp_broadcaster(self, crypto):
        """Test initialization with UDP broadcaster"""
        broadcaster = UDPBroadcaster(5555, crypto)
        manager = AlertManager(udp_broadcaster=broadcaster)
        
        assert manager.udp_broadcaster == broadcaster
        
        broadcaster.close()
    
    def test_init_with_custom_db_path(self):
        """Test initialization with custom database path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "custom.db"
            manager = AlertManager(db_path=str(db_path))
            
            assert db_path.exists()


class TestAlertManagerHandleAlert:
    """Test AlertManager alert handling"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing AlertCrypto"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_handle_alert_adds_alert_id(self):
        """Test that handle_alert adds UUID alert_id"""
        manager = AlertManager()
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        manager.handle_alert(alert)
        
        assert 'alert_id' in alert
        assert len(alert['alert_id']) == 36  # UUID4 format
    
    def test_handle_alert_adds_timestamp(self):
        """Test that handle_alert adds timestamp if missing"""
        manager = AlertManager()
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        manager.handle_alert(alert)
        
        assert 'timestamp' in alert
    
    def test_handle_alert_increments_counter(self):
        """Test that handle_alert increments processed count"""
        manager = AlertManager()
        
        assert manager.alerts_processed == 0
        
        for i in range(3):
            alert = {
                "canary_name": f"SSH-{i}",
                "attacker_ip": "192.168.1.100",
                "behavior": "test"
            }
            manager.handle_alert(alert)
        
        assert manager.alerts_processed == 3
    
    def test_handle_alert_dispatches_via_tcp(self, crypto):
        """Test that handle_alert sends via TCP dispatcher"""
        dispatcher = MagicMock()
        dispatcher.dispatch = MagicMock(return_value=True)
        
        manager = AlertManager(tcp_dispatcher=dispatcher)
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        manager.handle_alert(alert)
        
        dispatcher.dispatch.assert_called_once()
        assert manager.tcp_sent == 1
    
    def test_handle_alert_broadcasts_via_udp(self, crypto):
        """Test that handle_alert broadcasts via UDP"""
        broadcaster = MagicMock()
        broadcaster.broadcast = MagicMock(return_value=True)
        
        manager = AlertManager(udp_broadcaster=broadcaster)
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        manager.handle_alert(alert)
        
        broadcaster.broadcast.assert_called_once()
        assert manager.udp_sent == 1
    
    def test_handle_alert_logs_to_database(self):
        """Test that handle_alert logs to database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            manager = AlertManager(db_path=str(db_path))
            
            alert = {
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "behavior": "test",
                "timestamp": "2024-06-08T14:00:00Z"
            }
            
            manager.handle_alert(alert)
            
            # Check database has the alert
            assert manager.alert_db.get_alert_count() == 1
            assert manager.db_logged == 1
    
    def test_handle_alert_returns_true_on_success(self):
        """Test that handle_alert returns True on success"""
        manager = AlertManager()
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        result = manager.handle_alert(alert)
        
        assert result == True
    
    def test_handle_alert_thread_safe(self):
        """Test that handle_alert is thread-safe"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            manager = AlertManager(db_path=str(db_path))
            
            def submit_alerts(thread_id):
                for i in range(10):
                    alert = {
                        "canary_name": f"Thread-{thread_id}",
                        "attacker_ip": f"192.168.1.{thread_id}",
                        "behavior": f"test_{i}"
                    }
                    manager.handle_alert(alert)
            
            threads = [threading.Thread(target=submit_alerts, args=(i,)) for i in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            
            # Should have 50 alerts (5 threads * 10 alerts)
            assert manager.alerts_processed == 50
            assert manager.alert_db.get_alert_count() == 50
    
    def test_handle_alert_with_multiple_channels(self, crypto):
        """Test alert handling with all channels"""
        tcp_dispatcher = MagicMock()
        tcp_dispatcher.dispatch = MagicMock(return_value=True)
        
        udp_broadcaster = MagicMock()
        udp_broadcaster.broadcast = MagicMock(return_value=True)
        
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            manager = AlertManager(
                tcp_dispatcher=tcp_dispatcher,
                udp_broadcaster=udp_broadcaster,
                db_path=str(db_path)
            )
            
            alert = {
                "canary_name": "SSH-01",
                "attacker_ip": "192.168.1.100",
                "behavior": "test"
            }
            
            result = manager.handle_alert(alert)
            
            assert result == True
            tcp_dispatcher.dispatch.assert_called_once()
            udp_broadcaster.broadcast.assert_called_once()
            assert manager.db_logged == 1
    
    def test_handle_alert_graceful_channel_failure(self, crypto):
        """Test alert handling when channels fail"""
        tcp_dispatcher = MagicMock()
        tcp_dispatcher.dispatch = MagicMock(return_value=False)
        
        udp_broadcaster = MagicMock()
        udp_broadcaster.broadcast = MagicMock(return_value=False)
        
        manager = AlertManager(
            tcp_dispatcher=tcp_dispatcher,
            udp_broadcaster=udp_broadcaster
        )
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test"
        }
        
        # Should still return True (processing completed)
        # even if dispatch channels failed
        result = manager.handle_alert(alert)
        
        assert result == True
        assert manager.tcp_sent == 0
        assert manager.udp_sent == 0


class TestAlertManagerStatistics:
    """Test AlertManager statistics"""
    
    def test_get_statistics(self):
        """Test getting alert statistics"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            manager = AlertManager(db_path=str(db_path))
            
            # Submit some alerts
            for i in range(3):
                alert = {
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": "192.168.1.100",
                    "behavior": "test"
                }
                manager.handle_alert(alert)
            
            stats = manager.get_statistics()
            
            assert stats['alerts_processed'] == 3
            assert stats['db_total_alerts'] == 3


class TestAlertManagerConsoleOutput:
    """Test console output"""
    
    def test_handle_alert_prints_summary(self, capsys):
        """Test that handle_alert prints summary"""
        manager = AlertManager()
        
        alert = {
            "canary_name": "SSH-01",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 12345,
            "behavior": "ssh_password_attempt",
            "timestamp": "2024-06-08T14:00:00Z"
        }
        
        manager.handle_alert(alert)
        
        captured = capsys.readouterr()
        
        # Should contain key information
        assert "ALERT" in captured.out or "alert" in captured.out.lower()
        assert "192.168.1.100" in captured.out
        assert "SSH-01" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
