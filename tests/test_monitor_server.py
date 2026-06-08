"""
Unit tests for Monitor Server
Tests alert reception, decryption, validation, and persistence
"""

import pytest
import socket
import struct
import threading
import time
import tempfile
import uuid
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from monitor.monitor_server import MonitorServer
from shared.crypto import AlertCrypto, CanaryCryptoError
from shared.db import AlertDatabase


class TestMonitorServerInitialization:
    """Test MonitorServer initialization"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing AlertCrypto"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        """Fixture providing AlertDatabase"""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_init_stores_configuration(self, crypto, db):
        """Test that init stores host, port, crypto, db"""
        server = MonitorServer("0.0.0.0", 5000, crypto, db)
        
        assert server.host == "0.0.0.0"
        assert server.port == 5000
        assert server.crypto == crypto
        assert server.db == db
        assert server.running == False
    
    def test_init_with_emit_callback(self, crypto, db):
        """Test initialization with SocketIO callback"""
        callback = MagicMock()
        server = MonitorServer("localhost", 5000, crypto, db, emit_callback=callback)
        
        assert server.emit_callback == callback
    
    def test_init_statistics_reset(self, crypto, db):
        """Test that statistics are initialized to zero"""
        server = MonitorServer("localhost", 5000, crypto, db)
        
        assert server.alerts_received == 0
        assert server.alerts_valid == 0
        assert server.alerts_invalid == 0
        assert server.alerts_decryption_failed == 0


class TestMonitorServerStartStop:
    """Test server lifecycle"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_start_creates_listening_socket(self, crypto, db):
        """Test that start() creates a listening socket"""
        server = MonitorServer("127.0.0.1", 15000, crypto, db)
        server.start()
        
        assert server.running == True
        assert server.server_socket is not None
        
        server.stop()
    
    def test_start_runs_in_thread(self, crypto, db):
        """Test that server runs in background thread"""
        server = MonitorServer("127.0.0.1", 15001, crypto, db)
        server.start()
        
        assert server.server_thread is not None
        assert server.server_thread.is_alive()
        
        server.stop()
    
    def test_stop_closes_server(self, crypto, db):
        """Test that stop() closes the server"""
        server = MonitorServer("127.0.0.1", 15002, crypto, db)
        server.start()
        time.sleep(0.1)
        
        assert server.running == True
        
        server.stop()
        time.sleep(0.1)
        
        assert server.running == False
    
    def test_start_already_running(self, crypto, db):
        """Test starting server when already running"""
        server = MonitorServer("127.0.0.1", 15003, crypto, db)
        server.start()
        
        # Try to start again
        server.start()  # Should log warning but not crash
        
        assert server.running == True
        
        server.stop()


class TestMonitorServerAlertHandling:
    """Test alert reception and processing"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_receive_valid_alert(self, crypto, db):
        """Test receiving a valid encrypted alert"""
        server = MonitorServer("127.0.0.1", 15004, crypto, db)
        server.start()
        time.sleep(0.1)
        
        # Create test alert
        alert = {
            "alert_id": str(uuid.uuid4()),
            "canary_name": "SSH-01",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 12345,
            "behavior": "test_behavior",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Encrypt and send
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15004))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            # Check database
            assert db.get_alert_count() == 1
            alerts = db.get_recent_alerts(hours=1)
            assert len(alerts) == 1
            assert alerts[0]['canary_name'] == 'SSH-01'
        
        finally:
            server.stop()
    
    def test_receive_alert_increments_valid_counter(self, crypto, db):
        """Test that valid alerts increment counter"""
        server = MonitorServer("127.0.0.1", 15005, crypto, db)
        server.start()
        time.sleep(0.1)
        
        alert = {
            "alert_id": str(uuid.uuid4()),
            "canary_name": "FTP-01",
            "attacker_ip": "192.168.1.101",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15005))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            stats = server.get_statistics()
            assert stats['alerts_received'] == 1
            assert stats['alerts_valid'] == 1
        
        finally:
            server.stop()


class TestMonitorServerSchemaValidation:
    """Test alert schema validation"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_reject_missing_canary_name(self, crypto, db):
        """Test that alerts without canary_name are rejected"""
        server = MonitorServer("127.0.0.1", 15006, crypto, db)
        server.start()
        time.sleep(0.1)
        
        # Alert missing canary_name
        alert = {
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15006))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            stats = server.get_statistics()
            assert stats['alerts_invalid'] == 1
            assert stats['alerts_valid'] == 0
        
        finally:
            server.stop()
    
    def test_reject_missing_attacker_ip(self, crypto, db):
        """Test that alerts without attacker_ip are rejected"""
        server = MonitorServer("127.0.0.1", 15007, crypto, db)
        server.start()
        time.sleep(0.1)
        
        alert = {
            "canary_name": "SSH-01",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15007))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            assert server.get_statistics()['alerts_invalid'] == 1
        
        finally:
            server.stop()
    
    def test_reject_missing_timestamp(self, crypto, db):
        """Test that alerts without timestamp are rejected"""
        server = MonitorServer("127.0.0.1", 15008, crypto, db)
        server.start()
        time.sleep(0.1)
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15008))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            assert server.get_statistics()['alerts_invalid'] == 1
        
        finally:
            server.stop()


class TestMonitorServerMalformedData:
    """Test handling of malformed packets"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_incomplete_length_header(self, crypto, db):
        """Test handling incomplete length header"""
        server = MonitorServer("127.0.0.1", 15009, crypto, db)
        server.start()
        time.sleep(0.1)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15009))
            sock.sendall(b"\x00\x00")  # Only 2 bytes instead of 4
            sock.close()
            
            time.sleep(0.5)
            
            # Should not crash, no valid alert
            assert server.get_statistics()['alerts_received'] == 0
        
        finally:
            server.stop()
    
    def test_invalid_message_length(self, crypto, db):
        """Test handling invalid message length"""
        server = MonitorServer("127.0.0.1", 15010, crypto, db)
        server.start()
        time.sleep(0.1)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15010))
            # Send length > 10MB
            sock.sendall(struct.pack('>I', 100 * 1024 * 1024))
            sock.close()
            
            time.sleep(0.5)
            
            assert server.get_statistics()['alerts_received'] == 0
        
        finally:
            server.stop()
    
    def test_corrupted_encrypted_data(self, crypto, db):
        """Test handling corrupted encrypted data"""
        server = MonitorServer("127.0.0.1", 15011, crypto, db)
        server.start()
        time.sleep(0.1)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15011))
            
            # Send invalid encrypted data
            corrupted = b"not_valid_encrypted_data"
            message = struct.pack('>I', len(corrupted)) + corrupted
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            stats = server.get_statistics()
            assert stats['alerts_decryption_failed'] == 1
            assert stats['alerts_valid'] == 0
        
        finally:
            server.stop()


class TestMonitorServerSocketIOEmission:
    """Test SocketIO event emission"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_emit_callback_called_on_valid_alert(self, crypto, db):
        """Test that emit callback is called for valid alerts"""
        emit_callback = MagicMock()
        server = MonitorServer("127.0.0.1", 15012, crypto, db, emit_callback=emit_callback)
        server.start()
        time.sleep(0.1)
        
        alert = {
            "alert_id": str(uuid.uuid4()),
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15012))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            # Check that callback was called
            emit_callback.assert_called_once()
            call_args = emit_callback.call_args
            assert call_args[0][0] == 'new_alert'
            assert call_args[0][1]['canary_name'] == 'SSH-01'
        
        finally:
            server.stop()
    
    def test_emit_callback_not_called_for_invalid_alert(self, crypto, db):
        """Test that emit callback is not called for invalid alerts"""
        emit_callback = MagicMock()
        server = MonitorServer("127.0.0.1", 15013, crypto, db, emit_callback=emit_callback)
        server.start()
        time.sleep(0.1)
        
        # Missing required fields
        alert = {"canary_name": "SSH-01"}
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15013))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            # Callback should not be called
            emit_callback.assert_not_called()
        
        finally:
            server.stop()


class TestMonitorServerStatistics:
    """Test statistics tracking"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_get_statistics(self, crypto, db):
        """Test statistics reporting"""
        server = MonitorServer("127.0.0.1", 15014, crypto, db)
        
        stats = server.get_statistics()
        
        assert 'alerts_received' in stats
        assert 'alerts_valid' in stats
        assert 'alerts_invalid' in stats
        assert 'alerts_decryption_failed' in stats
        assert 'db_total_alerts' in stats


class TestMonitorServerMultipleClients:
    """Test handling multiple concurrent clients"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_multiple_concurrent_clients(self, crypto, db):
        """Test handling multiple concurrent client connections"""
        server = MonitorServer("127.0.0.1", 15015, crypto, db)
        server.start()
        time.sleep(0.1)
        
        def send_alert(alert_num):
            try:
                alert = {
                    "alert_id": str(uuid.uuid4()),
                    "canary_name": f"CANARY-{alert_num}",
                    "attacker_ip": f"192.168.1.{100 + alert_num}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
                
                encrypted = crypto.encrypt(alert)
                message = struct.pack('>I', len(encrypted)) + encrypted
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", 15015))
                sock.sendall(message)
                sock.close()
            except Exception as e:
                pass
        
        try:
            # Send from 5 concurrent clients
            threads = []
            for i in range(5):
                t = threading.Thread(target=send_alert, args=(i,))
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
            
            time.sleep(0.5)
            
            stats = server.get_statistics()
            assert stats['alerts_received'] == 5
            assert stats['alerts_valid'] == 5
        
        finally:
            server.stop()


class TestMonitorServerDatabasePersistence:
    """Test database persistence"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    @pytest.fixture
    def db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield AlertDatabase(str(db_path))
    
    def test_alert_persisted_to_database(self, crypto, db):
        """Test that received alerts are persisted to database"""
        server = MonitorServer("127.0.0.1", 15016, crypto, db)
        server.start()
        time.sleep(0.1)
        
        alert = {
            "alert_id": str(uuid.uuid4()),
            "canary_name": "SSH-01",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 12345,
            "behavior": "ssh_password_attempt",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        encrypted = crypto.encrypt(alert)
        message = struct.pack('>I', len(encrypted)) + encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 15016))
            sock.sendall(message)
            sock.close()
            
            time.sleep(0.5)
            
            # Query database directly
            alerts = db.get_recent_alerts(hours=1)
            assert len(alerts) == 1
            assert alerts[0]['canary_name'] == 'SSH-01'
            assert alerts[0]['attacker_ip'] == '192.168.1.100'
        
        finally:
            server.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
