"""
Unit tests for TCPDispatcher
Tests encryption, TCP transmission, and retry logic
"""

import pytest
import socket
import struct
import threading
import time
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from alert_engine.tcp_dispatcher import TCPDispatcher
from shared.crypto import AlertCrypto, CanaryCryptoError


class TestTCPDispatcherInitialization:
    """Test TCPDispatcher initialization"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_init_stores_monitor_config(self, crypto):
        """Test that init stores monitor host and port"""
        dispatcher = TCPDispatcher("192.168.1.100", 5000, crypto)
        
        assert dispatcher.monitor_host == "192.168.1.100"
        assert dispatcher.monitor_port == 5000
        assert dispatcher.crypto == crypto
        assert dispatcher.connected == False
        assert dispatcher.socket is None
    
    def test_init_with_different_hosts(self, crypto):
        """Test initialization with various host formats"""
        test_cases = [
            ("localhost", 5000),
            ("127.0.0.1", 5000),
            ("192.168.1.1", 5000),
            ("monitor.internal.com", 5000),
        ]
        
        for host, port in test_cases:
            dispatcher = TCPDispatcher(host, port, crypto)
            assert dispatcher.monitor_host == host
            assert dispatcher.monitor_port == port


class TestTCPDispatcherConnection:
    """Test TCP connection management"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_connect_connection_refused(self, crypto):
        """Test connection handling when refused"""
        dispatcher = TCPDispatcher("127.0.0.1", 9999, crypto)  # Non-existent port
        
        result = dispatcher._connect()
        
        assert result == False
        assert dispatcher.connected == False
    
    def test_connect_timeout(self, crypto):
        """Test connection timeout handling"""
        # Try to connect to a non-routable address (should timeout)
        dispatcher = TCPDispatcher("192.0.2.1", 5000, crypto)  # TEST-NET-1 (non-routable)
        dispatcher.socket = MagicMock()
        dispatcher.socket.connect.side_effect = socket.timeout("Timeout")
        
        # Mock the socket creation to use our mock
        with patch('socket.socket', return_value=dispatcher.socket):
            result = dispatcher._connect()
        
        assert result == False
        assert dispatcher.connected == False
    
    def test_close_socket(self, crypto):
        """Test closing connection"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        dispatcher.close()
        
        dispatcher.socket.close.assert_called_once()
        assert dispatcher.connected == False


class TestTCPDispatcherMessageFormat:
    """Test TCP message format with length prefix"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_message_length_prefix_format(self, crypto):
        """Test that length prefix is 4 bytes big-endian"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # Create mock socket
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        # Test data
        payload = b"test_encrypted_data"
        expected_length = len(payload)
        expected_prefix = struct.pack('>I', expected_length)
        
        dispatcher._send_encrypted_alert(payload)
        
        # Verify sendall was called with correct format
        dispatcher.socket.sendall.assert_called_once()
        sent_data = dispatcher.socket.sendall.call_args[0][0]
        
        # Check prefix
        assert sent_data[:4] == expected_prefix
        # Check payload
        assert sent_data[4:] == payload
    
    def test_message_length_prefix_large_payload(self, crypto):
        """Test length prefix with larger payload"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        # Create large payload (1MB)
        payload = b"x" * (1024 * 1024)
        expected_length = len(payload)
        
        dispatcher._send_encrypted_alert(payload)
        
        sent_data = dispatcher.socket.sendall.call_args[0][0]
        received_length = struct.unpack('>I', sent_data[:4])[0]
        
        assert received_length == expected_length
        assert len(sent_data) == 4 + expected_length


class TestTCPDispatcherDispatch:
    """Test alert dispatch with retry logic"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_dispatch_successful_on_first_attempt(self, crypto):
        """Test successful dispatch on first attempt"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        alert = {
            "canary_name": "SSH-01",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 12345,
            "behavior": "ssh_password_attempt",
            "timestamp": "2024-06-08T14:00:00Z",
            "fake_data_touched": False
        }
        
        result = dispatcher.dispatch(alert)
        
        assert result == True
        dispatcher.socket.sendall.assert_called_once()
    
    def test_dispatch_encryption_failure(self, crypto):
        """Test dispatch when encryption fails"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # Mock crypto to raise error
        dispatcher.crypto = MagicMock()
        dispatcher.crypto.encrypt.side_effect = CanaryCryptoError("Encryption failed")
        
        alert = {"test": "alert"}
        
        result = dispatcher.dispatch(alert)
        
        assert result == False
    
    def test_dispatch_connection_failure_then_success(self, crypto):
        """Test retry after initial connection failure"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # Mock _connect to fail once then succeed
        dispatcher._connect = MagicMock(side_effect=[False, True])
        dispatcher._send_encrypted_alert = MagicMock(return_value=True)
        
        alert = {"test": "alert"}
        
        # Note: This would take time due to backoff sleep, so we should mock time.sleep
        with patch('time.sleep'):
            result = dispatcher.dispatch(alert)
        
        assert result == True
        assert dispatcher._connect.call_count == 2
    
    def test_dispatch_retry_exhaustion(self, crypto):
        """Test failure after all retries exhausted"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # Mock to always fail
        dispatcher._connect = MagicMock(return_value=False)
        
        alert = {"test": "alert"}
        
        with patch('time.sleep'):
            result = dispatcher.dispatch(alert)
        
        assert result == False
        # Should attempt 3 times (3 _connect calls)
        assert dispatcher._connect.call_count == 3
    
    def test_dispatch_send_failure_then_retry_success(self, crypto):
        """Test successful dispatch on retry after send failure"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # Mock to fail once on send, then succeed
        dispatcher._connect = MagicMock(return_value=True)
        dispatcher._send_encrypted_alert = MagicMock(side_effect=[False, True])
        
        alert = {"test": "alert"}
        
        with patch('time.sleep'):
            result = dispatcher.dispatch(alert)
        
        assert result == True
        assert dispatcher._send_encrypted_alert.call_count == 2
    
    def test_dispatch_backoff_timing(self, crypto):
        """Test that backoff delays are applied"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher._connect = MagicMock(return_value=False)
        
        alert = {"test": "alert"}
        
        # Track time.sleep calls
        with patch('time.sleep') as mock_sleep:
            dispatcher.dispatch(alert)
        
        # Should sleep between retry attempts (2 sleeps for 3 attempts)
        assert mock_sleep.call_count == 2
        # Both should be 2 seconds
        for call in mock_sleep.call_args_list:
            assert call[0][0] == 2
    
    def test_dispatch_with_realistic_alert(self, crypto):
        """Test dispatch with realistic alert data"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        alert = {
            "canary_name": "FTP-Honeypot-01",
            "port": 2121,
            "attacker_ip": "203.0.113.45",
            "attacker_port": 59823,
            "behavior": "ftp_login_attempt: username=admin password=secret",
            "timestamp": "2024-06-08T14:32:15.123456Z",
            "fake_data_touched": True
        }
        
        result = dispatcher.dispatch(alert)
        
        assert result == True
        # Verify encrypted data was sent
        dispatcher.socket.sendall.assert_called_once()
        sent_data = dispatcher.socket.sendall.call_args[0][0]
        assert len(sent_data) > 4  # At least has length prefix + some data


class TestTCPDispatcherSendAlert:
    """Test send alert functionality"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_send_alert_success(self, crypto):
        """Test successful alert send"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        result = dispatcher._send_encrypted_alert(b"test_data")
        
        assert result == True
        dispatcher.socket.sendall.assert_called_once()
    
    def test_send_alert_timeout(self, crypto):
        """Test send timeout"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.socket.sendall.side_effect = socket.timeout("Timeout")
        dispatcher.connected = True
        
        result = dispatcher._send_encrypted_alert(b"test_data")
        
        assert result == False
        assert dispatcher.connected == False
    
    def test_send_alert_broken_pipe(self, crypto):
        """Test broken pipe error"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.socket.sendall.side_effect = BrokenPipeError("Pipe broken")
        dispatcher.connected = True
        
        result = dispatcher._send_encrypted_alert(b"test_data")
        
        assert result == False
        assert dispatcher.connected == False
    
    def test_send_alert_connection_reset(self, crypto):
        """Test connection reset error"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.socket.sendall.side_effect = ConnectionResetError("Reset")
        dispatcher.connected = True
        
        result = dispatcher._send_encrypted_alert(b"test_data")
        
        assert result == False
        assert dispatcher.connected == False


class TestTCPDispatcherEnd2End:
    """End-to-end integration tests"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_dispatch_with_encryption_round_trip(self, crypto):
        """Test that dispatched alert can be decrypted on other end"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        
        # We'll capture what was sent
        sent_data = None
        
        def capture_send(data):
            nonlocal sent_data
            sent_data = data
        
        dispatcher.socket = MagicMock()
        dispatcher.socket.sendall = capture_send
        dispatcher.connected = True
        
        alert = {
            "canary_name": "HTTP-01",
            "port": 8080,
            "attacker_ip": "192.0.2.100",
            "attacker_port": 54321,
            "behavior": "http_post_request to /api/v1/keys",
            "timestamp": "2024-06-08T15:00:00Z",
            "fake_data_touched": True
        }
        
        dispatcher.dispatch(alert)
        
        # Extract encrypted payload from sent data
        assert sent_data is not None
        length = struct.unpack('>I', sent_data[:4])[0]
        encrypted_payload = sent_data[4:4+length]
        
        # Decrypt with same crypto
        decrypted = crypto.decrypt(encrypted_payload)
        
        assert decrypted == alert
    
    def test_multiple_dispatches_different_alerts(self, crypto):
        """Test multiple alerts with same dispatcher"""
        dispatcher = TCPDispatcher("localhost", 5000, crypto)
        dispatcher.socket = MagicMock()
        dispatcher.connected = True
        
        alerts = [
            {
                "canary_name": "SSH-01",
                "behavior": "ssh_password_attempt: admin/admin",
                "timestamp": "2024-06-08T14:00:00Z"
            },
            {
                "canary_name": "FTP-01",
                "behavior": "ftp_login_attempt: ftp/ftp",
                "timestamp": "2024-06-08T14:01:00Z"
            },
            {
                "canary_name": "HTTP-01",
                "behavior": "http_get /admin",
                "timestamp": "2024-06-08T14:02:00Z"
            }
        ]
        
        results = [dispatcher.dispatch(alert) for alert in alerts]
        
        assert all(results)
        assert dispatcher.socket.sendall.call_count == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
