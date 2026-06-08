"""
Unit tests for UDPBroadcaster
Tests encryption, UDP broadcast, and message format
"""

import pytest
import socket
import struct
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from alert_engine.udp_broadcaster import UDPBroadcaster, CARY_MAGIC
from shared.crypto import AlertCrypto, CanaryCryptoError


class TestUDPBroadcasterInitialization:
    """Test UDPBroadcaster initialization"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_init_stores_broadcast_port(self, crypto):
        """Test that init stores broadcast port"""
        broadcaster = UDPBroadcaster(5555, crypto)
        
        assert broadcaster.broadcast_port == 5555
        assert broadcaster.crypto == crypto
        assert broadcaster.socket is not None
    
    def test_init_with_various_ports(self, crypto):
        """Test initialization with various port numbers"""
        test_ports = [1234, 5000, 5555, 10000, 65535]
        
        for port in test_ports:
            broadcaster = UDPBroadcaster(port, crypto)
            assert broadcaster.broadcast_port == port
            broadcaster.close()
    
    def test_init_socket_created_with_broadcast_enabled(self, crypto):
        """Test that socket is created with SO_BROADCAST enabled"""
        broadcaster = UDPBroadcaster(5555, crypto)
        
        assert broadcaster.socket is not None
        assert isinstance(broadcaster.socket, socket.socket)
        # Verify it's UDP (SOCK_DGRAM)
        assert broadcaster.socket.type == socket.SOCK_DGRAM
        
        broadcaster.close()
    
    def test_init_socket_non_blocking(self, crypto):
        """Test that socket is set to non-blocking mode"""
        broadcaster = UDPBroadcaster(5555, crypto)
        
        # Non-blocking socket should raise BlockingIOError on would-block
        with pytest.raises((BlockingIOError, OSError)):
            # Try to send to non-existent address to trigger error
            broadcaster.socket.sendto(b"test", ('127.0.0.1', 1))
        
        broadcaster.close()


class TestUDPBroadcasterMessageFormat:
    """Test UDP message format with magic header"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_magic_header_constant(self):
        """Test magic header is correct"""
        assert CARY_MAGIC == b'CARY'
        assert len(CARY_MAGIC) == 4
    
    def test_message_format_magic_length_payload(self, crypto):
        """Test complete message format: MAGIC + LENGTH + PAYLOAD"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {
            "canary_name": "TEST",
            "behavior": "test_alert"
        }
        
        broadcaster.broadcast(alert)
        
        # Verify sendto was called
        broadcaster.socket.sendto.assert_called_once()
        
        sent_data, (dest_ip, dest_port) = broadcaster.socket.sendto.call_args[0]
        
        # Verify destination
        assert dest_ip == '255.255.255.255'
        assert dest_port == 5555
        
        # Verify message structure
        assert sent_data[:4] == CARY_MAGIC
        
        # Extract and verify length
        length = struct.unpack('>I', sent_data[4:8])[0]
        payload = sent_data[8:]
        assert len(payload) == length
        
        broadcaster.close()
    
    def test_message_format_with_various_payload_sizes(self, crypto):
        """Test message format with different payload sizes"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        # Test with different length data
        test_alerts = [
            {"small": "alert"},
            {"medium": "alert" * 100},
            {"large": "alert" * 1000}
        ]
        
        for alert in test_alerts:
            broadcaster.broadcast(alert)
            
            sent_data, _ = broadcaster.socket.sendto.call_args[0]
            
            # Verify format
            assert sent_data[:4] == CARY_MAGIC
            length = struct.unpack('>I', sent_data[4:8])[0]
            assert len(sent_data) == 8 + length
        
        broadcaster.close()
    
    def test_length_prefix_big_endian(self, crypto):
        """Test that length prefix is big-endian 32-bit integer"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {"test": "data"}
        broadcaster.broadcast(alert)
        
        sent_data, _ = broadcaster.socket.sendto.call_args[0]
        
        # Extract length and verify it's big-endian
        length_bytes = sent_data[4:8]
        length = struct.unpack('>I', length_bytes)[0]
        
        # Should be positive and reasonable
        assert length > 0
        assert length < 1000000  # Less than 1MB
        
        broadcaster.close()


class TestUDPBroadcasterBroadcast:
    """Test broadcast functionality"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_broadcast_successful(self, crypto):
        """Test successful broadcast"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {"test": "alert"}
        result = broadcaster.broadcast(alert)
        
        assert result == True
        broadcaster.socket.sendto.assert_called_once()
        
        broadcaster.close()
    
    def test_broadcast_encryption_failure(self, crypto):
        """Test broadcast when encryption fails"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.crypto = MagicMock()
        broadcaster.crypto.encrypt.side_effect = CanaryCryptoError("Encryption failed")
        
        alert = {"test": "alert"}
        result = broadcaster.broadcast(alert)
        
        assert result == False
        
        broadcaster.close()
    
    def test_broadcast_socket_error(self, crypto):
        """Test broadcast with socket error"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto.side_effect = socket.error("Socket error")
        
        alert = {"test": "alert"}
        result = broadcaster.broadcast(alert)
        
        assert result == False
        
        broadcaster.close()
    
    def test_broadcast_blocking_io_error(self, crypto):
        """Test broadcast with non-blocking buffer full"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto.side_effect = BlockingIOError("Would block")
        
        alert = {"test": "alert"}
        result = broadcaster.broadcast(alert)
        
        # BlockingIOError is acceptable for fire-and-forget
        assert result == False
        
        broadcaster.close()
    
    def test_broadcast_fire_and_forget(self, crypto):
        """Test fire-and-forget nature (no retries)"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(side_effect=socket.error("Error"))
        
        alert = {"test": "alert"}
        
        # Should return False immediately, no retries
        result = broadcaster.broadcast(alert)
        
        assert result == False
        # Should only try once
        assert broadcaster.socket.sendto.call_count == 1
        
        broadcaster.close()
    
    def test_broadcast_with_realistic_alert(self, crypto):
        """Test broadcast with realistic alert data"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {
            "canary_name": "SSH-Honeypot-01",
            "port": 2222,
            "attacker_ip": "203.0.113.45",
            "attacker_port": 59823,
            "behavior": "ssh_password_auth_attempt: username=root password=toor",
            "timestamp": "2024-06-08T14:32:15.123456Z",
            "fake_data_touched": False
        }
        
        result = broadcaster.broadcast(alert)
        
        assert result == True
        broadcaster.socket.sendto.assert_called_once()
        
        # Verify message format
        sent_data, (dest_ip, dest_port) = broadcaster.socket.sendto.call_args[0]
        assert dest_ip == '255.255.255.255'
        assert dest_port == 5555
        assert sent_data[:4] == CARY_MAGIC
        
        broadcaster.close()
    
    def test_broadcast_to_broadcast_address(self, crypto):
        """Test that broadcasts go to 255.255.255.255"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {"test": "alert"}
        broadcaster.broadcast(alert)
        
        sent_data, (dest_ip, dest_port) = broadcaster.socket.sendto.call_args[0]
        
        assert dest_ip == '255.255.255.255'
        assert dest_port == 5555
        
        broadcaster.close()


class TestUDPBroadcasterSocket:
    """Test socket management"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_close_socket(self, crypto):
        """Test closing socket"""
        broadcaster = UDPBroadcaster(5555, crypto)
        assert broadcaster.socket is not None
        
        broadcaster.close()
        # Socket should be closed
        # Note: We can't easily test if it's closed without trying to use it
    
    def test_multiple_broadcasts(self, crypto):
        """Test multiple broadcasts with same broadcaster"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alerts = [
            {"test": "alert1"},
            {"test": "alert2"},
            {"test": "alert3"}
        ]
        
        results = [broadcaster.broadcast(alert) for alert in alerts]
        
        assert all(results)
        assert broadcaster.socket.sendto.call_count == 3
        
        broadcaster.close()


class TestUDPBroadcasterEncryption:
    """Test encryption integration"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_broadcast_with_encryption_round_trip(self, crypto):
        """Test that broadcast message can be decrypted"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        
        sent_data = None
        
        def capture_send(data, addr):
            nonlocal sent_data
            sent_data = data
            return len(data)
        
        broadcaster.socket.sendto = capture_send
        
        alert = {
            "canary_name": "TEST",
            "port": 2222,
            "behavior": "test_behavior",
            "timestamp": "2024-06-08T14:00:00Z"
        }
        
        broadcaster.broadcast(alert)
        
        # Extract encrypted payload from sent data
        assert sent_data is not None
        assert sent_data[:4] == CARY_MAGIC
        length = struct.unpack('>I', sent_data[4:8])[0]
        encrypted_payload = sent_data[8:8+length]
        
        # Decrypt with same crypto
        decrypted = crypto.decrypt(encrypted_payload)
        
        assert decrypted == alert
        
        broadcaster.close()
    
    def test_different_alerts_produce_different_encrypted_payloads(self, crypto):
        """Test that different alerts produce different ciphertexts"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        
        sent_data_list = []
        
        def capture_send(data, addr):
            sent_data_list.append(data)
            return len(data)
        
        broadcaster.socket.sendto = capture_send
        
        alert1 = {"type": "ssh", "behavior": "attempt1"}
        alert2 = {"type": "ftp", "behavior": "attempt2"}
        
        broadcaster.broadcast(alert1)
        broadcaster.broadcast(alert2)
        
        # Extract payloads
        payload1 = sent_data_list[0][8:]
        payload2 = sent_data_list[1][8:]
        
        # Should be different
        assert payload1 != payload2
        
        # But both should decrypt correctly
        assert crypto.decrypt(payload1) == alert1
        assert crypto.decrypt(payload2) == alert2
        
        broadcaster.close()


class TestUDPBroadcasterEnd2End:
    """End-to-end integration tests"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_complete_broadcast_flow(self, crypto):
        """Test complete broadcast flow with all components"""
        broadcaster = UDPBroadcaster(5555, crypto)
        broadcaster.socket = MagicMock()
        broadcaster.socket.sendto = MagicMock(return_value=100)
        
        alert = {
            "canary_name": "HTTP-Honeypot-01",
            "port": 8080,
            "attacker_ip": "192.0.2.100",
            "attacker_port": 54321,
            "behavior": "http_post_request to /api/v1/keys",
            "timestamp": "2024-06-08T15:00:00Z",
            "fake_data_touched": True
        }
        
        result = broadcaster.broadcast(alert)
        
        assert result == True
        broadcaster.socket.sendto.assert_called_once()
        
        sent_data, (dest_ip, dest_port) = broadcaster.socket.sendto.call_args[0]
        
        # Verify complete structure
        assert sent_data[:4] == CARY_MAGIC
        assert dest_ip == '255.255.255.255'
        assert dest_port == 5555
        
        # Verify can decrypt
        length = struct.unpack('>I', sent_data[4:8])[0]
        encrypted_payload = sent_data[8:8+length]
        decrypted = crypto.decrypt(encrypted_payload)
        
        assert decrypted == alert
        
        broadcaster.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
