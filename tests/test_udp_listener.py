"""
Unit tests for UDP Listener
Tests broadcast alert reception and decryption
"""

import pytest
import socket
import struct
import threading
import time
import tempfile
import uuid
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, MagicMock

from monitor.udp_listener import UDPListener
from shared.crypto import AlertCrypto


class TestUDPListenerInitialization:
    """Test UDPListener initialization"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing AlertCrypto"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_init_stores_configuration(self, crypto):
        """Test that init stores port and crypto"""
        listener = UDPListener(5555, crypto)
        
        assert listener.port == 5555
        assert listener.crypto == crypto
        assert listener.running == False
    
    def test_init_statistics_reset(self, crypto):
        """Test that statistics are initialized to zero"""
        listener = UDPListener(5555, crypto)
        
        assert listener.packets_received == 0
        assert listener.packets_valid == 0
        assert listener.packets_invalid == 0
        assert listener.packets_decryption_failed == 0


class TestUDPListenerLifecycle:
    """Test listener lifecycle"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_start_creates_socket(self, crypto):
        """Test that start() creates a UDP socket"""
        listener = UDPListener(15555, crypto)
        listener.start()
        
        assert listener.running == True
        assert listener.socket is not None
        
        listener.stop()
    
    def test_start_runs_in_thread(self, crypto):
        """Test that listener runs in background thread"""
        listener = UDPListener(15556, crypto)
        listener.start()
        
        assert listener.listener_thread is not None
        assert listener.listener_thread.is_alive()
        
        listener.stop()
    
    def test_stop_closes_listener(self, crypto):
        """Test that stop() closes the listener"""
        listener = UDPListener(15557, crypto)
        listener.start()
        time.sleep(0.1)
        
        assert listener.running == True
        
        listener.stop()
        time.sleep(0.1)
        
        assert listener.running == False
    
    def test_start_already_running(self, crypto):
        """Test starting listener when already running"""
        listener = UDPListener(15558, crypto)
        listener.start()
        
        # Try to start again
        listener.start()  # Should log warning but not crash
        
        assert listener.running == True
        
        listener.stop()


class TestUDPListenerPacketReception:
    """Test receiving and parsing UDP packets"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_receive_valid_broadcast_alert(self, crypto):
        """Test receiving a valid CARY packet"""
        listener = UDPListener(15559, crypto)
        listener.start()
        time.sleep(0.1)
        
        # Create test alert
        alert = {
            "alert_id": str(uuid.uuid4()),
            "canary_name": "SSH-01",
            "attacker_ip": "192.168.1.100",
            "behavior": "test_broadcast"
        }
        
        # Encrypt and build CARY packet
        encrypted = crypto.encrypt(alert)
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            # Send to listener
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15559))
            sock.close()
            
            time.sleep(0.5)
            
            # Check statistics
            stats = listener.get_statistics()
            assert stats['packets_received'] == 1
            assert stats['packets_valid'] == 1
        
        finally:
            listener.stop()
    
    def test_increment_received_counter(self, crypto):
        """Test that received counter increments"""
        listener = UDPListener(15560, crypto)
        listener.start()
        time.sleep(0.1)
        
        alert = {
            "canary_name": "FTP-01",
            "attacker_ip": "192.168.1.101"
        }
        
        encrypted = crypto.encrypt(alert)
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15560))
            sock.close()
            
            time.sleep(0.5)
            
            assert listener.packets_received == 1
        
        finally:
            listener.stop()


class TestUDPListenerPacketValidation:
    """Test packet validation"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_reject_packet_too_short(self, crypto):
        """Test rejection of packets shorter than 8 bytes"""
        listener = UDPListener(15561, crypto)
        listener.start()
        time.sleep(0.1)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(b"SHORT", ("127.0.0.1", 15561))
            sock.close()
            
            time.sleep(0.5)
            
            stats = listener.get_statistics()
            assert stats['packets_received'] == 1
            assert stats['packets_valid'] == 0
        
        finally:
            listener.stop()
    
    def test_reject_invalid_magic_header(self, crypto):
        """Test rejection of packets without CARY magic"""
        listener = UDPListener(15562, crypto)
        listener.start()
        time.sleep(0.1)
        
        # Create packet with wrong magic
        alert = {"canary_name": "SSH-01"}
        encrypted = crypto.encrypt(alert)
        
        message = (
            b"XXXX" +  # Wrong magic
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15562))
            sock.close()
            
            time.sleep(0.5)
            
            assert listener.packets_received == 1
            assert listener.packets_valid == 0
        
        finally:
            listener.stop()
    
    def test_reject_corrupted_encryption(self, crypto):
        """Test rejection of corrupted encrypted data"""
        listener = UDPListener(15563, crypto)
        listener.start()
        time.sleep(0.1)
        
        # Create packet with invalid encrypted data
        corrupted = b"not_valid_encrypted_data"
        
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(corrupted)) +
            corrupted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15563))
            sock.close()
            
            time.sleep(0.5)
            
            stats = listener.get_statistics()
            assert stats['packets_decryption_failed'] == 1
            assert stats['packets_valid'] == 0
        
        finally:
            listener.stop()
    
    def test_reject_missing_canary_name(self, crypto):
        """Test rejection of alerts without canary_name"""
        listener = UDPListener(15564, crypto)
        listener.start()
        time.sleep(0.1)
        
        # Alert missing canary_name
        alert = {
            "attacker_ip": "192.168.1.100"
        }
        
        encrypted = crypto.encrypt(alert)
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15564))
            sock.close()
            
            time.sleep(0.5)
            
            stats = listener.get_statistics()
            assert stats['packets_invalid'] == 1
            assert stats['packets_valid'] == 0
        
        finally:
            listener.stop()
    
    def test_reject_incomplete_payload(self, crypto):
        """Test rejection of packets with incomplete payload"""
        listener = UDPListener(15565, crypto)
        listener.start()
        time.sleep(0.1)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # Send CARY magic + length that claims more data than provided
            sock.sendto(
                UDPListener.CARY_MAGIC +
                struct.pack('>I', 1000) +  # Claim 1000 bytes
                b"short"  # Only 5 bytes
                ,
                ("127.0.0.1", 15565)
            )
            sock.close()
            
            time.sleep(0.5)
            
            assert listener.packets_received == 1
            assert listener.packets_valid == 0
        
        finally:
            listener.stop()


class TestUDPListenerStatistics:
    """Test statistics tracking"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_get_statistics(self, crypto):
        """Test statistics reporting"""
        listener = UDPListener(15566, crypto)
        
        stats = listener.get_statistics()
        
        assert 'packets_received' in stats
        assert 'packets_valid' in stats
        assert 'packets_invalid' in stats
        assert 'packets_decryption_failed' in stats
    
    def test_statistics_accumulate(self, crypto):
        """Test statistics accumulate across packets"""
        listener = UDPListener(15567, crypto)
        listener.start()
        time.sleep(0.1)
        
        alert = {"canary_name": "SSH-01"}
        encrypted = crypto.encrypt(alert)
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send 3 packets
            for i in range(3):
                sock.sendto(message, ("127.0.0.1", 15567))
            
            sock.close()
            time.sleep(0.5)
            
            stats = listener.get_statistics()
            assert stats['packets_received'] == 3
            assert stats['packets_valid'] == 3
        
        finally:
            listener.stop()


class TestUDPListenerMessageFormat:
    """Test CARY message format parsing"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_message_format_with_magic(self, crypto):
        """Test message format: CARY magic + length + payload"""
        listener = UDPListener(15568, crypto)
        listener.start()
        time.sleep(0.1)
        
        alert = {
            "canary_name": "HTTP-01",
            "attacker_ip": "10.0.0.1"
        }
        
        encrypted = crypto.encrypt(alert)
        
        # Verify message format
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        # Verify components
        assert message[:4] == b'CARY'
        assert struct.unpack('>I', message[4:8])[0] == len(encrypted)
        assert message[8:] == encrypted
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15568))
            sock.close()
            
            time.sleep(0.5)
            
            assert listener.packets_received == 1
            assert listener.packets_valid == 1
        
        finally:
            listener.stop()


class TestUDPListenerConcurrency:
    """Test handling multiple concurrent packets"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_multiple_rapid_packets(self, crypto):
        """Test handling multiple rapid UDP packets"""
        listener = UDPListener(15569, crypto)
        listener.start()
        time.sleep(0.1)
        
        alert_template = {
            "canary_name": "SSH-{0}",
            "attacker_ip": "192.168.1.{0}"
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Send 10 packets rapidly
            for i in range(10):
                alert = {
                    "canary_name": f"SSH-{i}",
                    "attacker_ip": f"192.168.1.{100+i}"
                }
                
                encrypted = crypto.encrypt(alert)
                message = (
                    UDPListener.CARY_MAGIC +
                    struct.pack('>I', len(encrypted)) +
                    encrypted
                )
                
                sock.sendto(message, ("127.0.0.1", 15569))
            
            sock.close()
            time.sleep(1)
            
            stats = listener.get_statistics()
            # Should have received all 10 (or close due to UDP)
            assert stats['packets_received'] >= 8
            assert stats['packets_valid'] >= 8
        
        finally:
            listener.stop()


class TestUDPListenerConsoleOutput:
    """Test console output"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_broadcast_alert_printed(self, crypto, capsys):
        """Test that valid alerts are printed to console"""
        listener = UDPListener(15570, crypto)
        listener.start()
        time.sleep(0.1)
        
        alert = {
            "canary_name": "SSH-01",
            "attacker_ip": "203.0.113.45",
            "behavior": "ssh_attack"
        }
        
        encrypted = crypto.encrypt(alert)
        message = (
            UDPListener.CARY_MAGIC +
            struct.pack('>I', len(encrypted)) +
            encrypted
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(message, ("127.0.0.1", 15570))
            sock.close()
            
            time.sleep(0.5)
            
            captured = capsys.readouterr()
            
            # Should contain "BROADCAST ALERT" in output
            assert "BROADCAST ALERT" in captured.out or "broadcast" in captured.out.lower()
        
        finally:
            listener.stop()


class TestUDPListenerDaemonThread:
    """Test daemon thread behavior"""
    
    @pytest.fixture
    def crypto(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_listener_thread_is_daemon(self, crypto):
        """Test that listener thread is daemon"""
        listener = UDPListener(15571, crypto)
        listener.start()
        
        assert listener.listener_thread.daemon == True
        
        listener.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
