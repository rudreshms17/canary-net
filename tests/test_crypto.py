"""
Unit tests for AlertCrypto encryption/decryption
Uses pytest for testing
"""

import pytest
import json
import tempfile
from pathlib import Path
from shared.crypto import AlertCrypto, CanaryCryptoError


class TestAlertCryptoKeyGeneration:
    """Test key generation and loading"""
    
    def test_generate_key_creates_file(self):
        """Test that generate_key creates a key file"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            
            key = AlertCrypto.generate_key(str(key_path))
            
            assert key_path.exists()
            assert len(key) > 0
            # Fernet keys are base64-encoded, so they should start with specific characters
            assert isinstance(key, str)
    
    def test_generate_key_creates_parent_directories(self):
        """Test that generate_key creates parent directories if needed"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "subdir1" / "subdir2" / "test_key.fernet"
            
            key = AlertCrypto.generate_key(str(key_path))
            
            assert key_path.exists()
            assert key_path.parent.exists()
    
    def test_init_creates_key_if_not_exists(self):
        """Test that __init__ creates a key file if it doesn't exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "new_key.fernet"
            
            crypto = AlertCrypto(str(key_path))
            
            assert key_path.exists()
            assert crypto.cipher is not None
    
    def test_init_loads_existing_key(self):
        """Test that __init__ loads an existing key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            
            # Create crypto instance (generates key)
            crypto1 = AlertCrypto(str(key_path))
            
            # Create another instance with same path
            crypto2 = AlertCrypto(str(key_path))
            
            # Both should be able to encrypt/decrypt each other's data
            test_data = {"test": "data"}
            encrypted = crypto1.encrypt(test_data)
            decrypted = crypto2.decrypt(encrypted)
            
            assert decrypted == test_data


class TestAlertCryptoEncryptionDecryption:
    """Test encryption and decryption operations"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_encrypt_returns_bytes(self, crypto):
        """Test that encrypt returns bytes"""
        data = {"message": "test"}
        encrypted = crypto.encrypt(data)
        assert isinstance(encrypted, bytes)
    
    def test_decrypt_returns_dict(self, crypto):
        """Test that decrypt returns a dictionary"""
        original_data = {"message": "test"}
        encrypted = crypto.encrypt(original_data)
        decrypted = crypto.decrypt(encrypted)
        assert isinstance(decrypted, dict)
    
    def test_round_trip_encryption(self, crypto):
        """Test encrypt followed by decrypt returns original data"""
        original_data = {
            "canary_name": "SSH-Honeypot",
            "port": 2222,
            "attacker_ip": "192.168.1.100",
            "attacker_port": 54321,
            "behavior": "ssh_password_auth_attempt",
            "timestamp": "2024-06-08T14:32:00Z",
            "fake_data_touched": False
        }
        
        encrypted = crypto.encrypt(original_data)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == original_data
    
    def test_encrypt_complex_data_types(self, crypto):
        """Test encryption with various data types"""
        data = {
            "string": "value",
            "integer": 42,
            "float": 3.14,
            "boolean": True,
            "null": None,
            "list": [1, 2, 3],
            "nested": {"key": "value"}
        }
        
        encrypted = crypto.encrypt(data)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == data
    
    def test_encrypt_produces_different_output_each_time(self, crypto):
        """Test that encrypt produces different ciphertext each time (due to Fernet timestamp)"""
        data = {"test": "data"}
        encrypted1 = crypto.encrypt(data)
        encrypted2 = crypto.encrypt(data)
        
        # Fernet includes timestamp, so ciphertexts should be different
        # (though both decrypt to same plaintext)
        assert encrypted1 != encrypted2
        assert crypto.decrypt(encrypted1) == data
        assert crypto.decrypt(encrypted2) == data
    
    def test_decrypt_with_wrong_key_raises_error(self):
        """Test that decrypting with wrong key raises CanaryCryptoError"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create two different keys
            key_path1 = Path(tmpdir) / "key1.fernet"
            key_path2 = Path(tmpdir) / "key2.fernet"
            
            crypto1 = AlertCrypto(str(key_path1))
            crypto2 = AlertCrypto(str(key_path2))
            
            # Encrypt with crypto1
            data = {"test": "data"}
            encrypted = crypto1.encrypt(data)
            
            # Try to decrypt with crypto2 (different key)
            with pytest.raises(CanaryCryptoError):
                crypto2.decrypt(encrypted)
    
    def test_decrypt_corrupted_data_raises_error(self, crypto):
        """Test that decrypting corrupted data raises CanaryCryptoError"""
        # Create invalid encrypted data (random bytes)
        corrupted_data = b'not_valid_encrypted_data'
        
        with pytest.raises(CanaryCryptoError):
            crypto.decrypt(corrupted_data)
    
    def test_encrypt_non_serializable_object_raises_error(self, crypto):
        """Test that encrypting non-JSON-serializable objects raises CanaryCryptoError"""
        class CustomObject:
            pass
        
        data = {"obj": CustomObject()}
        
        with pytest.raises(CanaryCryptoError):
            crypto.encrypt(data)


class TestAlertCryptoErrors:
    """Test error handling and custom exceptions"""
    
    def test_canary_crypto_error_is_exception(self):
        """Test that CanaryCryptoError is an Exception"""
        assert issubclass(CanaryCryptoError, Exception)
    
    def test_invalid_key_path_raises_error(self):
        """Test that invalid key path raises CanaryCryptoError"""
        # Use an impossible path (to a directory that will be treated as file)
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir)  # This is a directory, not a file
            
            with pytest.raises(CanaryCryptoError):
                AlertCrypto(str(bad_path))
    
    def test_generate_key_invalid_path_raises_error(self):
        """Test that generate_key with invalid path raises error"""
        # This is platform-dependent, but we can try with an invalid path
        with pytest.raises(CanaryCryptoError):
            AlertCrypto.generate_key("/invalid/path/that/should/not/exist/key.fernet")


class TestAlertCryptoAlertFormat:
    """Test with realistic alert data"""
    
    @pytest.fixture
    def crypto(self):
        """Fixture providing a AlertCrypto instance"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            yield AlertCrypto(str(key_path))
    
    def test_encrypt_decrypt_ssh_alert(self, crypto):
        """Test encryption/decryption of SSH alert"""
        ssh_alert = {
            "canary_name": "SSH-Honeypot-01",
            "port": 2222,
            "attacker_ip": "203.0.113.45",
            "attacker_port": 59823,
            "behavior": "ssh_password_auth_attempt: username=root password=toor client_version=OpenSSH_8.0",
            "timestamp": "2024-06-08T14:32:15.123456Z",
            "fake_data_touched": False
        }
        
        encrypted = crypto.encrypt(ssh_alert)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == ssh_alert
    
    def test_encrypt_decrypt_ftp_alert(self, crypto):
        """Test encryption/decryption of FTP alert"""
        ftp_alert = {
            "canary_name": "FTP-Honeypot-01",
            "port": 2121,
            "attacker_ip": "198.51.100.89",
            "attacker_port": 41234,
            "behavior": "ftp_login_attempt: username=admin password=password123",
            "timestamp": "2024-06-08T14:33:22.654321Z",
            "fake_data_touched": True
        }
        
        encrypted = crypto.encrypt(ftp_alert)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == ftp_alert
    
    def test_encrypt_decrypt_http_alert(self, crypto):
        """Test encryption/decryption of HTTP alert"""
        http_alert = {
            "canary_name": "HTTP-Honeypot-01",
            "port": 8080,
            "attacker_ip": "192.0.2.100",
            "attacker_port": 12345,
            "behavior": "http_post_request | path=/api/v1/keys | user_agent=curl/7.88.1 | auth=Bearer eyJhbGc...",
            "timestamp": "2024-06-08T14:34:10.987654Z",
            "fake_data_touched": True
        }
        
        encrypted = crypto.encrypt(http_alert)
        decrypted = crypto.decrypt(encrypted)
        
        assert decrypted == http_alert


class TestAlertCryptoKeyConsistency:
    """Test key consistency and persistence"""
    
    def test_same_plaintext_different_keys_produces_different_ciphertext(self):
        """Test that same data encrypted with different keys produces different ciphertexts"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path1 = Path(tmpdir) / "key1.fernet"
            key_path2 = Path(tmpdir) / "key2.fernet"
            
            crypto1 = AlertCrypto(str(key_path1))
            crypto2 = AlertCrypto(str(key_path2))
            
            data = {"test": "data"}
            encrypted1 = crypto1.encrypt(data)
            encrypted2 = crypto2.encrypt(data)
            
            # Different keys should produce different ciphertexts
            assert encrypted1 != encrypted2
    
    def test_key_file_content_is_valid_fernet_key(self):
        """Test that generated key file contains valid Fernet key"""
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = Path(tmpdir) / "test_key.fernet"
            
            AlertCrypto.generate_key(str(key_path))
            
            # Try to load and use the key
            with open(key_path, 'rb') as f:
                key_content = f.read()
            
            # This should not raise an error
            from cryptography.fernet import Fernet
            cipher = Fernet(key_content)
            
            # Verify it works
            test_data = b"test"
            encrypted = cipher.encrypt(test_data)
            decrypted = cipher.decrypt(encrypted)
            assert decrypted == test_data


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
