"""
Encryption utilities for secure alert transmission
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import json
from typing import Dict, Any


class AlertCrypto:
    """Handle encryption/decryption of alerts"""
    
    def __init__(self, master_key: bytes = None):
        self.backend = default_backend()
        self.master_key = master_key or os.urandom(32)
    
    def encrypt_alert(self, alert_data: Dict[str, Any]) -> bytes:
        """
        Encrypt alert data using AES-256-GCM
        
        Args:
            alert_data: Dictionary containing alert information
            
        Returns:
            Encrypted bytes (IV + ciphertext + tag)
        """
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        plaintext = json.dumps(alert_data).encode()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv + ciphertext + encryptor.tag
    
    def decrypt_alert(self, encrypted_data: bytes) -> Dict[str, Any]:
        """
        Decrypt alert data
        
        Args:
            encrypted_data: IV + ciphertext + tag
            
        Returns:
            Decrypted alert dictionary
        """
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return json.loads(plaintext.decode())
