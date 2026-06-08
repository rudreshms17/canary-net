"""
Encryption utilities for secure alert transmission
Uses Fernet symmetric encryption for consistent key-based encryption
"""

from cryptography.fernet import Fernet, InvalidToken
import json
import os
from pathlib import Path
from typing import Dict, Any


class CanaryCryptoError(Exception):
    """Custom exception for encryption/decryption errors"""
    pass


class AlertCrypto:
    """
    Handle encryption/decryption of alerts using Fernet symmetric encryption
    
    Fernet guarantees that a message encrypted with it cannot be manipulated
    or read without the key. It also includes timestamp and authentication.
    """
    
    def __init__(self, key_path: str):
        """
        Initialize AlertCrypto with a key file
        
        Args:
            key_path: Path to the Fernet key file. File must exist.
        
        Raises:
            FileNotFoundError: If key file does not exist
            CanaryCryptoError: If key cannot be loaded or initialized
        """
        self.key_path = key_path
        
        # Check if file exists
        if not os.path.exists(key_path):
            raise FileNotFoundError(
                f"Key file not found: {key_path}. Run with --generate-key first."
            )
        
        try:
            # Load the key from file
            with open(key_path, 'rb') as f:
                key = f.read()
            self.cipher = Fernet(key)
        
        except FileNotFoundError:
            raise
        except Exception as e:
            raise CanaryCryptoError(f"Failed to initialize cipher: {e}")
    
    def encrypt(self, data: Dict[str, Any]) -> bytes:
        """
        Encrypt alert data
        
        Serializes the data dictionary to JSON, then encrypts using Fernet.
        
        Args:
            data: Dictionary containing alert information
            
        Returns:
            Encrypted bytes (can be safely transmitted or stored)
            
        Raises:
            CanaryCryptoError: If serialization or encryption fails
        """
        try:
            # Serialize dict to JSON
            json_data = json.dumps(data).encode('utf-8')
            
            # Encrypt using Fernet
            encrypted = self.cipher.encrypt(json_data)
            
            return encrypted
        
        except TypeError as e:
            raise CanaryCryptoError(f"Failed to serialize data to JSON: {e}")
        except Exception as e:
            raise CanaryCryptoError(f"Encryption failed: {e}")
    
    def decrypt(self, data: bytes) -> Dict[str, Any]:
        """
        Decrypt alert data
        
        Decrypts using Fernet, then deserializes from JSON.
        
        Args:
            data: Encrypted bytes from encrypt() method
            
        Returns:
            Decrypted alert dictionary
            
        Raises:
            CanaryCryptoError: If decryption or deserialization fails
        """
        try:
            # Decrypt using Fernet
            decrypted = self.cipher.decrypt(data)
            
            # Deserialize from JSON
            json_data = json.loads(decrypted.decode('utf-8'))
            
            return json_data
        
        except InvalidToken as e:
            raise CanaryCryptoError(f"Invalid token - data may be corrupted or encrypted with different key: {e}")
        except json.JSONDecodeError as e:
            raise CanaryCryptoError(f"Failed to deserialize JSON: {e}")
        except Exception as e:
            raise CanaryCryptoError(f"Decryption failed: {e}")
    
    @classmethod
    def generate_key(cls, path: str) -> str:
        """
        Generate a new Fernet key and save it to a file
        
        Args:
            path: File path where the key will be saved
            
        Returns:
            The generated key (as string for display)
            
        Raises:
            CanaryCryptoError: If key generation or file writing fails
        """
        try:
            key = Fernet.generate_key()
            key_path = Path(path)
            key_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(key_path, 'wb') as f:
                f.write(key)
            
            return key.decode('utf-8')
        
        except Exception as e:
            raise CanaryCryptoError(f"Failed to generate and save key: {e}")
