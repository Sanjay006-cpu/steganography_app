import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """Derive a Fernet key from a password using PBKDF2HMAC with SHA256.
    
    Args:
        password (str): The password to derive the key from.
        salt (bytes, optional): Salt for key derivation. If None, a random salt is generated.
    
    Returns:
        tuple: (key, salt) where key is the derived key and salt is the used salt.
    
    Raises:
        TypeError: If password is not a string or salt is not bytes.
    """
    if not isinstance(password, str):
        raise TypeError(f"Password must be str, got {type(password)}")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError(f"Salt must be bytes, got {type(salt)}")
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

class Encryptor:
    """A class for symmetric encryption and decryption using Fernet."""
    
    def __init__(self, key: bytes):
        """Initialize the Encryptor with a key.
        
        Args:
            key (bytes): The encryption key.
        
        Raises:
            TypeError: If key is not bytes.
        """
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        self.cipher = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data.
        
        Args:
            data (bytes): The data to encrypt.
        
        Returns:
            bytes: The encrypted data.
        
        Raises:
            TypeError: If data is not bytes.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Data to encrypt must be bytes, got {type(data)}")
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data.
        
        Args:
            data (bytes): The data to decrypt.
        
        Returns:
            bytes: The decrypted data.
        
        Raises:
            TypeError: If data is not bytes.
        """
        if not isinstance(data, bytes):
            raise TypeError(f"Data to decrypt must be bytes, got {type(data)}")
        return self.cipher.decrypt(data)