import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
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
    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError(f"Key must be bytes, got {type(key)}")
        self.cipher = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError(f"Data to encrypt must be bytes, got {type(data)}")
        return self.cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        if not isinstance(data, bytes):
            raise TypeError(f"Data to decrypt must be bytes, got {type(data)}")
        return self.cipher.decrypt(data)