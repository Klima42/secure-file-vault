from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidKey
import base64
import os

class Crypto:
    ITERATIONS = 480000  # Increased from default 100000 for better security
    
    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for key derivation"""
        return os.urandom(16)
    
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=Crypto.ITERATIONS,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    @staticmethod
    def encrypt_file(file_data: bytes, password: str) -> tuple[bytes, bytes]:
        """
        Encrypt file data using key derived from password
        Returns tuple of (encrypted_data, salt)
        """
        salt = Crypto.generate_salt()
        key = Crypto.derive_key(password, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)
        return encrypted_data, salt
    
    @staticmethod
    def decrypt_file(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
        """
        Decrypt file data using key derived from password
        Raises InvalidKey if password is incorrect
        """
        try:
            key = Crypto.derive_key(password, salt)
            f = Fernet(key)
            return f.decrypt(encrypted_data)
        except Exception as e:
            raise InvalidKey("Invalid decryption password")