    # totp_handler.py
import pyotp
import qrcode
from PySide6.QtWidgets import QMessageBox
from PySide6.QtGui import QPixmap
from cryptography.fernet import Fernet
from crypto import Encryptor  # Assuming Encryptor is defined in crypto.py

class TOTPHandler:
    """Handles TOTP secret generation, QR code display, and verification."""

    def __init__(self):
        self.totp_secret = None

    def generate_totp_secret(self):
        """Generate a new TOTP secret."""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret

    def get_totp_uri(self, name="SteganographyApp", issuer="YourApp"):
        """Generate a provisioning URI for the TOTP secret."""
        if not self.totp_secret:
            self.generate_totp_secret()
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=name, issuer_name=issuer)

    def display_qr_code(self, parent=None):
        """Display the TOTP secret as a QR code for the user to scan."""
        uri = self.get_totp_uri()
        qr = qrcode.make(uri)
        qr.save("totp_qr.png")
        pixmap = QPixmap("totp_qr.png")
        qr_dialog = QMessageBox(parent)
        qr_dialog.setWindowTitle("Scan TOTP QR Code")
        qr_dialog.setText("Scan this QR code with your authenticator app (e.g., Google Authenticator):")
        qr_dialog.setIconPixmap(pixmap)
        qr_dialog.exec()

    def encrypt_totp_secret(self, key):
        """Encrypt the TOTP secret using the provided key."""
        if not self.totp_secret:
            raise ValueError("No TOTP secret generated.")
        encryptor = Encryptor(key)
        totp_secret_bytes = self.totp_secret.encode()
        return encryptor.encrypt(totp_secret_bytes)

    def verify_totp_code(self, totp_code, encrypted_totp_secret, key):
        """Verify the provided TOTP code against the decrypted TOTP secret."""
        encryptor = Encryptor(key)
        try:
            decrypted_totp_secret = encryptor.decrypt(encrypted_totp_secret).decode()
            totp = pyotp.TOTP(decrypted_totp_secret)
            return totp.verify(totp_code)
        except Exception as e:
            raise ValueError(f"TOTP verification failed: {str(e)}")