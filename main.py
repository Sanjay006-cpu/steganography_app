import os
import sys
import logging
import time
import base64
import pyotp  # For TOTP generation and verification
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QRadioButton,
    QPushButton, QLabel, QTextEdit, QFileDialog, QMessageBox, QProgressBar,
    QInputDialog, QLineEdit, QDialog, QSlider, QCheckBox
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from media import ImageHandler, AudioHandler
from crypto import derive_key, Encryptor
from password import PasswordGenerator, PasswordAnalyzer, RateLimiter
from cryptography.fernet import Fernet

# Maximum character limit for data entry
MAX_CHAR_LIMIT = 10000

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')

class PasswordDialog(QDialog):
    """Dialog for generating and selecting a password."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Generate Password")
        self.generator = PasswordGenerator()
        self.analyzer = PasswordAnalyzer()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        # Length Slider
        length_layout = QHBoxLayout()
        length_layout.addWidget(QLabel("Length (12-64):"))
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setMinimum(12)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(12)
        self.length_label = QLabel("12")
        self.length_slider.valueChanged.connect(lambda: self.length_label.setText(str(self.length_slider.value())))
        length_layout.addWidget(self.length_slider)
        length_layout.addWidget(self.length_label)
        layout.addLayout(length_layout)
        # Character Set Options
        self.upper_check = QCheckBox("Uppercase Letters")
        self.upper_check.setChecked(True)
        self.digits_check = QCheckBox("Digits")
        self.digits_check.setChecked(True)
        self.symbols_check = QCheckBox("Symbols")
        self.symbols_check.setChecked(True)
        self.pronounceable_check = QCheckBox("Pronounceable")
        layout.addWidget(self.upper_check)
        layout.addWidget(self.digits_check)
        layout.addWidget(self.symbols_check)
        layout.addWidget(self.pronounceable_check)
        # Generate Button
        self.generate_button = QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_password)
        layout.addWidget(self.generate_button)
        # Password Display
        self.password_field = QLineEdit()
        self.password_field.setReadOnly(True)
        layout.addWidget(QLabel("Generated Password:"))
        layout.addWidget(self.password_field)
        # Strength Display
        self.strength_label = QLabel("Strength: N/A")
        self.entropy_label = QLabel("Entropy: N/A bits")
        layout.addWidget(self.strength_label)
        layout.addWidget(self.entropy_label)
        # Use Password Button
        self.use_button = QPushButton("Use Password")
        self.use_button.clicked.connect(self.accept)
        layout.addWidget(self.use_button)
        self.setLayout(layout)

    def generate_password(self):
        length = self.length_slider.value()
        password = self.generator.generate(
            length=length,
            use_upper=self.upper_check.isChecked(),
            use_digits=self.digits_check.isChecked(),
            use_symbols=self.symbols_check.isChecked(),
            pronounceable=self.pronounceable_check.isChecked()
        )
        self.password_field.setText(password)
        analysis = self.analyzer.analyze(password)
        strength_text = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
        self.strength_label.setText(f"Strength: {strength_text[analysis['score']]}")
        self.entropy_label.setText(f"Entropy: {analysis['entropy']} bits")

    def get_password(self):
        return self.password_field.text()

class SteganographyApp(QWidget):
    """Main application window for steganography."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steganography Application")
        self.setGeometry(100, 100, 600, 450)
        self.media_type = "image"
        self.action = "encode"
        self.input_file = ""
        self.output_file = ""
        self.max_chars = 0
        self.password = None
        self.rate_limiter = RateLimiter(max_attempts=5, window_seconds=600, lockout_seconds=1800)
        
        # Load or generate TOTP secret
        secret_file = 'totp_secret.txt'
        if os.path.exists(secret_file):
            with open(secret_file, 'r') as f:
                totp_secret = f.read().strip()
        else:
            totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
            with open(secret_file, 'w') as f:
                f.write(totp_secret)
        self.totp = pyotp.TOTP(totp_secret)
        print(f"TOTP Secret (for Microsoft Authenticator setup): {totp_secret}")
        
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        self.setLayout(main_layout)

        # Style sheet
        self.setStyleSheet("""
            QWidget {
                background-color: black;
                color: white;
                font-family: 'Segoe UI';
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid white;
                border-radius: 5px;
                padding: 10px;
            }
            QPushButton {
                background-color: #333333;
                color: white;
                border-radius: 6px;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QRadioButton, QCheckBox {
                color: white;
            }
            QTextEdit, QLineEdit {
                background-color: #222222;
                color: white;
                border: 1px solid white;
            }
        """)

        # Media Type Selection
        media_group = QGroupBox("Media Type")
        media_layout = QHBoxLayout()
        self.image_radio = QRadioButton("Image")
        self.image_radio.setChecked(True)
        self.image_radio.toggled.connect(self.update_media_type)
        self.audio_radio = QRadioButton("Audio")
        self.audio_radio.toggled.connect(self.update_media_type)
        media_layout.addWidget(self.image_radio)
        media_layout.addWidget(self.audio_radio)
        media_group.setLayout(media_layout)
        main_layout.addWidget(media_group)

        # Action Selection
        action_group = QGroupBox("Action")
        action_layout = QHBoxLayout()
        self.encode_radio = QRadioButton("Encode")
        self.encode_radio.setChecked(True)
        self.encode_radio.toggled.connect(self.update_action)
        self.decode_radio = QRadioButton("Decode")
        self.decode_radio.toggled.connect(self.update_action)
        action_layout.addWidget(self.encode_radio)
        action_layout.addWidget(self.decode_radio)
        action_group.setLayout(action_layout)
        main_layout.addWidget(action_group)

        # Encryption Method
        self.encryption_group = QGroupBox("Encryption Method")
        encryption_layout = QHBoxLayout()
        self.auto_key_radio = QRadioButton("Automatic Key")
        self.auto_key_radio.setChecked(True)
        self.custom_password_radio = QRadioButton("Custom Password")
        self.custom_password_radio.toggled.connect(self.update_action)
        encryption_layout.addWidget(self.auto_key_radio)
        encryption_layout.addWidget(self.custom_password_radio)
        self.encryption_group.setLayout(encryption_layout)
        main_layout.addWidget(self.encryption_group)

        # Password Generation
        self.password_layout = QHBoxLayout()
        self.generate_password_button = QPushButton("Generate Password")
        self.generate_password_button.clicked.connect(self.show_password_dialog)
        self.password_strength_label = QLabel("Password Strength: N/A")
        self.password_layout.addWidget(self.generate_password_button)
        self.password_layout.addWidget(self.password_strength_label)
        self.password_widget = QWidget()
        self.password_widget.setLayout(self.password_layout)
        main_layout.addWidget(self.password_widget)

        # File Selection
        file_group = QGroupBox("Files")
        file_layout = QVBoxLayout()
        input_layout = QHBoxLayout()
        self.select_input_button = QPushButton("Select Input File")
        self.select_input_button.clicked.connect(self.select_input_file)
        self.input_file_label = QLabel("No file selected")
        input_layout.addWidget(self.select_input_button)
        input_layout.addWidget(self.input_file_label)
        file_layout.addLayout(input_layout)
        output_layout = QHBoxLayout()
        self.select_output_button = QPushButton("Select Output File")
        self.select_output_button.clicked.connect(self.select_output_file)
        self.output_file_label = QLabel("")
        output_layout.addWidget(self.select_output_button)
        output_layout.addWidget(self.output_file_label)
        file_layout.addLayout(output_layout)
        file_group.setLayout(file_layout)
        main_layout.addWidget(file_group)

        # Data Entry
        self.data_group = QGroupBox("Data")
        data_layout = QVBoxLayout()
        self.data_entry = QTextEdit()
        self.data_entry.textChanged.connect(self.update_char_count)
        data_layout.addWidget(self.data_entry)
        self.char_count_label = QLabel("0 / 0 characters")
        data_layout.addWidget(self.char_count_label)
        self.data_group.setLayout(data_layout)
        main_layout.addWidget(self.data_group)

        # Execute Button
        self.execute_button = QPushButton("Execute")
        self.execute_button.clicked.connect(self.execute)
        main_layout.addWidget(self.execute_button, alignment=Qt.AlignCenter)

        # Status and Progress
        self.status_label = QLabel("Ready")
        main_layout.addWidget(self.status_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)

        self.update_action()

    def update_media_type(self):
        self.media_type = "image" if self.image_radio.isChecked() else "audio"
        self.reset_files()

    def update_action(self):
        self.action = "encode" if self.encode_radio.isChecked() else "decode"
        self.data_group.setVisible(self.action == "encode")
        self.encryption_group.setVisible(self.action == "encode")
        self.select_output_button.setVisible(self.action == "encode")
        self.output_file_label.setVisible(self.action == "encode")
        self.password_widget.setVisible(self.action == "encode" and self.custom_password_radio.isChecked())
        self.reset_files()

    def reset_files(self):
        self.input_file = ""
        self.output_file = ""
        self.input_file_label.setText("No file selected")
        self.output_file_label.setText("")
        self.max_chars = 0
        self.password = None
        self.password_strength_label.setText("Password Strength: N/A")
        self.update_char_count()

    def select_input_file(self):
        file_types = {
            "image": "Image files (*.png *.jpg *.jpeg *.bmp)",
            "audio": "Audio files (*.wav *.mp3 *.ogg)"
        }.get(self.media_type, "All files (*.*)")
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", file_types)
        if file_name:
            self.input_file = file_name
            self.input_file_label.setText(os.path.basename(file_name))
            handler = ImageHandler() if self.media_type == "image" else AudioHandler()
            max_bytes = handler.get_max_data_size(file_name) - 16  # Account for metadata
            self.max_chars = min(max_bytes // 2, MAX_CHAR_LIMIT)
            self.update_char_count()

    def select_output_file(self):
        file_types = {
            "image": "Image files (*.png)",
            "audio": "Audio files (*.wav)"
        }.get(self.media_type, "All files (*.*)")
        file_name, _ = QFileDialog.getSaveFileName(self, "Select Output File", "", file_types)
        if file_name:
            self.output_file = file_name
            self.output_file_label.setText(os.path.basename(file_name))

    def update_char_count(self):
        current_length = len(self.data_entry.toPlainText())
        if self.action == "encode" and self.max_chars > 0:
            if current_length > self.max_chars:
                self.data_entry.setPlainText(self.data_entry.toPlainText()[:self.max_chars])
                cursor = self.data_entry.textCursor()
                cursor.movePosition(QTextCursor.End)
                self.data_entry.setTextCursor(cursor)
            current_length = len(self.data_entry.toPlainText())
            self.char_count_label.setText(f"{current_length} / {self.max_chars} characters")
        else:
            self.char_count_label.setText("0 / 0 characters")

    def show_password_dialog(self):
        dialog = PasswordDialog(self)
        if dialog.exec():
            password = dialog.get_password()
            if password:
                self.password = password
                analysis = PasswordAnalyzer().analyze(password)
                strength_text = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Good", 4: "Strong", 5: "Very Strong"}
                self.password_strength_label.setText(f"Password Strength: {strength_text[analysis['score']]}")

    def verify_totp(self):
        """Verify the TOTP code entered by the user."""
        totp_code, ok = QInputDialog.getText(self, "TOTP Verification", "Enter the TOTP code from your authenticator app:", QLineEdit.Normal)
        if not ok or not totp_code:
            raise ValueError("TOTP code required.")
        if not self.totp.verify(totp_code):
            self.rate_limiter.record_failure()
            raise ValueError("TOTP verification failed: Invalid code.")
        return True

    def execute(self):
        if not self.input_file:
            QMessageBox.critical(self, "Error", "Select an input file.")
            return
        
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        handler = ImageHandler() if self.media_type == "image" else AudioHandler()

        try:
            if self.action == "encode":
                if not self.output_file:
                    raise ValueError("Select an output file.")
                if not self.data_entry.toPlainText():
                    raise ValueError("Enter data to hide.")
                
                data = self.data_entry.toPlainText().encode('utf-8')
                logging.debug(f"Input data: {data[:10]}... (type: {type(data)})")

                if self.auto_key_radio.isChecked():
                    key = Fernet.generate_key()
                    encryptor = Encryptor(key)
                    encrypted_data = encryptor.encrypt(data)
                    hidden_data = b'\x00' + encrypted_data
                    handler.encode(self.input_file, hidden_data, self.output_file)
                    QApplication.clipboard().setText(key.decode())
                    self.progress_bar.setValue(100)
                    QMessageBox.information(
                        self,
                        "Success",
                        "Encoding complete. Key copied to clipboard."
                    )
                else:  # Custom Password
                    password = self.password
                    if not password:
                        password, ok = QInputDialog.getText(self, "Password", "Enter password:", QLineEdit.Password)
                        if not ok or not password:
                            raise ValueError("Password required.")
                    key, salt = derive_key(password)
                    encryptor = Encryptor(key)
                    encrypted_data = encryptor.encrypt(data)
                    hidden_data = b'\x01' + salt + encrypted_data
                    handler.encode(self.input_file, hidden_data, self.output_file)
                    self.progress_bar.setValue(100)
                    QMessageBox.information(
                        self,
                        "Success",
                        "Encoding complete. Remember your password."
                    )
                    self.password = None

            else:  # Decode
                if not self.rate_limiter.can_attempt():
                    remaining = int(self.rate_limiter.lockout_seconds - (time.time() - self.rate_limiter.attempts[-1]))
                    raise ValueError(f"Too many failed attempts. Wait {remaining // 60} minutes.")
                
                # Verify TOTP before decoding
                self.verify_totp()

                hidden_data = handler.decode(self.input_file)
                if not isinstance(hidden_data, bytes):
                    raise TypeError(f"Decoded data must be bytes, got {type(hidden_data)}")
                if len(hidden_data) < 1:
                    raise ValueError("No hidden data found.")
                
                flag = hidden_data[0]
                try:
                    if flag == 0:  # Auto-generated key
                        key, ok = QInputDialog.getText(self, "Key", "Enter encryption key:", QLineEdit.Password)
                        if not ok or not key:
                            raise ValueError("Key required.")
                        encryptor = Encryptor(key.encode())
                        decrypted_data = encryptor.decrypt(hidden_data[1:])
                        self.progress_bar.setValue(100)
                        QMessageBox.information(self, "Decoded Data", decrypted_data.decode('utf-8'))
                    elif flag == 1:  # Custom password
                        if len(hidden_data) < 17:
                            raise ValueError("Invalid data format.")
                        salt = hidden_data[1:17]
                        password, ok = QInputDialog.getText(self, "Password", "Enter password:", QLineEdit.Password)
                        if not ok or not password:
                            raise ValueError("Password required.")
                        key, _ = derive_key(password, salt)
                        encryptor = Encryptor(key)
                        decrypted_data = encryptor.decrypt(hidden_data[17:])
                        self.progress_bar.setValue(100)
                        QMessageBox.information(self, "Decoded Data", decrypted_data.decode('utf-8'))
                    else:
                        raise ValueError(f"Unknown flag: {flag}")
                except Exception as decrypt_error:
                    self.rate_limiter.record_failure()
                    raise decrypt_error

            self.status_label.setText("Operation complete")
        except Exception as e:
            logging.error(f"Execution error: {e}")
            QMessageBox.critical(self, "Error", str(e))
            self.status_label.setText("Operation failed")
        
        self.progress_bar.setVisible(False)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SteganographyApp()
    window.show()
    sys.exit(app.exec())