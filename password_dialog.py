import logging
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QSlider, QCheckBox,
    QPushButton, QLineEdit
)
from PySide6.QtCore import Qt
from password import PasswordGenerator, PasswordAnalyzer

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