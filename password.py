import secrets
import string
import math
import time

class PasswordGenerator:
    """A class to generate secure passwords based on specified criteria."""
    
    def generate(self, length, use_upper=True, use_digits=True, use_symbols=True, pronounceable=False):
        """Generate a password.
        
        Args:
            length (int): The length of the password.
            use_upper (bool): Include uppercase letters.
            use_digits (bool): Include digits.
            use_symbols (bool): Include symbols.
            pronounceable (bool): Generate a pronounceable password.
        
        Returns:
            str: The generated password.
        """
        if pronounceable:
            return self._generate_pronounceable(length)
        else:
            return self._generate_random(length, use_upper, use_digits, use_symbols)

    def _generate_random(self, length, use_upper, use_digits, use_symbols):
        """Generate a random password.
        
        Args:
            length (int): The length of the password.
            use_upper (bool): Include uppercase letters.
            use_digits (bool): Include digits.
            use_symbols (bool): Include symbols.
        
        Returns:
            str: The generated password.
        
        Raises:
            ValueError: If no character sets are selected.
        """
        chars = string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += string.punctuation
        if not chars:
            raise ValueError("At least one character set must be selected")
        return ''.join(secrets.choice(chars) for _ in range(length))

    def _generate_pronounceable(self, length):
        """Generate a pronounceable password.
        
        Args:
            length (int): The length of the password.
        
        Returns:
            str: The generated password.
        """
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowels = 'aeiou'
        password = ''
        for i in range(length):
            if i % 2 == 0:
                password += secrets.choice(consonants)
            else:
                password += secrets.choice(vowels)
        return password

class PasswordAnalyzer:
    """A class to analyze the strength of a password."""
    
    def analyze(self, password):
        """Analyze password strength and entropy.
        
        Args:
            password (str): The password to analyze.
        
        Returns:
            dict: Contains 'score' (0-5) and 'entropy' (bits).
        """
        char_types = {
            'lower': string.ascii_lowercase,
            'upper': string.ascii_uppercase,
            'digit': string.digits,
            'symbol': string.punctuation
        }
        length = len(password)
        checks = {key: any(c in chars for c in password) for key, chars in char_types.items()}
        
        # Calculate strength score
        score = sum(checks.values()) + (length >= 8)
        
        # Estimate character set size for entropy
        charset_size = sum(
            26 if checks['lower'] else 0,
            26 if checks['upper'] else 0,
            10 if checks['digit'] else 0,
            len(string.punctuation) if checks['symbol'] else 0
        )
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0

        return {'score': score, 'entropy': round(entropy, 2)}

class RateLimiter:
    """A class to limit the rate of attempts."""
    
    def __init__(self, max_attempts=5, window_seconds=600, lockout_seconds=1800):
        """Initialize the RateLimiter.
        
        Args:
            max_attempts (int): Max attempts in the window (default: 5).
            window_seconds (int): Time window in seconds (default: 600).
            lockout_seconds (int): Lockout duration in seconds (default: 1800).
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.attempts = []
        self.lockout_until = 0  # Timestamp until which lockout is active

    def can_attempt(self):
        """Check if an attempt is allowed.
        
        Returns:
            bool: True if allowed, False otherwise.
        """
        now = time.time()
        if now < self.lockout_until:
            return False
        self.attempts = [t for t in self.attempts if now - t < self.window_seconds]
        return len(self.attempts) < self.max_attempts

    def record_failure(self):
        """Record a failed attempt."""
        now = time.time()
        self.attempts.append(now)
        self.attempts = [t for t in self.attempts if now - t < self.window_seconds]
        if len(self.attempts) >= self.max_attempts:
            self.lockout_until = now + self.lockout_seconds