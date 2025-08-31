import secrets
import string
import math
import time

class PasswordGenerator:
    """
    A class to generate secure passwords based on specified criteria.
    """
    def generate(self, length, use_upper=True, use_digits=True, use_symbols=True, pronounceable=False):
        """
        Generate a password based on the given parameters.

        Args:
            length (int): The length of the password.
            use_upper (bool): Include uppercase letters (default: True).
            use_digits (bool): Include digits (default: True).
            use_symbols (bool): Include symbols (default: True).
            pronounceable (bool): Generate a pronounceable password (default: False).
        Returns:
            str: The generated password.
        """
        if pronounceable:
            return self._generate_pronounceable(length)
        else:
            return self._generate_random(length, use_upper, use_digits, use_symbols)

    def _generate_random(self, length, use_upper, use_digits, use_symbols):
        """
        Generate a random password using the specified character sets.

        Args:
            length (int): The length of the password.
            use_upper (bool): Include uppercase letters.
            use_digits (bool): Include digits.
            use_symbols (bool): Include symbols.
        Returns:
            str: The generated random password.
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
        """
        Generate a pronounceable password by alternating consonants and vowels.

        Args:
            length (int): The length of the password.
        Returns:
            str: The generated pronounceable password.
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
    """
    A class to analyze the strength of a password.
    """
    def analyze(self, password):
        """
        Analyze the password and return its strength score and entropy.

        Args:
            password (str): The password to analyze.
        Returns:
            dict: A dictionary containing:
                - 'score' (int): Strength score from 0 to 5.
                - 'entropy' (float): Entropy in bits, rounded to 2 decimal places.
        """
        length = len(password)
        has_upper = any(c in string.ascii_uppercase for c in password)
        has_lower = any(c in string.ascii_lowercase for c in password)
        has_digit = any(c in string.digits for c in password)
        has_symbol = any(c in string.punctuation for c in password)

        # Calculate strength score
        score = 0
        if length >= 8:
            score += 1
        if has_upper:
            score += 1
        if has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_symbol:
            score += 1

        # Estimate character set size for entropy calculation
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += len(string.punctuation)

        # Calculate entropy: length * log2(charset_size)
        if charset_size == 0:
            entropy = 0
        else:
            entropy = length * math.log2(charset_size)

        return {
            'score': score,
            'entropy': round(entropy, 2)
        }

class RateLimiter:
    """
    A class to limit the rate of attempts, useful for preventing brute-force attacks.
    """
    def __init__(self, max_attempts=5, window_seconds=600, lockout_seconds=1800):
        """
        Initialize the RateLimiter.

        Args:
            max_attempts (int): Maximum number of attempts allowed in the window (default: 5).
            window_seconds (int): Time window in seconds for attempts (default: 600, i.e., 10 minutes).
            lockout_seconds (int): Lockout duration in seconds after exceeding attempts (default: 1800, i.e., 30 minutes).
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.attempts = []

    def can_attempt(self):
        """
        Check if an attempt is allowed.

        Returns:
            bool: True if an attempt is allowed, False otherwise.
        """
        now = time.time()
        # Remove attempts older than the window
        self.attempts = [t for t in self.attempts if now - t < self.window_seconds]
        if len(self.attempts) < self.max_attempts:
            return True
        else:
            # Check if lockout period has passed since the last attempt
            last_attempt = self.attempts[-1]
            if now - last_attempt > self.lockout_seconds:
                self.attempts = []
                return True
            return False

    def record_failure(self):
        """
        Record a failed attempt.
        """
        now = time.time()
        self.attempts.append(now)