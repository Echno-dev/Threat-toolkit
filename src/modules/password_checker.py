"""
Password Strength Checker Module for Multinedor!!!
Evaluates password security using length, character diversity,
dictionary checks, and entropy calculation.
Now extended with HIBP Pwned Passwords breach check.
"""

import re
import string
import math
import hashlib
import requests   # <-- new import for API call

class PasswordChecker:
    def __init__(self):
        self.common_passwords = [
            'password', '123456', '123456789', '12345678', '12345', '1234567',
            'password123', 'admin', 'qwerty', 'abc123', 'welcome',
            'monkey', 'dragon', 'master', 'shadow', 'michael', 'superman', 'batman'
        ]
        self.char_sets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }

    # ----------------------------
    # Strength & Entropy Checks
    # ----------------------------
    def calculate_entropy(self, password):
        charset_size = 0
        if any(c in self.char_sets['lowercase'] for c in password):
            charset_size += len(self.char_sets['lowercase'])
        if any(c in self.char_sets['uppercase'] for c in password):
            charset_size += len(self.char_sets['uppercase'])
        if any(c in self.char_sets['digits'] for c in password):
            charset_size += len(self.char_sets['digits'])
        if any(c in self.char_sets['special'] for c in password):
            charset_size += len(self.char_sets['special'])
        if charset_size == 0: return 0.0
        entropy = math.log2(charset_size) * len(password)
        return round(entropy, 2)

    def check_character_requirements(self, password):
        return {
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digits': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
            'min_length': len(password) >= 8
        }

    def check_common_patterns(self, password):
        issues = {
            'is_common': password.lower() in [p.lower() for p in self.common_passwords],
            'has_sequential': bool(re.search(r'(012|123|234|abc|bcd|cde|def)', password.lower())),
            'has_repetitive': bool(re.search(r'(.)\1{2,}', password)),
            'is_keyboard_pattern': any(p in password.lower() for p in ['qwerty', 'asdf', 'zxcv', '1234'])
        }
        return issues

    def calculate_strength_score(self, password):
        if not password: return 0, "Empty"
        score = min(25, len(password) * 2)  # Length
        char_reqs = self.check_character_requirements(password)
        score += sum(10 for req, met in char_reqs.items() if met and req != 'min_length')
        entropy = self.calculate_entropy(password)
        score += min(25, entropy/3)
        patterns = self.check_common_patterns(password)
        score -= sum(5 for issue, present in patterns.items() if present)
        score = max(0, min(100, score))
        if score >= 80: strength = "Very Strong"
        elif score >= 60: strength = "Strong"
        elif score >= 40: strength = "Medium"
        elif score >= 20: strength = "Weak"
        else: strength = "Very Weak"
        return int(score), strength

    def get_recommendations(self, password):
        recommendations = []
        if len(password) < 8:
            recommendations.append("• Use at least 8 characters (12+ recommended)")
        char_reqs = self.check_character_requirements(password)
        if not char_reqs['has_lowercase']:
            recommendations.append("• Add lowercase letters (a-z)")
        if not char_reqs['has_uppercase']:
            recommendations.append("• Add uppercase letters (A-Z)")
        if not char_reqs['has_digits']:
            recommendations.append("• Add numbers (0-9)")
        if not char_reqs['has_special']:
            recommendations.append("• Add special characters (!@#$%^&*)")
        patterns = self.check_common_patterns(password)
        if patterns['is_common']:
            recommendations.append("• Avoid common passwords")
        if patterns['has_sequential']:
            recommendations.append("• Avoid sequential characters (123, abc)")
        if patterns['has_repetitive']:
            recommendations.append("• Avoid repetitive characters (aaa, 111)")
        if patterns['is_keyboard_pattern']:
            recommendations.append("• Avoid keyboard patterns (qwerty, asdf)")
        if not recommendations:
            recommendations.append("• Excellent password! Consider using a password manager")
        return recommendations

    def comprehensive_check(self, password):
        score, strength = self.calculate_strength_score(password)
        entropy = self.calculate_entropy(password)
        char_reqs = self.check_character_requirements(password)
        patterns = self.check_common_patterns(password)
        recommendations = self.get_recommendations(password)
        return {
            'password_length': len(password),
            'strength_score': score,
            'strength_level': strength,
            'entropy_bits': entropy,
            'character_requirements': char_reqs,
            'pattern_analysis': patterns,
            'recommendations': recommendations,
            'is_secure': score >= 60 and not patterns['is_common']
        }

    # ----------------------------
    # NEW: HIBP Breach Check
    # ----------------------------
    def check_pwned_password(self, password):
        """
        Check if password is found in HIBP Pwned Passwords.
        Returns: (found: bool, count: int, error: str|None)
        """
        if not password:
            return False, 0, "Empty password"

        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "Multinador-Toolkit"})
            if r.status_code != 200:
                return False, 0, f"API error {r.status_code}"
            for line in r.text.splitlines():
                h, count = line.split(":")
                if h.strip().upper() == suffix:
                    return True, int(count), None
            return False, 0, None
        except Exception as e:
            return False, 0, str(e)


if __name__ == "__main__":
    checker = PasswordChecker()
    pw = input("Enter password to check: ")

    print("\n--- Strength Analysis ---")
    print(checker.comprehensive_check(pw))

    print("\n--- HIBP Breach Check ---")
    found, count, err = checker.check_pwned_password(pw)
    if err:
        print("Error:", err)
    elif found:
        print(f"❌ Password FOUND in {count} breaches! Change it immediately.")
    else:
        print("✅ Password NOT found in known breaches.")
