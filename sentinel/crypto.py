import math
import hashlib
import re
from typing import Dict, Any

def calculate_entropy(password: str) -> float:
    """Calculates Shannon entropy in bits for password strength assessment."""
    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 33
    
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 2)

def evaluate_password(password: str) -> Dict[str, Any]:
    """Evaluates password against length, entropy, and complexity rules."""
    entropy = calculate_entropy(password)
    length = len(password)
    
    strength = "Weak"
    if entropy >= 80 and length >= 14:
        strength = "Very Strong"
    elif entropy >= 60 and length >= 10:
        strength = "Strong"
    elif entropy >= 40 and length >= 8:
        strength = "Moderate"

    return {
        "length": length,
        "entropy_bits": entropy,
        "strength": strength,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_numbers": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password))
    }

def identify_hash(hash_str: str) -> str:
    """Identifies potential hash algorithm based on length and character set."""
    h = hash_str.strip()
    if not re.fullmatch(r"^[a-fA-F0-9]+$", h):
        if h.startswith(("$2a$", "$2b$", "$2y$")):
            return "Bcrypt"
        return "Unknown / Salted Format"
    
    length = len(h)
    if length == 32: return "MD5 / NTLM"
    if length == 40: return "SHA-1"
    if length == 56: return "SHA-224"
    if length == 64: return "SHA-256"
    if length == 96: return "SHA-384"
    if length == 128: return "SHA-512"
    return "Unknown"
