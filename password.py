import secrets, string, re
from typing import Tuple

def generate_password(length: int = 16, use_digits: bool = True, use_symbols: bool = True) -> str:
    if length < 8:
        raise ValueError("Password length should be at least 8.")
    alphabet = string.ascii_letters
    if use_digits: alphabet += string.digits
    if use_symbols: alphabet += "!@#$%^&*()-_=+[]{};:,.?/\\|"

    parts = []
    if use_digits: parts.append(secrets.choice(string.digits))
    if use_symbols: parts.append(secrets.choice("!@#$%^&*()-_=+[]{};:,.?/\\|"))
    parts.append(secrets.choice(string.ascii_lowercase))
    parts.append(secrets.choice(string.ascii_uppercase))
    while len(parts) < length:
        parts.append(secrets.choice(alphabet))
    secrets.SystemRandom().shuffle(parts)
    return "".join(parts[:length])

def strength_label(pw: str) -> Tuple[int, str]:
    score = 0
    if len(pw) >= 12: score += 1
    if len(pw) >= 16: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"[!@#$%^&*()\-\_=+\[\]{};:,.?/\\|]", pw): score += 1
    if re.search(r"(.)\1{2,}", pw): score -= 1

    if score <= 2: return score, "weak"
    elif score <= 4: return score, "medium"
    else: return score, "strong"
