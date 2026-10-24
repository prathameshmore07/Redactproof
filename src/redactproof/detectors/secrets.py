import math
import re
from typing import List
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity
from .regex import hash_secret

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in set(data):
        p_x = float(data.count(x)) / length
        entropy += - p_x * math.log2(p_x)
    return entropy

def luhn_check(card_number: str) -> bool:
    """Validate numeric card string using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

CARD_CANDIDATE_REGEX = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
TOKEN_CANDIDATE_REGEX = re.compile(r'\b[A-Za-z0-9+/=_-]{20,}\b')

class SecretsDetector:
    """Detects high-entropy random secrets and payment cards."""

    def detect(self, items: List[TextItem], salt: str = "redactproof-salt") -> List[Finding]:
        findings: List[Finding] = []

        for item in items:
            text = item.text

            # 1. Credit Cards with Luhn Check
            for match in CARD_CANDIDATE_REGEX.finditer(text):
                clean_num = "".join(filter(str.isdigit, match.group(0)))
                if luhn_check(clean_num):
                    findings.append(
                        Finding(
                            region_id=item.region_id,
                            bbox=item.bbox,
                            category=FindingCategory.CREDENTIAL,
                            detector="luhn_credit_card",
                            confidence=0.99,
                            action=Action.REDACT,
                            text_length=len(clean_num),
                            text_salted_sha256=hash_secret(clean_num, salt),
                            rationale="Payment card number validated via Luhn checksum",
                            sensitivity=Sensitivity.CRITICAL,
                        )
                    )

            # 2. High-Entropy Tokens / Hex / Base64 Hashes
            words = TOKEN_CANDIDATE_REGEX.findall(text)
            for word in words:
                # Exclude purely repetitive or English-like strings
                if len(word) >= 20:
                    ent = shannon_entropy(word)
                    # For base64 / mixed case tokens, entropy > 3.9 indicates high randomness
                    if ent >= 3.9:
                        findings.append(
                            Finding(
                                region_id=item.region_id,
                                bbox=item.bbox,
                                category=FindingCategory.CREDENTIAL,
                                detector="shannon_entropy_secret",
                                confidence=0.88,
                                action=Action.REDACT,
                                text_length=len(word),
                                text_salted_sha256=hash_secret(word, salt),
                                rationale=f"High-entropy secret token (entropy={ent:.2f} bits/char)",
                                sensitivity=Sensitivity.HIGH,
                            )
                        )

        return findings
