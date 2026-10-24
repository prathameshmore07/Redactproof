import re
import hashlib
from typing import List, Tuple
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity

# Pre-compiled high precision regular expressions
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_REGEX = re.compile(r'(\+?\d{1,3}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b')

# Secret formats
JWT_REGEX = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
BEARER_REGEX = re.compile(r'\bBearer\s+([A-Za-z0-9._~+/-]{16,})\b', re.IGNORECASE)
AWS_KEY_REGEX = re.compile(r'\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b')
GITHUB_TOKEN_REGEX = re.compile(r'\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}')
STRIPE_KEY_REGEX = re.compile(r'\b(sk|pk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b')
SLACK_TOKEN_REGEX = re.compile(r'\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b')
OPENAI_KEY_REGEX = re.compile(r'\bsk-(?:proj-|live-)?[a-zA-Z0-9_-]{32,}\b')
PRIVATE_KEY_REGEX = re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')
GENERIC_API_KEY_REGEX = re.compile(r'(?:api[_-]?key|secret|token|password|auth|access[_-]?key)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{16,})["\']?', re.IGNORECASE)

def hash_secret(text: str, salt: str = "redactproof-salt") -> str:
    return hashlib.sha256((salt + text).encode("utf-8")).hexdigest()

class RegexDetector:
    """Detects credentials, emails, phone numbers, and keys via deterministic regex."""

    def detect(self, items: List[TextItem], salt: str = "redactproof-salt") -> List[Finding]:
        findings: List[Finding] = []

        for item in items:
            text = item.text

            # 1. Emails (Personal Identity)
            for m in EMAIL_REGEX.finditer(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.PERSONAL_IDENTITY,
                        detector="regex_email",
                        confidence=0.98,
                        action=Action.REDACT,
                        text_length=len(m.group(0)),
                        text_salted_sha256=hash_secret(m.group(0), salt),
                        rationale=f"Email address detected",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

            # 2. AWS Keys
            for m in AWS_KEY_REGEX.finditer(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_aws_key",
                        confidence=0.99,
                        action=Action.REDACT,
                        text_length=len(m.group(0)),
                        text_salted_sha256=hash_secret(m.group(0), salt),
                        rationale="AWS Access Key ID detected",
                        sensitivity=Sensitivity.CRITICAL,
                    )
                )

            # 3. GitHub Tokens
            for m in GITHUB_TOKEN_REGEX.finditer(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_github_token",
                        confidence=0.99,
                        action=Action.REDACT,
                        text_length=len(m.group(0)),
                        text_salted_sha256=hash_secret(m.group(0), salt),
                        rationale="GitHub Personal Access Token detected",
                        sensitivity=Sensitivity.CRITICAL,
                    )
                )

            # 4. Stripe Keys
            for m in STRIPE_KEY_REGEX.finditer(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_stripe_key",
                        confidence=0.99,
                        action=Action.REDACT,
                        text_length=len(m.group(0)),
                        text_salted_sha256=hash_secret(m.group(0), salt),
                        rationale="Stripe API Key detected",
                        sensitivity=Sensitivity.CRITICAL,
                    )
                )

            # 5. JWT Tokens
            for m in JWT_REGEX.finditer(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_jwt",
                        confidence=0.95,
                        action=Action.REDACT,
                        text_length=len(m.group(0)),
                        text_salted_sha256=hash_secret(m.group(0), salt),
                        rationale="JSON Web Token (JWT) detected",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

            # 6. Generic API Key Assignments (e.g. api_key = "...")
            for m in GENERIC_API_KEY_REGEX.finditer(text):
                secret_val = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_generic_secret",
                        confidence=0.92,
                        action=Action.REDACT,
                        text_length=len(secret_val),
                        text_salted_sha256=hash_secret(secret_val, salt),
                        rationale="Explicit API key or token assignment",
                        sensitivity=Sensitivity.CRITICAL,
                    )
                )

            # 7. Private Keys
            if PRIVATE_KEY_REGEX.search(text):
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.CREDENTIAL,
                        detector="regex_private_key",
                        confidence=1.0,
                        action=Action.REDACT,
                        text_length=len(text),
                        text_salted_sha256=hash_secret(text, salt),
                        rationale="Private Key header detected",
                        sensitivity=Sensitivity.CRITICAL,
                    )
                )

        return findings
