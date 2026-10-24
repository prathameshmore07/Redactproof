import re
from typing import List
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity
from .regex import hash_secret

LOCAL_USER_PATH_REGEX = re.compile(
    r'(?:/Users/|/home/|[A-Za-z]:\\Users\\)([a-zA-Z0-9._-]+)(?:/[^\s<>"\':]+|\\)?',
    re.IGNORECASE
)

class LocalPathDetector:
    """Detects local filesystem paths containing user account names."""

    def detect(self, items: List[TextItem], salt: str = "redactproof-salt") -> List[Finding]:
        findings: List[Finding] = []

        for item in items:
            text = item.text
            for match in LOCAL_USER_PATH_REGEX.finditer(text):
                full_path = match.group(0)
                username = match.group(1)
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.LOCAL_PATH_USER,
                        detector="local_path_user",
                        confidence=0.96,
                        action=Action.REDACT,
                        text_length=len(full_path),
                        text_salted_sha256=hash_secret(full_path, salt),
                        rationale=f"Local user path exposing local username '{username}'",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

        return findings
