from typing import List, Optional
from ..schemas import TextItem, Finding
from .regex import RegexDetector
from .secrets import SecretsDetector
from .url import URLDetector
from .ip import IPAndHostDetector
from .local_paths import LocalPathDetector

class CompositeDetector:
    """Runs all deterministic detectors over perception text items."""

    def __init__(self):
        self.regex_detector = RegexDetector()
        self.secrets_detector = SecretsDetector()
        self.url_detector = URLDetector()
        self.ip_detector = IPAndHostDetector()
        self.local_paths_detector = LocalPathDetector()

    def detect_all(
        self,
        items: List[TextItem],
        allowlist_domains: Optional[List[str]] = None,
        salt: str = "redactproof-salt",
    ) -> List[Finding]:
        findings: List[Finding] = []
        findings.extend(self.regex_detector.detect(items, salt=salt))
        findings.extend(self.secrets_detector.detect(items, salt=salt))
        findings.extend(self.url_detector.detect(items, allowlist_domains=allowlist_domains, salt=salt))
        findings.extend(self.ip_detector.detect(items, salt=salt))
        findings.extend(self.local_paths_detector.detect(items, salt=salt))
        return findings

__all__ = [
    "RegexDetector",
    "SecretsDetector",
    "URLDetector",
    "IPAndHostDetector",
    "LocalPathDetector",
    "CompositeDetector",
]
