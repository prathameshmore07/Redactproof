import re
from urllib.parse import urlparse, parse_qs
from typing import List, Optional
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity
from .regex import hash_secret

URL_REGEX = re.compile(r'https?://[^\s<>"\')]+', re.IGNORECASE)
SENSITIVE_PARAM_NAMES = {"token", "key", "api_key", "secret", "auth", "password", "session", "code", "access_token"}

class URLDetector:
    """Detects URLs, checks for embedded tokens, and respects domain allowlists."""

    def detect(
        self,
        items: List[TextItem],
        allowlist_domains: Optional[List[str]] = None,
        salt: str = "redactproof-salt",
    ) -> List[Finding]:
        findings: List[Finding] = []
        allowlist_domains = [d.lower() for d in (allowlist_domains or [])]

        for item in items:
            text = item.text
            for match in URL_REGEX.finditer(text):
                raw_url = match.group(0).rstrip('.,;:)')
                try:
                    parsed = urlparse(raw_url)
                    hostname = (parsed.hostname or "").lower()
                    params = parse_qs(parsed.query)

                    # Check for sensitive query parameters
                    leaked_params = [p for p in params.keys() if p.lower() in SENSITIVE_PARAM_NAMES]
                    if leaked_params:
                        findings.append(
                            Finding(
                                region_id=item.region_id,
                                bbox=item.bbox,
                                category=FindingCategory.CREDENTIAL,
                                detector="url_token_param",
                                confidence=0.96,
                                action=Action.REDACT,
                                text_length=len(raw_url),
                                text_salted_sha256=hash_secret(raw_url, salt),
                                rationale=f"URL contains sensitive credential query parameter: {', '.join(leaked_params)}",
                                sensitivity=Sensitivity.CRITICAL,
                            )
                        )
                        continue

                    # If domain is explicitly in allowlist, mark as keep
                    if any(hostname == d or hostname.endswith("." + d) for d in allowlist_domains):
                        findings.append(
                            Finding(
                                region_id=item.region_id,
                                bbox=item.bbox,
                                category=FindingCategory.PUBLIC_PACKAGE_NAME,
                                detector="url_allowlist",
                                confidence=1.0,
                                action=Action.KEEP,
                                text_length=len(raw_url),
                                text_salted_sha256=hash_secret(raw_url, salt),
                                rationale=f"URL host '{hostname}' is in policy allowlist",
                                sensitivity=Sensitivity.LOW,
                            )
                        )
                except Exception:
                    pass

        return findings
