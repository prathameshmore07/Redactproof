import ipaddress
import re
from typing import List
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity
from .regex import hash_secret

IPV4_CANDIDATE_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b')
INTERNAL_HOST_REGEX = re.compile(
    r'\b(?:[a-zA-Z0-9_-]+\.)+(?:internal|local|corp|staging|dev|private|lan|intra|test|svc|cluster\.local)\b|localhost(?::\d+)?\b',
    re.IGNORECASE
)

class IPAndHostDetector:
    """Detects private IP addresses and internal infrastructure hostnames."""

    def detect(self, items: List[TextItem], salt: str = "redactproof-salt") -> List[Finding]:
        findings: List[Finding] = []

        for item in items:
            text = item.text

            # 1. Private / Internal IPs
            for match in IPV4_CANDIDATE_REGEX.finditer(text):
                raw = match.group(0).split(":")[0]
                try:
                    ip = ipaddress.ip_address(raw)
                    if ip.is_private or ip.is_loopback or ip.is_reserved:
                        findings.append(
                            Finding(
                                region_id=item.region_id,
                                bbox=item.bbox,
                                category=FindingCategory.INTERNAL_HOSTNAME,
                                detector="private_ip",
                                confidence=0.97,
                                action=Action.REDACT,
                                text_length=len(match.group(0)),
                                text_salted_sha256=hash_secret(match.group(0), salt),
                                rationale=f"Private/Internal IP address detected: {raw}",
                                sensitivity=Sensitivity.HIGH,
                            )
                        )
                except ValueError:
                    pass

            # 2. Internal hostnames & staging clusters
            for match in INTERNAL_HOST_REGEX.finditer(text):
                host = match.group(0)
                findings.append(
                    Finding(
                        region_id=item.region_id,
                        bbox=item.bbox,
                        category=FindingCategory.INTERNAL_HOSTNAME,
                        detector="internal_hostname",
                        confidence=0.95,
                        action=Action.REDACT,
                        text_length=len(host),
                        text_salted_sha256=hash_secret(host, salt),
                        rationale=f"Internal infrastructure hostname or cluster address: {host}",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

        return findings
