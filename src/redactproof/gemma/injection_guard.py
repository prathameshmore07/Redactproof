import re
from typing import List, Tuple
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity

INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(?:all\s+)?previous\s+instructions?', re.IGNORECASE),
    re.compile(r'disregard\s+(?:all\s+)?(?:rules|instructions)', re.IGNORECASE),
    re.compile(r'mark\s+everything\s+(?:as\s+)?(?:safe|keep)', re.IGNORECASE),
    re.compile(r'system\s+prompt\s*:', re.IGNORECASE),
    re.compile(r'override\s+policy', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+in\s+developer\s+mode', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'never\s+redact', re.IGNORECASE),
]

class PromptInjectionGuard:
    """Defends against adversarial prompt injection embedded in screenshots."""

    @staticmethod
    def inspect_text_items(items: List[TextItem]) -> List[Finding]:
        findings: List[Finding] = []
        for item in items:
            text = item.text
            for pattern in INJECTION_PATTERNS:
                if pattern.search(text):
                    findings.append(
                        Finding(
                            region_id=item.region_id,
                            bbox=item.bbox,
                            category=FindingCategory.PROMPT_INJECTION_ATTEMPT,
                            detector="injection_guard",
                            confidence=1.0,
                            action=Action.REVIEW,
                            text_length=len(text),
                            rationale=f"Adversarial prompt injection pattern detected in image text: '{pattern.pattern}'",
                            sensitivity=Sensitivity.CRITICAL,
                        )
                    )
                    break
        return findings

    @staticmethod
    def sanitize_for_prompt(text: str) -> str:
        """Wraps text in strictly quoted untrusted data block."""
        escaped = text.replace('"', '\\"').replace('\n', ' ')
        return f'"{escaped}"'
