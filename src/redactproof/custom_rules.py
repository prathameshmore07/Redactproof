import re
from typing import List, Tuple, Dict, Any, Optional
from .schemas import BoundingBox, TextItem, Finding, FindingCategory, Action, Sensitivity


class CustomRuleMatcher:
    """
    Parses and matches user-typed keywords, phrases, and regular expressions
    against extracted OCR text items or plain text.
    """

    @staticmethod
    def parse_user_input(
        text_input: str,
        is_regex: bool = False,
        case_sensitive: bool = False,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Parses comma-separated or newline-delimited user entries.
        Returns (compiled_rules, validation_errors).
        """
        if not text_input or not text_input.strip():
            return [], []

        raw_terms = []
        # Support both newline and comma separation
        for line in text_input.splitlines():
            for part in line.split(","):
                cleaned = part.strip()
                if cleaned and cleaned not in raw_terms:
                    raw_terms.append(cleaned)

        compiled_rules = []
        errors = []

        flags = 0 if case_sensitive else re.IGNORECASE

        for term in raw_terms:
            if is_regex:
                try:
                    compiled_re = re.compile(term, flags)
                    compiled_rules.append({
                        "original": term,
                        "pattern": compiled_re,
                        "is_regex": True,
                    })
                except re.error as e:
                    errors.append(f"Invalid regex '{term}': {e}")
            else:
                # Escape literal terms to make a safe regex pattern
                escaped = re.escape(term)
                # If term is alphanumeric, match with word boundary optionally
                compiled_re = re.compile(escaped, flags)
                compiled_rules.append({
                    "original": term,
                    "pattern": compiled_re,
                    "is_regex": False,
                })

        return compiled_rules, errors

    @staticmethod
    def match_against_text_items(
        text_items: List[TextItem],
        rules: List[Dict[str, Any]],
        action: Action = Action.REDACT,
        start_region_id: int = 9000,
    ) -> List[Finding]:
        """
        Scans all OCR TextItems for matches against compiled user rules.
        Calculates proportional sub-bounding boxes for partial text matches.
        """
        findings: List[Finding] = []
        curr_id = start_region_id

        for item in text_items:
            item_text = item.text
            if not item_text:
                continue

            for rule in rules:
                pattern = rule["pattern"]
                original_term = rule["original"]

                for match in pattern.finditer(item_text):
                    start_char, end_char = match.span()
                    matched_substr = match.group(0)

                    # Sub-box estimation
                    total_chars = max(1, len(item_text))
                    item_width = item.bbox.width
                    char_w = item_width / total_chars

                    raw_sub_x1 = int(item.bbox.x1 + start_char * char_w)
                    raw_sub_x2 = int(item.bbox.x1 + end_char * char_w)

                    # Guarantee minimum width and stay clamped inside item coordinates
                    sub_x1 = max(item.bbox.x1, min(item.bbox.x2 - 4, raw_sub_x1))
                    sub_x2 = max(sub_x1 + 4, min(item.bbox.x2, raw_sub_x2))
                    sub_y1 = item.bbox.y1
                    sub_y2 = max(sub_y1 + 4, item.bbox.y2)

                    finding_bbox = BoundingBox(
                        x1=sub_x1,
                        y1=sub_y1,
                        x2=sub_x2,
                        y2=sub_y2,
                    )

                    findings.append(
                        Finding(
                            region_id=curr_id,
                            bbox=finding_bbox,
                            category=FindingCategory.OTHER,
                            detector="user_custom",
                            confidence=1.0,
                            action=action,
                            text_length=len(matched_substr),
                            plaintext=matched_substr,
                            rationale=f"Custom keyword/pattern match: '{original_term}'",
                            sensitivity=Sensitivity.HIGH,
                        )
                    )
                    curr_id += 1

        return findings

    @staticmethod
    def sanitize_plain_text(
        text: str,
        rules: List[Dict[str, Any]],
        replacement: str = "[REDACTED]",
    ) -> Tuple[str, int]:
        """
        Directly replaces matched terms in plain text.
        Returns (sanitized_text, total_replacements_count).
        """
        sanitized = text
        total_count = 0

        for rule in rules:
            pattern = rule["pattern"]
            matches = list(pattern.finditer(sanitized))
            total_count += len(matches)
            sanitized = pattern.sub(replacement, sanitized)

        return sanitized, total_count


class SmartSuggestionsEngine:
    """
    Analyzes findings and policies to generate actionable, categorized,
    and priority-scored redaction recommendations for the user.
    """

    @staticmethod
    def categorize_finding(finding: Finding) -> Dict[str, Any]:
        """Maps a finding into a presentation-friendly category with icon, color, and sensitivity."""
        cat = finding.category.value
        icon = "🔒"
        badge_color = "#3b82f6"
        group_name = "Other Sensitive"

        if cat == "credential":
            icon = "🔑"
            badge_color = "#ef4444"
            group_name = "Credentials & Secrets"
        elif cat in ("personal_identity", "customer_identity"):
            icon = "👤"
            badge_color = "#f97316"
            group_name = "Personal Identifiers (PII)"
        elif cat in ("internal_hostname", "local_path_user"):
            icon = "🌐"
            badge_color = "#8b5cf6"
            group_name = "Infrastructure & System Paths"
        elif cat in ("face_or_avatar", "qr_or_barcode"):
            icon = "🖼️"
            badge_color = "#ec4899"
            group_name = "Visual Targets (Faces / Codes)"
        elif cat == "prompt_injection_attempt":
            icon = "⚠️"
            badge_color = "#dc2626"
            group_name = "Adversarial & Injections"
        elif finding.detector == "user_custom":
            icon = "✏️"
            badge_color = "#06b6d4"
            group_name = "Custom User Redactions"

        # Determine sensitivity badge
        sens = finding.sensitivity.value.upper()

        return {
            "group_name": group_name,
            "icon": icon,
            "badge_color": badge_color,
            "sensitivity": sens,
            "is_critical": sens in ("CRITICAL", "HIGH"),
        }
