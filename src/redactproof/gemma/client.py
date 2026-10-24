import json
import re
import requests
from typing import List, Optional, Tuple, Dict, Any
from ..schemas import TextItem, Finding, FindingCategory, Action, Sensitivity
from ..config import settings
from .schemas import (
    ModelReviewResponse,
    ModelStrangerTestResponse,
    ModelAdversaryResponse,
    ModelFindingItem,
    ModelRelationalRisk,
)
from .prompts import (
    REVIEW_SYSTEM_PROMPT,
    STRANGER_TEST_SYSTEM_PROMPT,
    ADVERSARY_SYSTEM_PROMPT,
    format_ocr_items_for_prompt,
)

class GemmaClient:
    """
    Client for local Gemma 4 model via Ollama.
    Enforces schema-constrained JSON output and Pydantic validation.
    Provides offline mock fallback for tests and air-gapped CI environments.
    """

    def __init__(
        self,
        base_url: str = settings.ollama_url,
        model_name: Optional[str] = None,
        timeout: float = settings.gemma_timeout_seconds,
        runtime_mode: str = "auto",  # "auto", "ollama", "mock"
    ):
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name or settings.gemma_model
        self.timeout = timeout
        self.runtime_mode = runtime_mode
        self._active_model = self._detect_model()

    def _detect_model(self) -> str:
        if self.runtime_mode == "mock":
            return "mock-gemma4"

        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=2.0)
            if resp.status_code == 200:
                models = [m.get("name", "") for m in resp.json().get("models", [])]
                if self.model_name in models:
                    return self.model_name
                # Check for other gemma variants
                for m in models:
                    if "gemma4" in m or "gemma" in m:
                        return m
        except Exception:
            pass

        return self.model_name

    def is_ollama_online(self) -> bool:
        if self.runtime_mode == "mock":
            return False
        try:
            r = requests.get(f"{self.base_url}/api/version", timeout=1.5)
            return r.status_code == 200
        except Exception:
            return False

    def _call_ollama(self, prompt: str, system: str) -> Optional[str]:
        if not self.is_ollama_online():
            return None

        payload = {
            "model": self._active_model,
            "system": system,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
            },
        }

        try:
            resp = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("response", "")
        except Exception:
            return None
        return None

    def review_ambiguous_and_relational(
        self, items: List[TextItem], destination: str
    ) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        """Classify ambiguous regions and identify relational risks."""
        if not items:
            return [], []

        formatted_data = format_ocr_items_for_prompt(items)
        raw_json = self._call_ollama(
            prompt=formatted_data,
            system=REVIEW_SYSTEM_PROMPT.replace("{destination}", destination),
        )

        findings: List[Finding] = []
        relational_risks: List[Dict[str, Any]] = []

        if raw_json:
            try:
                parsed = ModelReviewResponse.model_validate_json(raw_json)
                item_map = {it.region_id: it for it in items}

                for item in parsed.findings:
                    if item.region_id in item_map:
                        orig = item_map[item.region_id]
                        findings.append(
                            Finding(
                                region_id=item.region_id,
                                bbox=orig.bbox,
                                category=FindingCategory(item.category) if item.category in FindingCategory._value2member_map_ else FindingCategory.AMBIGUOUS,
                                detector="gemma_reviewer",
                                confidence=item.confidence,
                                action=Action(item.proposed_action) if item.proposed_action in Action._value2member_map_ else Action.REDACT,
                                text_length=len(orig.text),
                                rationale=item.rationale,
                                sensitivity=Sensitivity(item.sensitivity) if item.sensitivity in Sensitivity._value2member_map_ else Sensitivity.HIGH,
                            )
                        )

                for rel in parsed.relational_risks:
                    relational_risks.append(rel.model_dump())
                return findings, relational_risks
            except Exception:
                pass

        # Offline / Mock heuristics when Ollama is unavailable
        findings, relational_risks = self._heuristic_mock_review(items, destination)
        return findings, relational_risks

    def stranger_test(self, items: List[TextItem], destination: str) -> List[str]:
        """Perform the Stranger Test: what can an outsider infer from visible text?"""
        if not items:
            return []

        formatted_data = format_ocr_items_for_prompt(items)
        raw_json = self._call_ollama(
            prompt=formatted_data,
            system=STRANGER_TEST_SYSTEM_PROMPT.replace("{destination}", destination),
        )

        if raw_json:
            try:
                parsed = ModelStrangerTestResponse.model_validate_json(raw_json)
                return parsed.inferences
            except Exception:
                pass

        # Mock / Fallback inferences based on OCR items
        return self._heuristic_mock_stranger_test(items, destination)

    def adversary_attack(self, items: List[TextItem], destination: str) -> Tuple[bool, List[str]]:
        """Adversarial re-attack on output image text."""
        if not items:
            return True, []

        formatted_data = format_ocr_items_for_prompt(items)
        raw_json = self._call_ollama(
            prompt=formatted_data,
            system=ADVERSARY_SYSTEM_PROMPT.replace("{destination}", destination),
        )

        if raw_json:
            try:
                parsed = ModelAdversaryResponse.model_validate_json(raw_json)
                return parsed.clean, parsed.residual_findings
            except Exception:
                pass

        # Mock / Fallback check
        return self._heuristic_mock_adversary(items, destination)

    # --- Heuristic fallbacks for offline / deterministic testing ---

    def _heuristic_mock_review(
        self, items: List[TextItem], destination: str
    ) -> Tuple[List[Finding], List[Dict[str, Any]]]:
        findings: List[Finding] = []
        relational_risks: List[Dict[str, Any]] = []

        # Detect staging hosts, customer references, tier words
        customer_regions = []
        tier_regions = []
        staging_regions = []

        for it in items:
            t = it.text.lower()
            if any(w in t for w in ["acme", "globex", "corp", "inc", "customer"]):
                customer_regions.append(it.region_id)
            if any(w in t for w in ["enterprise", "plan", "premium", "tier", "$", "billing"]):
                tier_regions.append(it.region_id)
            if any(w in t for w in ["staging", "internal", "k8s", "prod-cluster", "dev-backend"]):
                staging_regions.append(it.region_id)

        # Relational disclosure: customer + tier + host
        if customer_regions and (tier_regions or staging_regions):
            all_involved = list(set(customer_regions + tier_regions + staging_regions))
            relational_risks.append({
                "region_ids": all_involved,
                "inference": "Reveals customer identity linked to account tier or staging infrastructure.",
                "proposed_action": "redact",
            })
            for rid in all_involved:
                orig = next(x for x in items if x.region_id == rid)
                findings.append(
                    Finding(
                        region_id=rid,
                        bbox=orig.bbox,
                        category=FindingCategory.CUSTOMER_IDENTITY,
                        detector="gemma_relational_detector",
                        confidence=0.88,
                        action=Action.REDACT,
                        text_length=len(orig.text),
                        rationale="Part of relational disclosure identifying customer tier or infrastructure.",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

        return findings, relational_risks

    def _heuristic_mock_stranger_test(self, items: List[TextItem], destination: str) -> List[str]:
        inferences = []
        joined = " ".join([it.text.lower() for it in items])

        if any(w in joined for w in ["acme", "globex", "customer"]):
            inferences.append("Customer name or organization identity visible")
        if any(w in joined for w in ["enterprise", "plan", "premium", "billing"]):
            inferences.append("Commercial account tier or subscription status inferable")
        if any(w in joined for w in ["staging", "internal", "10.", "192.168.", "localhost"]):
            inferences.append("Internal network architecture and staging endpoint names exposed")
        if any(w in joined for w in ["/users/", "/home/"]):
            inferences.append("Local operating system username and directory layout revealed")
        if any(w in joined for w in ["token", "key", "secret", "bearer"]):
            inferences.append("Authentication credentials or access tokens present")

        return inferences

    def _heuristic_mock_adversary(
        self, items: List[TextItem], destination: str
    ) -> Tuple[bool, List[str]]:
        residual = []
        for it in items:
            t = it.text.lower()
            if any(w in t for w in ["bearer", "ghp_", "sk_live", "eyjhbg"]):
                residual.append(f"Residual secret token remaining in region {it.region_id}: {it.text[:12]}...")
            if any(w in t for w in [".internal", ".corp", "staging-"]):
                residual.append(f"Residual internal hostname remaining in region {it.region_id}")

        clean = len(residual) == 0
        return clean, residual
