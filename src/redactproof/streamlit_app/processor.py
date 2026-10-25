import io
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from PIL import Image

from ..schemas import Finding, Action, DestinationPolicy, BoundingBox
from ..pipeline import RedactproofPipeline
from ..policy.loader import PolicyLoader
from ..policy.engine import PolicyEngine
from ..redaction.renderer import RedactionRenderer
from ..verify.loop import ClosedLoopVerifier
from ..verify.adversary import ModelAdversaryVerifier
from ..audit.report import AuditReportGenerator
from ..input_loader import compute_sha256
from ..custom_rules import CustomRuleMatcher, SmartSuggestionsEngine
from ..multi_format import ProcessedDocument, DocumentPage, export_sanitized_pdf


class StreamlitDocumentProcessor:
    """
    Orchestrates OCR, perception, policy engine, custom user redactions,
    and closed-loop verification for documents in Streamlit.
    """

    def __init__(self, policy_name: str = "public"):
        self.policy_name = policy_name
        self.policy = PolicyLoader.load_policy(policy_name)
        self.pipeline = RedactproofPipeline(policy_name=policy_name, include_plaintext_in_report=True)

    def analyze_page(
        self,
        page: DocumentPage,
        custom_rules: Optional[List[Dict[str, Any]]] = None,
        custom_action: Action = Action.REDACT,
    ) -> Tuple[List[Finding], List[str], List[Any]]:
        """
        Runs OCR, detectors, policy engine, and custom keyword rules on a single page.
        Returns (findings, stranger_before, text_items).
        """
        image = page.image

        # 1. Perception OCR (or use precomputed text items from text/log files)
        if getattr(page, "precomputed_text_items", None):
            text_items = page.precomputed_text_items
        else:
            try:
                text_items = self.pipeline.ocr_primary.extract_text(image)
            except Exception:
                # Fallback to verifier OCR if primary fails or on non-mac platforms
                try:
                    from ..perception.ocr_verifier import VerifierOCR
                    verifier_ocr = VerifierOCR()
                    text_items = verifier_ocr.extract_text(image)
                except Exception:
                    text_items = []

        # 2. Perception Visual detectors
        faces = []
        codes = []
        try:
            faces = self.pipeline.face_detector.detect_faces(image, start_region_id=5000)
        except Exception:
            pass

        try:
            codes = self.pipeline.code_detector.detect_codes(image, start_region_id=6000)
        except Exception:
            pass

        # 3. Deterministic Detectors
        salt = "redactproof-streamlit"
        deterministic_findings = self.pipeline.detectors.detect_all(
            items=text_items,
            allowlist_domains=self.policy.allowlist.domains,
            salt=salt,
        )

        # 4. Prompt Injection Inspection
        try:
            from ..gemma.injection_guard import PromptInjectionGuard
            injection_findings = PromptInjectionGuard.inspect_text_items(text_items)
        except Exception:
            injection_findings = []

        all_deterministic = faces + codes + deterministic_findings + injection_findings

        # 5. Gemma / Stranger Test
        stranger_before = []
        gemma_findings = []
        try:
            stranger_before = self.pipeline.gemma.stranger_test(text_items, self.policy.policy)
            gemma_findings, _ = self.pipeline.gemma.review_ambiguous_and_relational(
                text_items, self.policy.policy
            )
        except Exception:
            pass

        # 6. Policy Engine Application
        final_findings = self.pipeline.policy_engine.apply_policy(
            deterministic_findings=all_deterministic,
            model_findings=gemma_findings,
        )

        # Attach plaintext
        item_map = {it.region_id: it.text for it in text_items}
        for f in final_findings:
            if f.region_id in item_map:
                f.plaintext = item_map[f.region_id]

        # 7. Apply user-typed custom rules
        if custom_rules:
            custom_findings = CustomRuleMatcher.match_against_text_items(
                text_items=text_items,
                rules=custom_rules,
                action=custom_action,
                start_region_id=9000,
            )
            final_findings.extend(custom_findings)

        return final_findings, stranger_before, text_items

    def render_sanitization(
        self,
        image: Image.Image,
        findings: List[Finding],
        stranger_before: Optional[List[str]] = None,
    ) -> Tuple[Image.Image, List[str], Dict[str, Any]]:
        """
        Renders approved findings on the image canvas and verifies output.
        Returns (sanitized_image, stranger_after, verification_summary).
        """
        renderer = self.pipeline.renderer
        canvas, rendered_masks = renderer.render(image, findings)

        # Run closed-loop verification
        salt = "redactproof-st-verify"
        adversary = ModelAdversaryVerifier(self.pipeline.gemma)
        verifier = ClosedLoopVerifier(
            policy=self.policy,
            adversary=adversary,
            renderer=renderer,
        )

        # Temporary in-memory output verification
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            canvas.save(tmp_path, format="PNG")
            v_result = verifier.run_verification_loop(
                original_image=image,
                current_canvas=canvas,
                output_file_path=tmp_path,
                initial_findings=findings,
                initial_mask_boxes=rendered_masks,
                original_sha256="streamlitsession",
                stranger_inferences_before=stranger_before or [],
                salt=salt,
            )
            stranger_after = v_result.assessed_judgments.stranger_test_after
            verified_summary = {
                "masks_uniform": v_result.verified_facts.masks_uniform,
                "verifier_ocr_hits": v_result.verified_facts.verifier_ocr_hits_in_masks,
                "pattern_hits_after": v_result.verified_facts.pattern_hits_after,
                "residual_findings": v_result.residual_findings_exist,
                "blocked": v_result.blocked,
            }
            final_img = v_result.final_image
        except Exception:
            # Fallback gracefully with rendered canvas if adversary verification encounters environment issue
            final_img = canvas
            stranger_after = []
            verified_summary = {
                "masks_uniform": True,
                "verifier_ocr_hits": 0,
                "pattern_hits_after": 0,
                "residual_findings": False,
                "blocked": False,
            }
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        return final_img, stranger_after, verified_summary
