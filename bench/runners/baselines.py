from typing import List, Tuple
from PIL import Image
from redactproof.schemas import BoundingBox, Finding, Action
from redactproof.perception.ocr_apple_vision import AppleVisionOCR
from redactproof.detectors.regex import RegexDetector
from redactproof.detectors import CompositeDetector
from redactproof.gemma.client import GemmaClient
from redactproof.policy.engine import PolicyEngine
from redactproof.policy.loader import PolicyLoader
from redactproof.redaction.renderer import RedactionRenderer
from redactproof.verify.loop import ClosedLoopVerifier
from redactproof.verify.adversary import ModelAdversaryVerifier

class BaselineEvaluator:
    """Implements the 5 comparison baselines defined in RedactBench (Section 15)."""

    def __init__(self, runtime: str = "mock"):
        self.ocr = AppleVisionOCR()
        self.regex = RegexDetector()
        self.composite = CompositeDetector()
        self.gemma = GemmaClient(runtime_mode=runtime)
        self.policy = PolicyLoader.load_policy("public")
        self.policy_engine = PolicyEngine(self.policy)
        self.renderer = RedactionRenderer()

    def run_regex_only(self, image: Image.Image) -> Image.Image:
        items = self.ocr.extract_text(image)
        findings = self.regex.detect(items)
        canvas, _ = self.renderer.render(image, findings)
        return canvas

    def run_ocr_ner(self, image: Image.Image) -> Image.Image:
        items = self.ocr.extract_text(image)
        regex_finds = self.regex.detect(items)
        # Mock simple NER for email/hostnames
        composite_finds = self.composite.detect_all(items, allowlist_domains=["docs.python.org", "github.com"])
        canvas, _ = self.renderer.render(image, composite_finds)
        return canvas

    def run_gemma_only(self, image: Image.Image) -> Image.Image:
        items = self.ocr.extract_text(image)
        # Directly prompt Gemma with zero deterministic detectors
        gemma_finds, _ = self.gemma.review_ambiguous_and_relational(items, "public")
        canvas, _ = self.renderer.render(image, gemma_finds)
        return canvas

    def run_redactproof_no_verify(self, image: Image.Image) -> Image.Image:
        items = self.ocr.extract_text(image)
        det_finds = self.composite.detect_all(items, allowlist_domains=["docs.python.org", "github.com"])
        gemma_finds, _ = self.gemma.review_ambiguous_and_relational(items, "public")
        merged = self.policy_engine.apply_policy(det_finds, gemma_finds)
        canvas, _ = self.renderer.render(image, merged)
        return canvas

    def run_redactproof_full(self, image: Image.Image, temp_output_path) -> Image.Image:
        items = self.ocr.extract_text(image)
        det_finds = self.composite.detect_all(items, allowlist_domains=["docs.python.org", "github.com"])
        gemma_finds, _ = self.gemma.review_ambiguous_and_relational(items, "public")
        merged = self.policy_engine.apply_policy(det_finds, gemma_finds)
        canvas, masks = self.renderer.render(image, merged)

        adversary = ModelAdversaryVerifier(self.gemma)
        verifier = ClosedLoopVerifier(self.policy, adversary, self.renderer)
        v_result = verifier.run_verification_loop(
            original_image=image,
            current_canvas=canvas,
            output_file_path=temp_output_path,
            initial_findings=merged,
            initial_mask_boxes=masks,
            original_sha256="fake_sha256",
            stranger_inferences_before=[],
        )
        return v_result.final_image
