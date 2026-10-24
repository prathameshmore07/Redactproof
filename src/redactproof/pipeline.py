from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from PIL import Image

from .schemas import (
    BoundingBox,
    TextItem,
    Finding,
    DestinationPolicy,
    AuditReport,
    Action,
    FindingCategory,
)
from .input_loader import load_and_validate_image, compute_sha256
from .policy.loader import PolicyLoader
from .policy.engine import PolicyEngine
from .perception.ocr_apple_vision import AppleVisionOCR
from .perception.faces import AppleVisionFaceDetector
from .perception.codes import AppleVisionBarcodeDetector
from .detectors import CompositeDetector
from .gemma.injection_guard import PromptInjectionGuard
from .gemma.client import GemmaClient
from .redaction.renderer import RedactionRenderer
from .verify.loop import ClosedLoopVerifier, VerificationResult
from .verify.adversary import ModelAdversaryVerifier
from .audit.report import AuditReportGenerator
from .config import settings

class PipelineResult:
    def __init__(
        self,
        success: bool,
        exit_code: int,
        sanitized_image: Optional[Image.Image],
        output_path: Optional[Path],
        audit_report: AuditReport,
        findings: List[Finding],
        stranger_before: List[str],
        stranger_after: List[str],
        review_required: bool,
        blocked: bool,
    ):
        self.success = success
        self.exit_code = exit_code
        self.sanitized_image = sanitized_image
        self.output_path = output_path
        self.audit_report = audit_report
        self.findings = findings
        self.stranger_before = stranger_before
        self.stranger_after = stranger_after
        self.review_required = review_required
        self.blocked = blocked

class RedactproofPipeline:
    """End-to-end orchestration pipeline for Redactproof."""

    def __init__(
        self,
        policy_name: str = "public",
        gemma_runtime: str = "auto",
        gemma_model: Optional[str] = None,
        margin_px: int = settings.default_margin_px,
        strict_mode: bool = False,
        include_plaintext_in_report: bool = False,
    ):
        self.policy = PolicyLoader.load_policy(policy_name)
        self.policy_engine = PolicyEngine(self.policy)
        self.ocr_primary = AppleVisionOCR(recognition_level="accurate")
        self.face_detector = AppleVisionFaceDetector()
        self.code_detector = AppleVisionBarcodeDetector()
        self.detectors = CompositeDetector()
        self.gemma = GemmaClient(
            runtime_mode=gemma_runtime,
            model_name=gemma_model or settings.gemma_model,
        )
        self.renderer = RedactionRenderer(margin_px=margin_px)
        self.strict_mode = strict_mode
        self.include_plaintext = include_plaintext_in_report

    def run(
        self,
        input_path: Path,
        output_path: Optional[Path] = None,
        report_path: Optional[Path] = None,
    ) -> PipelineResult:
        # 1. Load and validate input
        loaded = load_and_validate_image(input_path)
        input_sha256 = loaded.file_hash
        image = loaded.image

        # 2. Perception pass
        text_items = self.ocr_primary.extract_text(image)
        face_findings = self.face_detector.detect_faces(image, start_region_id=5000)
        code_findings = self.code_detector.detect_codes(image, start_region_id=6000)

        # 3. Deterministic Detectors
        salt = "redactproof-" + input_sha256[:8]
        deterministic_findings = self.detectors.detect_all(
            items=text_items,
            allowlist_domains=self.policy.allowlist.domains,
            salt=salt,
        )

        # 4. Prompt Injection Inspection
        injection_findings = PromptInjectionGuard.inspect_text_items(text_items)

        # Combine all deterministic findings
        all_deterministic = face_findings + code_findings + deterministic_findings + injection_findings

        # 5. Gemma Review & Stranger Test (Before)
        stranger_before = self.gemma.stranger_test(text_items, self.policy.policy)
        gemma_findings, relational_risks = self.gemma.review_ambiguous_and_relational(
            text_items, self.policy.policy
        )

        # 6. Policy Engine Application (with Asymmetric Authority enforcement)
        final_findings = self.policy_engine.apply_policy(
            deterministic_findings=all_deterministic,
            model_findings=gemma_findings,
        )

        # Re-attach plaintext if requested
        if self.include_plaintext:
            item_map = {it.region_id: it.text for it in text_items}
            for f in final_findings:
                if f.region_id in item_map:
                    f.plaintext = item_map[f.region_id]

        # 7. Check Review Queue
        review_findings = [f for f in final_findings if f.action == Action.REVIEW]
        review_required = len(review_findings) > 0

        # If strict mode and review items remain, export is blocked
        if self.strict_mode and review_required:
            report = AuditReportGenerator.generate_report(
                input_path=input_path,
                input_hash=input_sha256,
                output_path=None,
                output_hash=None,
                policy=self.policy,
                findings=final_findings,
                verified=None,  # Not verified because blocked
                assessed=None,
                status="blocked_pending_review",
                include_plaintext=self.include_plaintext,
            )
            if report_path:
                AuditReportGenerator.save_report(report, report_path)
            return PipelineResult(
                success=False,
                exit_code=2,  # Exit code 2 for review blocked
                sanitized_image=None,
                output_path=None,
                audit_report=report,
                findings=final_findings,
                stranger_before=stranger_before,
                stranger_after=[],
                review_required=True,
                blocked=True,
            )

        # Determine output file path
        if not output_path:
            output_path = input_path.parent / f"{input_path.stem}.sanitized{input_path.suffix}"

        # 8. Render Redactions
        canvas, rendered_masks = self.renderer.render(image, final_findings)

        # 9. Closed-Loop Verification
        adversary_verifier = ModelAdversaryVerifier(self.gemma)
        verifier_loop = ClosedLoopVerifier(
            policy=self.policy,
            adversary=adversary_verifier,
            renderer=self.renderer,
        )

        v_result = verifier_loop.run_verification_loop(
            original_image=image,
            current_canvas=canvas,
            output_file_path=output_path,
            initial_findings=final_findings,
            initial_mask_boxes=rendered_masks,
            original_sha256=input_sha256,
            stranger_inferences_before=stranger_before,
            salt=salt,
        )

        # 10. Compute final output hash & audit report
        final_hash = compute_sha256(output_path)
        status = "sanitized_verified_with_residual_model_risk"
        if v_result.blocked:
            status = "blocked_residual_risk"
        elif v_result.residual_findings_exist:
            status = "residual_risk_flagged"

        report = AuditReportGenerator.generate_report(
            input_path=input_path,
            input_hash=input_sha256,
            output_path=output_path if not v_result.blocked else None,
            output_hash=final_hash if not v_result.blocked else None,
            policy=self.policy,
            findings=final_findings,
            verified=v_result.verified_facts,
            assessed=v_result.assessed_judgments,
            status=status,
            include_plaintext=self.include_plaintext,
            gemma_model_name=self.gemma._active_model,
            runtime_name=self.gemma.runtime_mode,
        )

        if report_path:
            AuditReportGenerator.save_report(report, report_path)

        # If blocked by verifier on residual finding in strict mode, delete output file
        if v_result.blocked:
            if output_path.exists():
                output_path.unlink()
            return PipelineResult(
                success=False,
                exit_code=3,  # Exit code 3 for residual risk block
                sanitized_image=None,
                output_path=None,
                audit_report=report,
                findings=final_findings,
                stranger_before=stranger_before,
                stranger_after=v_result.assessed_judgments.stranger_test_after,
                review_required=review_required,
                blocked=True,
            )

        return PipelineResult(
            success=True,
            exit_code=0,
            sanitized_image=v_result.final_image,
            output_path=output_path,
            audit_report=report,
            findings=final_findings,
            stranger_before=stranger_before,
            stranger_after=v_result.assessed_judgments.stranger_test_after,
            review_required=review_required,
            blocked=False,
        )
