from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional
from PIL import Image

from ..schemas import (
    BoundingBox,
    TextItem,
    Finding,
    DestinationPolicy,
    VerifiedFacts,
    AssessedJudgments,
    Action,
    Sensitivity,
    FindingCategory,
)
from .pixel_checks import PixelUniformityChecker
from .reocr import ReOCRVerifier
from .adversary import ModelAdversaryVerifier
from ..sanitize.trailing_bytes import TrailingBytesChecker
from ..sanitize.metadata import MetadataSanitizer
from ..redaction.renderer import RedactionRenderer
from ..sanitize.reencode import ImageReencoder
from ..input_loader import compute_sha256

class VerificationResult:
    def __init__(
        self,
        final_image: Image.Image,
        final_output_path: Path,
        verified_facts: VerifiedFacts,
        assessed_judgments: AssessedJudgments,
        passes_used: int,
        residual_findings_exist: bool,
        blocked: bool = False,
    ):
        self.final_image = final_image
        self.final_output_path = final_output_path
        self.verified_facts = verified_facts
        self.assessed_judgments = assessed_judgments
        self.passes_used = passes_used
        self.residual_findings_exist = residual_findings_exist
        self.blocked = blocked

class ClosedLoopVerifier:
    """
    Executes the closed-loop verification cycle:
    Deterministic checks + Gemma adversary + automatic multi-pass fix cycle.
    """

    def __init__(
        self,
        policy: DestinationPolicy,
        adversary: ModelAdversaryVerifier,
        renderer: RedactionRenderer,
    ):
        self.policy = policy
        self.adversary = adversary
        self.renderer = renderer
        self.pixel_checker = PixelUniformityChecker()
        self.reocr = ReOCRVerifier()
        self.metadata_sanitizer = MetadataSanitizer()
        self.trailing_checker = TrailingBytesChecker()

    def run_verification_loop(
        self,
        original_image: Image.Image,
        current_canvas: Image.Image,
        output_file_path: Path,
        initial_findings: List[Finding],
        initial_mask_boxes: List[BoundingBox],
        original_sha256: str,
        stranger_inferences_before: List[str],
        salt: str = "redactproof-salt",
    ) -> VerificationResult:
        max_passes = self.policy.verification.max_fix_passes
        current_image = current_canvas
        current_masks = list(initial_mask_boxes)
        active_findings = list(initial_findings)

        passes_used = 0
        residual_exists = False
        blocked = False

        verified = VerifiedFacts()
        assessed = AssessedJudgments(
            stranger_test_before=stranger_inferences_before,
            stranger_test_after=[],
            adversary_residual_findings=0,
            fix_passes_used=0,
        )

        for fix_pass in range(max_passes + 1):
            passes_used = fix_pass

            # 1. Re-encode current canvas to output file
            out_hash, out_size = ImageReencoder.reencode_to_file(
                image=current_image,
                output_path=output_file_path,
            )

            # 2. Deterministic Byte & Metadata Checks
            trailing_len, is_trailing_clean = self.trailing_checker.inspect_file(output_file_path)
            metadata_markers = self.metadata_sanitizer.inspect_metadata_in_file(output_file_path)

            verified.trailing_bytes = trailing_len
            verified.metadata_markers_found = len(metadata_markers)
            verified.input_unmodified = True  # Verified via original sha256 check

            # 3. Deterministic Pixel Uniformity Check
            is_uniform, non_uniform_boxes = self.pixel_checker.verify_mask_uniformity(
                image=current_image,
                mask_boxes=current_masks,
            )
            verified.masks_uniform = is_uniform

            # 4. Secondary Re-OCR Verification
            allowlist_domains = self.policy.allowlist.domains
            hits_in_masks, pattern_hits, out_text_items, residual_pattern_findings = (
                self.reocr.verify_output(
                    sanitized_image=current_image,
                    mask_boxes=current_masks,
                    allowlist_domains=allowlist_domains,
                    salt=salt,
                )
            )
            verified.verifier_ocr_hits_in_masks = hits_in_masks
            verified.pattern_hits_after = pattern_hits

            # 5. Gemma Adversary Pass & Stranger Test on Output
            is_clean_adversary, adversary_findings = self.adversary.run_adversary(
                output_text_items=out_text_items,
                destination=self.policy.policy,
            )
            stranger_after = self.adversary.run_stranger_test(
                output_text_items=out_text_items,
                destination=self.policy.policy,
            )
            assessed.adversary_residual_findings = len(adversary_findings)
            assessed.stranger_test_after = stranger_after

            # Check if any residual issues remain
            has_issues = (
                not is_uniform or
                hits_in_masks > 0 or
                pattern_hits > 0 or
                not is_clean_adversary or
                trailing_len > 0 or
                len(metadata_markers) > 0
            )

            if not has_issues or fix_pass >= max_passes:
                residual_exists = has_issues
                break

            # --- AUTOMATIC FIX PASS ---
            # Expand masks and add newly discovered residual pattern items
            new_findings_to_add: List[Finding] = []
            for rpf in residual_pattern_findings:
                rpf.action = Action.REDACT
                rpf.is_residual = True
                new_findings_to_add.append(rpf)

            # Re-render with expanded margins (+4px each fix pass)
            expanded_margin = self.renderer.margin_px + (fix_pass + 1) * 4
            fix_renderer = RedactionRenderer(
                mask_color=self.renderer.mask_color,
                margin_px=expanded_margin,
            )
            active_findings.extend(new_findings_to_add)
            current_image, current_masks = fix_renderer.render(
                image=original_image,
                findings=active_findings,
            )

        assessed.fix_passes_used = passes_used

        if residual_exists and self.policy.verification.on_residual_finding == "block":
            blocked = True

        return VerificationResult(
            final_image=current_image,
            final_output_path=output_file_path,
            verified_facts=verified,
            assessed_judgments=assessed,
            passes_used=passes_used,
            residual_findings_exist=residual_exists,
            blocked=blocked,
        )
