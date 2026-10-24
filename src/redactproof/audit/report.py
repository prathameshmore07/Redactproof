import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from ..schemas import (
    AuditReport,
    Finding,
    DestinationPolicy,
    VerifiedFacts,
    AssessedJudgments,
    Action,
)
from ..config import settings
from ..input_loader import compute_sha256

class AuditReportGenerator:
    """Generates an honest, structured audit report adhering to Section 12 specifications."""

    @staticmethod
    def generate_report(
        input_path: Path,
        input_hash: str,
        output_path: Optional[Path],
        output_hash: Optional[str],
        policy: DestinationPolicy,
        findings: List[Finding],
        verified: VerifiedFacts,
        assessed: AssessedJudgments,
        status: str = "sanitized_verified_with_residual_model_risk",
        include_plaintext: bool = False,
        primary_ocr_name: str = "apple_vision_accurate",
        verifier_ocr_name: str = "apple_vision_fast_contrast_binarized",
        gemma_model_name: str = "gemma-4-e2b",
        runtime_name: str = "ollama",
    ) -> AuditReport:
        # Tally transformations
        redacted_count = sum(1 for f in findings if f.action == Action.REDACT)
        pseudo_count = sum(1 for f in findings if f.action == Action.PSEUDONYMIZE)
        kept_count = sum(1 for f in findings if f.action == Action.KEEP)
        review_count = sum(1 for f in findings if f.action == Action.REVIEW)

        findings_report = []
        for f in findings:
            record: Dict[str, Any] = {
                "region_id": f.region_id,
                "bbox": [f.bbox.x1, f.bbox.y1, f.bbox.x2, f.bbox.y2],
                "category": f.category.value,
                "detector": f.detector,
                "confidence": round(f.confidence, 3),
                "action": f.action.value,
                "text_length": f.text_length,
                "text_salted_sha256": f.text_salted_sha256,
                "rationale": f.rationale,
            }
            if include_plaintext and f.plaintext:
                record["plaintext"] = f.plaintext
            findings_report.append(record)

        report = AuditReport(
            tool=settings.tool_name,
            version=settings.version,
            status=status,
            input={
                "file": str(input_path.name),
                "sha256": input_hash,
            },
            output={
                "file": str(output_path.name) if output_path else None,
                "sha256": output_hash,
                "reencoded": True,
            } if output_path else None,
            policy={
                "name": policy.policy,
                "version": policy.version,
                "source": policy.source,
                "sha256": policy.sha256,
            },
            models={
                "ocr_primary": primary_ocr_name,
                "ocr_verifier": verifier_ocr_name,
                "gemma": gemma_model_name,
                "runtime": runtime_name,
            },
            findings=findings_report,
            transformations={
                "regions_redacted": redacted_count,
                "regions_pseudonymized": pseudo_count,
                "regions_kept": kept_count,
                "regions_sent_to_review": review_count,
                "metadata_removed": ["exif", "iptc", "xmp", "png_text_chunks"],
            },
            verified=verified,
            assessed=assessed,
        )
        return report

    @staticmethod
    def save_report(report: AuditReport, target_path: Path):
        target_path = Path(target_path).resolve()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)
