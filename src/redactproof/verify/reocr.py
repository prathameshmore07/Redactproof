from typing import List, Tuple
from PIL import Image
from ..schemas import BoundingBox, TextItem, Finding
from ..perception.ocr_verifier import VerifierOCR
from ..detectors import CompositeDetector

class ReOCRVerifier:
    """
    Runs secondary OCR on sanitized output to ensure no text survives inside masks,
    and no deterministic pattern hits remain across the image.
    """

    def __init__(self):
        self.verifier_ocr = VerifierOCR()
        self.detector = CompositeDetector()

    def verify_output(
        self,
        sanitized_image: Image.Image,
        mask_boxes: List[BoundingBox],
        allowlist_domains: List[str],
        salt: str = "redactproof-salt",
    ) -> Tuple[int, int, List[TextItem], List[Finding]]:
        # 1. Secondary OCR pass
        items = self.verifier_ocr.extract_text(sanitized_image)

        # 2. Check for text inside masked boxes
        hits_in_masks = 0
        for item in items:
            for m_box in mask_boxes:
                if item.bbox.intersects(m_box):
                    hits_in_masks += 1
                    break

        # 3. Check for deterministic pattern hits anywhere in output image
        pattern_findings = self.detector.detect_all(
            items=items,
            allowlist_domains=allowlist_domains,
            salt=salt,
        )
        # Exclude KEEP actions
        critical_pattern_hits = [f for f in pattern_findings if f.action.value in ("redact", "review")]

        return hits_in_masks, len(critical_pattern_hits), items, critical_pattern_hits
