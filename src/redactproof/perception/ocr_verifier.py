import io
import shutil
import subprocess
from typing import List
from PIL import Image, ImageEnhance, ImageOps

from ..schemas import TextItem, BoundingBox

try:
    import Vision
    from Foundation import NSData
    APPLE_VISION_AVAILABLE = True
except ImportError:
    APPLE_VISION_AVAILABLE = False


class VerifierOCR:
    """
    Independent Verifier OCR engine.
    Designed to avoid shared blind spots with the primary detector.
    Uses Tesseract CLI if available, or Apple Vision with alternative recognition mode
    and distinct preprocessed imagery (contrast-stretched, grayscale binarization).
    """

    def __init__(self):
        self.tesseract_cmd = shutil.which("tesseract")

    def extract_text(self, image: Image.Image) -> List[TextItem]:
        # Preprocess image for adversarial extraction (high contrast, edge clarity)
        enhanced = image.convert("L")
        enhancer = ImageEnhance.Contrast(enhanced)
        enhanced = enhancer.enhance(2.0)

        # If tesseract is installed in PATH, use it as held-out engine
        if self.tesseract_cmd:
            try:
                return self._extract_tesseract(enhanced)
            except Exception:
                pass

        # Fallback to alternative mode in Apple Vision (fast level, no language correction)
        # This uses an entirely separate neural model from accurate mode in Vision framework.
        return self._extract_apple_vision_verifier(enhanced)

    def _extract_tesseract(self, image: Image.Image) -> List[TextItem]:
        # Run tesseract with TSV output to obtain bounding boxes
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        proc = subprocess.run(
            [self.tesseract_cmd, "stdin", "stdout", "tsv"],
            input=buf.getvalue(),
            capture_output=True,
            check=True,
        )
        lines = proc.stdout.decode("utf-8", errors="ignore").splitlines()
        if len(lines) <= 1:
            return []

        text_items = []
        reg_id = 1
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 12:
                text = parts[11].strip()
                conf = float(parts[10])
                if text and conf > 0:
                    left = int(parts[6])
                    top = int(parts[7])
                    w = int(parts[8])
                    h = int(parts[9])
                    text_items.append(
                        TextItem(
                            region_id=reg_id,
                            text=text,
                            bbox=BoundingBox(x1=left, y1=top, x2=left + w, y2=top + h),
                            confidence=conf / 100.0,
                        )
                    )
                    reg_id += 1
        return text_items

    def _extract_apple_vision_verifier(self, image: Image.Image) -> List[TextItem]:
        if not APPLE_VISION_AVAILABLE:
            return []

        buf = io.BytesIO()
        image.save(buf, format="PNG")
        image_bytes = buf.getvalue()
        ns_data = NSData.dataWithBytes_length_(image_bytes, len(image_bytes))

        request = Vision.VNRecognizeTextRequest.alloc().init()
        # Fast recognition uses a distinct lightweight character-level model without language dictionary bias
        request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelFast)
        request.setUsesLanguageCorrection_(False)

        handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
        success, error = handler.performRequests_error_([request], None)
        if not success:
            return []

        results = request.results()
        text_items: List[TextItem] = []
        width, height = image.size

        if results:
            for idx, observation in enumerate(results):
                top_candidate = observation.topCandidates_(1)
                if not top_candidate:
                    continue
                cand = top_candidate[0]
                text = cand.string()
                confidence = float(cand.confidence())

                box = observation.boundingBox()
                x1 = int(round(box.origin.x * width))
                y1 = int(round((1.0 - box.origin.y - box.size.height) * height))
                x2 = int(round((box.origin.x + box.size.width) * width))
                y2 = int(round((1.0 - box.origin.y) * height))

                x1 = max(0, min(width - 1, x1))
                y1 = max(0, min(height - 1, y1))
                x2 = max(x1 + 1, min(width, x2))
                y2 = max(y1 + 1, min(height, y2))

                text_items.append(
                    TextItem(
                        region_id=idx + 1,
                        text=text,
                        bbox=BoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
                        confidence=confidence,
                    )
                )

        return text_items
