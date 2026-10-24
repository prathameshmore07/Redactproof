import io
from pathlib import Path
from typing import List
from PIL import Image

from ..schemas import TextItem, BoundingBox

try:
    import Vision
    import objc
    from Foundation import NSData, NSURL
    APPLE_VISION_AVAILABLE = True
except ImportError:
    APPLE_VISION_AVAILABLE = False


class AppleVisionOCR:
    """Primary OCR detector using Apple Vision on macOS."""

    def __init__(self, recognition_level: str = "accurate"):
        self.recognition_level = recognition_level

    def is_available(self) -> bool:
        return APPLE_VISION_AVAILABLE

    def extract_text(self, image: Image.Image) -> List[TextItem]:
        if not APPLE_VISION_AVAILABLE:
            raise RuntimeError(
                "Apple Vision PyObjC framework is not available. Please install on macOS."
            )

        # Convert PIL image to PNG in memory
        buf = io.BytesIO()
        image.save(buf, format="PNG")
        image_bytes = buf.getvalue()
        ns_data = NSData.dataWithBytes_length_(image_bytes, len(image_bytes))

        # Setup Vision request
        request = Vision.VNRecognizeTextRequest.alloc().init()
        if self.recognition_level == "fast":
            request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelFast)
        else:
            request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)

        request.setUsesLanguageCorrection_(True)

        handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
        success, error = handler.performRequests_error_([request], None)
        if not success:
            raise RuntimeError(f"Apple Vision text recognition failed: {error}")

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

                # Normalized bounding box in Vision: (0,0) is bottom-left
                box = observation.boundingBox()
                # Convert to top-left pixel coordinates:
                x1 = int(round(box.origin.x * width))
                y1 = int(round((1.0 - box.origin.y - box.size.height) * height))
                x2 = int(round((box.origin.x + box.size.width) * width))
                y2 = int(round((1.0 - box.origin.y) * height))

                # Clamp coordinates
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
