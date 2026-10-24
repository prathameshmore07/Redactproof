import io
from typing import List
from PIL import Image

from ..schemas import Finding, FindingCategory, BoundingBox, Action, Sensitivity

try:
    import Vision
    from Foundation import NSData
    APPLE_VISION_AVAILABLE = True
except ImportError:
    APPLE_VISION_AVAILABLE = False


class AppleVisionBarcodeDetector:
    """Detects QR codes and barcodes using Apple Vision framework."""

    def is_available(self) -> bool:
        return APPLE_VISION_AVAILABLE

    def detect_codes(self, image: Image.Image, start_region_id: int = 2000) -> List[Finding]:
        if not APPLE_VISION_AVAILABLE:
            return []

        buf = io.BytesIO()
        image.save(buf, format="PNG")
        image_bytes = buf.getvalue()
        ns_data = NSData.dataWithBytes_length_(image_bytes, len(image_bytes))

        request = Vision.VNDetectBarcodesRequest.alloc().init()
        handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(ns_data, None)
        success, error = handler.performRequests_error_([request], None)
        if not success:
            return []

        results = request.results()
        findings: List[Finding] = []
        width, height = image.size

        if results:
            for idx, observation in enumerate(results):
                box = observation.boundingBox()
                confidence = float(observation.confidence())
                payload = observation.payloadStringValue() or "code"

                x1 = int(round(box.origin.x * width))
                y1 = int(round((1.0 - box.origin.y - box.size.height) * height))
                x2 = int(round((box.origin.x + box.size.width) * width))
                y2 = int(round((1.0 - box.origin.y) * height))

                x1 = max(0, min(width - 1, x1))
                y1 = max(0, min(height - 1, y1))
                x2 = max(x1 + 1, min(width, x2))
                y2 = max(y1 + 1, min(height, y2))

                findings.append(
                    Finding(
                        region_id=start_region_id + idx,
                        bbox=BoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
                        category=FindingCategory.QR_OR_BARCODE,
                        detector="apple_vision_barcodes",
                        confidence=confidence,
                        action=Action.REDACT,
                        text_length=len(payload),
                        rationale=f"Detected QR code or barcode ({observation.symbology()})",
                        sensitivity=Sensitivity.HIGH,
                    )
                )

        return findings
