from PIL import Image
from redactproof.schemas import BoundingBox, Finding, Action, FindingCategory
from redactproof.redaction.renderer import expand_and_merge_boxes, RedactionRenderer
from redactproof.verify.pixel_checks import PixelUniformityChecker

def test_expand_and_merge_boxes():
    boxes = [
        BoundingBox(x1=10, y1=10, x2=50, y2=25),
        BoundingBox(x1=52, y1=10, x2=90, y2=25),  # Adjacent box on same line
    ]
    # With margin of 4, boxes overlap and must merge
    merged = expand_and_merge_boxes(boxes, margin=4, image_width=200, image_height=200)
    assert len(merged) == 1
    assert merged[0].x1 == 6
    assert merged[0].x2 == 94

def test_renderer_creates_uniform_masks():
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    findings = [
        Finding(
            region_id=1,
            bbox=BoundingBox(x1=20, y1=20, x2=100, y2=40),
            category=FindingCategory.CREDENTIAL,
            detector="test",
            action=Action.REDACT,
        )
    ]
    renderer = RedactionRenderer(mask_color=(15, 15, 15), margin_px=4)
    canvas, masks = renderer.render(img, findings)

    # Verify that masked region is 100% uniform color
    is_uniform, non_uniform = PixelUniformityChecker.verify_mask_uniformity(canvas, masks)
    assert is_uniform is True
    assert len(non_uniform) == 0
