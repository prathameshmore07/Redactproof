from typing import List, Tuple, Optional
from PIL import Image, ImageDraw, ImageFont
from ..schemas import BoundingBox, Finding, Action
from .pseudonyms import PseudonymGenerator

def expand_and_merge_boxes(
    boxes: List[BoundingBox],
    margin: int,
    image_width: int,
    image_height: int,
) -> List[BoundingBox]:
    if not boxes:
        return []

    # 1. Expand with margin and clamp
    expanded = []
    for b in boxes:
        expanded.append(
            BoundingBox(
                x1=max(0, b.x1 - margin),
                y1=max(0, b.y1 - margin),
                x2=min(image_width, b.x2 + margin),
                y2=min(image_height, b.y2 + margin),
            )
        )

    # 2. Iteratively merge overlapping or nearly touching boxes on the same line
    merged: List[BoundingBox] = []
    expanded.sort(key=lambda b: (b.y1, b.x1))

    for box in expanded:
        if not merged:
            merged.append(box)
            continue

        last = merged[-1]
        # If boxes intersect or are separated by less than margin*2
        if box.intersects(last) or (abs(box.y1 - last.y1) <= margin * 2 and box.x1 <= last.x2 + margin * 2):
            merged[-1] = last.union(box)
        else:
            merged.append(box)

    return merged

class RedactionRenderer:
    """
    Renders solid opaque masks and fresh pseudonyms directly into the pixel buffer.
    Never uses transparency, layers, or annotations.
    """

    def __init__(self, mask_color: Tuple[int, int, int] = (15, 15, 15), margin_px: int = 4):
        self.mask_color = mask_color
        self.margin_px = margin_px
        self.pseudonym_gen = PseudonymGenerator()

    def render(
        self,
        image: Image.Image,
        findings: List[Finding],
    ) -> Tuple[Image.Image, List[BoundingBox]]:
        canvas = image.copy()
        if canvas.mode not in ("RGB", "RGBA"):
            canvas = canvas.convert("RGB")

        draw = ImageDraw.Draw(canvas)
        width, height = canvas.size

        # Filter findings to redact or pseudonymize
        redact_findings = [f for f in findings if f.action == Action.REDACT]
        pseudo_findings = [f for f in findings if f.action == Action.PSEUDONYMIZE]

        # Expand and merge redaction boxes
        redact_boxes = [f.bbox for f in redact_findings]
        merged_redact_boxes = expand_and_merge_boxes(redact_boxes, self.margin_px, width, height)

        # 1. Draw solid opaque masks for redact actions
        for box in merged_redact_boxes:
            draw.rectangle(
                [(box.x1, box.y1), (box.x2, box.y2)],
                fill=self.mask_color,
                outline=None,
            )

        # 2. Draw pseudonyms: cover with solid background first, then draw synthetic text
        rendered_pseudo_boxes = []
        for pf in pseudo_findings:
            box = pf.bbox
            exp_box = BoundingBox(
                x1=max(0, box.x1 - self.margin_px),
                y1=max(0, box.y1 - self.margin_px),
                x2=min(width, box.x2 + self.margin_px),
                y2=min(height, box.y2 + self.margin_px),
            )
            # Cover original text fully first
            draw.rectangle(
                [(exp_box.x1, exp_box.y1), (exp_box.x2, exp_box.y2)],
                fill=(30, 41, 59),  # Clean slate blue-gray background
                outline=None,
            )
            pseudo_text = self.pseudonym_gen.get_pseudonym(pf.category, str(pf.region_id))
            pf.pseudonym_label = pseudo_text

            # Render text in crisp white
            draw.text(
                (exp_box.x1 + 2, exp_box.y1 + 1),
                pseudo_text,
                fill=(241, 245, 249),
            )
            rendered_pseudo_boxes.append(exp_box)

        all_rendered_masks = merged_redact_boxes + rendered_pseudo_boxes
        return canvas, all_rendered_masks
