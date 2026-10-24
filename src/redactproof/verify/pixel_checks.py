from typing import List, Tuple
import numpy as np
from PIL import Image
from ..schemas import BoundingBox

class PixelUniformityChecker:
    """
    Deterministically verifies that every masked rectangle in the output
    has uniform color with zero pixel variance (no blur, no alpha blending, no leakage).
    """

    @staticmethod
    def verify_mask_uniformity(
        image: Image.Image,
        mask_boxes: List[BoundingBox],
        max_allowed_std_dev: float = 1.0,  # Strict threshold (allows slight JPEG DCT rounding)
    ) -> Tuple[bool, List[BoundingBox]]:
        if not mask_boxes:
            return True, []

        img_np = np.array(image.convert("RGB"))
        non_uniform_boxes: List[BoundingBox] = []

        for box in mask_boxes:
            # Crop region in numpy array: [y1:y2, x1:x2]
            crop = img_np[box.y1:box.y2, box.x1:box.x2]
            if crop.size == 0:
                continue

            # Standard deviation across RGB channels
            std_dev = float(np.std(crop))
            if std_dev > max_allowed_std_dev:
                non_uniform_boxes.append(box)

        is_uniform = len(non_uniform_boxes) == 0
        return is_uniform, non_uniform_boxes
