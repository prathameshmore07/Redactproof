import hashlib
from pathlib import Path
from typing import Tuple
from PIL import Image
from .trailing_bytes import TrailingBytesChecker
from ..input_loader import compute_sha256

class ImageReencoder:
    """
    Re-encodes an image from raw pixel buffer into a freshly created container.
    Guarantees no original metadata or chunks carry over.
    """

    @staticmethod
    def reencode_to_file(
        image: Image.Image,
        output_path: Path,
        format_override: str = "PNG",
    ) -> Tuple[str, int]:
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Create brand-new canvas and copy pixels
        width, height = image.size
        mode = "RGBA" if "A" in image.mode else "RGB"
        fresh_canvas = Image.new(mode, (width, height))
        fresh_canvas.paste(image)

        # Save without any metadata or ICC profile
        fmt = format_override.upper()
        if fmt == "JPG":
            fmt = "JPEG"

        save_kwargs = {}
        if fmt == "PNG":
            save_kwargs["compress_level"] = 6
            save_kwargs["optimize"] = True
        elif fmt == "JPEG":
            save_kwargs["quality"] = 92
            save_kwargs["optimize"] = True

        # Save to fresh file
        fresh_canvas.save(output_path, format=fmt, **save_kwargs)

        # Enforce zero trailing bytes
        TrailingBytesChecker.strip_trailing_bytes(output_path)

        out_hash = compute_sha256(output_path)
        out_size = output_path.stat().st_size
        return out_hash, out_size
