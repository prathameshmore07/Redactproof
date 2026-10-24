import hashlib
from pathlib import Path
from typing import Tuple, Dict, Any
from PIL import Image

class InputValidationError(Exception):
    """Raised when an input file is invalid, corrupt, or exceeds safe limits."""
    pass

class LoadedImage:
    def __init__(self, path: Path, image: Image.Image, file_hash: str, raw_bytes_len: int):
        self.path = path
        self.image = image
        self.file_hash = file_hash
        self.raw_bytes_len = raw_bytes_len
        self.width, self.height = image.size

def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def load_and_validate_image(
    input_path: str | Path,
    max_file_size_bytes: int = 50 * 1024 * 1024,
    max_dimension: int = 10000,
) -> LoadedImage:
    path = Path(input_path).resolve()
    if not path.exists():
        raise InputValidationError(f"File does not exist: {path}")
    if not path.is_file():
        raise InputValidationError(f"Path is not a regular file: {path}")

    size_bytes = path.stat().st_size
    if size_bytes == 0:
        raise InputValidationError(f"File is empty (0 bytes): {path}")
    if size_bytes > max_file_size_bytes:
        raise InputValidationError(f"File size {size_bytes} exceeds limit of {max_file_size_bytes} bytes")

    file_hash = compute_sha256(path)

    # Defend against decompression bombs
    Image.MAX_IMAGE_PIXELS = 100_000_000

    try:
        with Image.open(path) as img:
            img.verify()
    except Exception as e:
        raise InputValidationError(f"Image verification failed or corrupted file: {e}")

    try:
        img = Image.open(path)
        img.load()  # Ensure entire pixel buffer is loaded into memory
    except Exception as e:
        raise InputValidationError(f"Failed to decode image pixels: {e}")

    if img.width > max_dimension or img.height > max_dimension:
        raise InputValidationError(
            f"Image dimensions ({img.width}x{img.height}) exceed maximum allowed dimension ({max_dimension}px)"
        )

    # Convert to RGB or RGBA standard format
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode or img.mode == "P" else "RGB")

    return LoadedImage(
        path=path,
        image=img,
        file_hash=file_hash,
        raw_bytes_len=size_bytes,
    )
