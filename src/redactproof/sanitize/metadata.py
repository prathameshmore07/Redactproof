from pathlib import Path
from typing import List
from PIL import Image

METADATA_MARKERS = [
    b"Exif\x00\x00",
    b"http://ns.adobe.com/xap/1.0/",
    b"tEXt",
    b"zTXt",
    b"iTXt",
    b"eXIf",
]

class MetadataSanitizer:
    """Detects and verifies complete absence of EXIF, IPTC, XMP, and PNG text chunks."""

    @staticmethod
    def inspect_metadata_in_file(file_path: Path) -> List[str]:
        found: List[str] = []
        raw = file_path.read_bytes()

        if b"Exif\x00\x00" in raw or b"eXIf" in raw:
            found.append("exif")
        if b"http://ns.adobe.com/xap/1.0/" in raw or b"<x:xmpmeta" in raw:
            found.append("xmp")
        if b"tEXt" in raw or b"zTXt" in raw or b"iTXt" in raw:
            found.append("png_text_chunks")
        if b"Photoshop 3.0" in raw or b"IPTC" in raw:
            found.append("iptc")

        try:
            with Image.open(file_path) as img:
                if img.info and any(k in img.info for k in ("exif", "icc_profile", "comment", "xml:com.adobe.xmp")):
                    if "exif" not in found:
                        found.append("exif")
        except Exception:
            pass

        return found
