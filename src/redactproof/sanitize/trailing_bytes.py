from pathlib import Path
from typing import Tuple

PNG_IEND_CHUNK = b"IEND\xaeB`\x82"
JPEG_EOI_MARKER = b"\xff\xd9"

class TrailingBytesChecker:
    """Detects and strips bytes appended after the official end-of-image marker."""

    @staticmethod
    def inspect_file(file_path: Path) -> Tuple[int, bool]:
        data = file_path.read_bytes()
        trailing_count = 0

        # Check PNG
        iend_pos = data.rfind(PNG_IEND_CHUNK)
        if iend_pos != -1:
            end_expected = iend_pos + len(PNG_IEND_CHUNK)
            if len(data) > end_expected:
                trailing_count = len(data) - end_expected
                return trailing_count, False
            return 0, True

        # Check JPEG
        eoi_pos = data.rfind(JPEG_EOI_MARKER)
        if eoi_pos != -1:
            end_expected = eoi_pos + len(JPEG_EOI_MARKER)
            if len(data) > end_expected:
                trailing_count = len(data) - end_expected
                return trailing_count, False
            return 0, True

        return 0, True

    @staticmethod
    def strip_trailing_bytes(file_path: Path) -> int:
        data = file_path.read_bytes()
        iend_pos = data.rfind(PNG_IEND_CHUNK)
        if iend_pos != -1:
            end_expected = iend_pos + len(PNG_IEND_CHUNK)
            if len(data) > end_expected:
                stripped = len(data) - end_expected
                file_path.write_bytes(data[:end_expected])
                return stripped

        eoi_pos = data.rfind(JPEG_EOI_MARKER)
        if eoi_pos != -1:
            end_expected = eoi_pos + len(JPEG_EOI_MARKER)
            if len(data) > end_expected:
                stripped = len(data) - end_expected
                file_path.write_bytes(data[:end_expected])
                return stripped

        return 0
