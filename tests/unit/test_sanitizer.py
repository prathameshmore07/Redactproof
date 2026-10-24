import tempfile
from pathlib import Path
from PIL import Image, PngImagePlugin
from redactproof.sanitize.trailing_bytes import TrailingBytesChecker, PNG_IEND_CHUNK
from redactproof.sanitize.metadata import MetadataSanitizer
from redactproof.sanitize.reencode import ImageReencoder

def test_trailing_bytes_detection_and_stripping():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = Path(tmpdir) / "test_trailing.png"
        img = Image.new("RGB", (50, 50), color="blue")
        img.save(tmp_file, format="PNG")

        # Intentionally append malicious trailing bytes (aCropalypse style)
        clean_bytes = tmp_file.read_bytes()
        evil_trailing = b"\xde\xad\xbe\xefHIDDEN_LEAKED_DATA"
        tmp_file.write_bytes(clean_bytes + evil_trailing)

        # Inspect
        trailing_len, is_clean = TrailingBytesChecker.inspect_file(tmp_file)
        assert trailing_len == len(evil_trailing)
        assert is_clean is False

        # Strip
        stripped = TrailingBytesChecker.strip_trailing_bytes(tmp_file)
        assert stripped == len(evil_trailing)

        # Verify clean
        trailing_len_after, is_clean_after = TrailingBytesChecker.inspect_file(tmp_file)
        assert trailing_len_after == 0
        assert is_clean_after is True

def test_metadata_stripping_via_reencoder():
    with tempfile.TemporaryDirectory() as tmpdir:
        input_file = Path(tmpdir) / "with_metadata.png"
        output_file = Path(tmpdir) / "clean_reencoded.png"

        # Create image with text metadata chunk
        info = PngImagePlugin.PngInfo()
        info.add_text("Author", "Secret Employee")
        info.add_text("InternalProject", "TopSecretX")

        img = Image.new("RGB", (60, 60), color="red")
        img.save(input_file, format="PNG", pnginfo=info)

        # Confirm metadata exists in raw input file
        raw_in = input_file.read_bytes()
        assert b"TopSecretX" in raw_in

        # Re-encode
        out_hash, out_size = ImageReencoder.reencode_to_file(img, output_file)

        # Confirm metadata was completely stripped from output file
        raw_out = output_file.read_bytes()
        assert b"TopSecretX" not in raw_out
        assert b"Secret Employee" not in raw_out
        assert len(MetadataSanitizer.inspect_metadata_in_file(output_file)) == 0
