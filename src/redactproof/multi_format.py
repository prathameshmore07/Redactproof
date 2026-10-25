import io
import re
import hashlib
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional, Union
from PIL import Image, ImageDraw, ImageFont

from .schemas import BoundingBox, TextItem, Finding, FindingCategory, Action, Sensitivity
from .input_loader import InputValidationError, compute_sha256

# PDF support via PyMuPDF or fallback pypdf
try:
    import pymupdf  # PyMuPDF
    PYMUPDF_AVAILABLE = True
except ImportError:
    try:
        import fitz as pymupdf
        PYMUPDF_AVAILABLE = True
    except ImportError:
        PYMUPDF_AVAILABLE = False


class DocumentPage:
    """Represents a single page or view of an input document."""
    def __init__(
        self,
        page_number: int,
        image: Image.Image,
        text: Optional[str] = None,
        precomputed_text_items: Optional[List[TextItem]] = None,
    ):
        self.page_number = page_number
        self.image = image
        self.text = text or ""
        self.precomputed_text_items = precomputed_text_items or []
        self.width, self.height = image.size


class ProcessedDocument:
    """Represents a loaded multi-format document (PDF, Image, or Text)."""
    def __init__(
        self,
        doc_type: str,  # "image", "pdf", "text"
        filename: str,
        pages: List[DocumentPage],
        raw_bytes: bytes,
        file_hash: str,
        original_text: Optional[str] = None,
    ):
        self.doc_type = doc_type
        self.filename = filename
        self.pages = pages
        self.raw_bytes = raw_bytes
        self.file_hash = file_hash
        self.original_text = original_text
        self.total_pages = len(pages)


def render_text_to_image(
    text: str,
    width: int = 1200,
    bg_color: Tuple[int, int, int] = (15, 23, 42),
    text_color: Tuple[int, int, int] = (226, 232, 240),
    line_number_color: Tuple[int, int, int] = (100, 116, 139),
    font_size: int = 16,
    max_visual_lines: int = 350,
) -> Tuple[Image.Image, List[TextItem]]:
    """
    Renders plain text or code into a high-resolution dark-themed document image canvas,
    calculating precise bounding boxes for every line and word token.
    Caps visual canvas to max_visual_lines to guarantee safe memory bounds.
    """
    all_lines = text.splitlines() or [""]
    display_lines = all_lines[:max_visual_lines]
    has_more = len(all_lines) > max_visual_lines

    line_height = int(font_size * 1.6)
    left_margin = 80
    top_margin = 50
    bottom_margin = 60 if has_more else 50
    total_height = max(600, min(8000, top_margin + len(display_lines) * line_height + bottom_margin))

    # Use default PIL font or load a monospaced font
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None

    image = Image.new("RGB", (width, total_height), bg_color)
    draw = ImageDraw.Draw(image)

    text_items: List[TextItem] = []
    region_id = 1

    # Draw header bar
    draw.rectangle([(0, 0), (width, 36)], fill=(30, 41, 59))
    draw.ellipse([(16, 12), (24, 20)], fill=(239, 68, 68))
    draw.ellipse([(32, 12), (40, 20)], fill=(234, 179, 8))
    draw.ellipse([(48, 12), (56, 20)], fill=(34, 197, 94))
    draw.text((70, 10), "Redactproof Text & Code Viewer", fill=(148, 163, 184), font=font)

    # Draw vertical separator for line numbers
    draw.line([(left_margin - 16, 36), (left_margin - 16, total_height)], fill=(51, 65, 85), width=1)

    char_approx_width = max(7, int(font_size * 0.55))

    for idx, line in enumerate(display_lines):
        line_num = idx + 1
        y = top_margin + idx * line_height

        # Draw line number
        draw.text((16, y), f"{line_num:3d}", fill=line_number_color, font=font)

        if not line:
            continue

        # Draw line text
        draw.text((left_margin, y), line, fill=text_color, font=font)

        # Break line into words to generate distinct TextItems
        pos = 0
        for match in re.finditer(r"\S+", line):
            word = match.group(0)
            start_col = match.start()
            end_col = match.end()

            w_x1 = left_margin + start_col * char_approx_width
            w_x2 = min(width - 10, left_margin + end_col * char_approx_width)
            w_y1 = y
            w_y2 = y + line_height

            text_items.append(
                TextItem(
                    region_id=region_id,
                    text=word,
                    bbox=BoundingBox(x1=w_x1, y1=w_y1, x2=w_x2, y2=w_y2),
                    confidence=1.0,
                )
            )
            region_id += 1

    if has_more:
        remaining = len(all_lines) - max_visual_lines
        footer_y = top_margin + len(display_lines) * line_height + 15
        draw.text(
            (left_margin, footer_y),
            f"... [{remaining} additional lines omitted from visual canvas preview; 100% of text is sanitized on export]",
            fill=(148, 163, 184),
            font=font,
        )

    return image, text_items


def load_any_document(
    file_bytes: bytes,
    filename: str,
    max_pages: int = 50,
    dpi: int = 150,
) -> ProcessedDocument:
    """
    Universally loads and validates any input document:
    - Images: PNG, JPG, JPEG, WEBP, BMP, TIFF
    - PDFs: Multi-page rendering to images using PyMuPDF
    - Text/Code/Logs: Rendered to high-resolution visual canvas + parsed text
    """
    if not file_bytes:
        raise InputValidationError("Uploaded file is empty (0 bytes).")

    file_hash = hashlib.sha256(file_bytes).hexdigest()
    suffix = Path(filename).suffix.lower()

    # 1. PDF Document
    if suffix == ".pdf" or file_bytes.startswith(b"%PDF-"):
        if not PYMUPDF_AVAILABLE:
            raise InputValidationError(
                "PDF processing requires PyMuPDF. Please install pymupdf in your Python environment."
            )

        try:
            doc = pymupdf.open(stream=file_bytes, filetype="pdf")
        except Exception as e:
            raise InputValidationError(f"Could not parse PDF document: {e}")

        if doc.is_encrypted:
            raise InputValidationError("Password-protected PDFs are not supported. Please decrypt before uploading.")

        total_pdf_pages = len(doc)
        if total_pdf_pages == 0:
            raise InputValidationError("PDF contains 0 pages.")

        pages_to_load = min(total_pdf_pages, max_pages)
        pages: List[DocumentPage] = []

        # Zoom matrix for high-quality rendering (150 DPI)
        zoom = dpi / 72.0
        mat = pymupdf.Matrix(zoom, zoom)

        for i in range(pages_to_load):
            page = doc.load_page(i)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
            page_text = page.get_text()
            pages.append(DocumentPage(page_number=i + 1, image=img, text=page_text))

        doc.close()
        return ProcessedDocument(
            doc_type="pdf",
            filename=filename,
            pages=pages,
            raw_bytes=file_bytes,
            file_hash=file_hash,
        )

    # 2. Text / Code / Log files
    text_extensions = {
        ".txt", ".log", ".csv", ".json", ".py", ".env", ".md", ".yaml",
        ".yml", ".xml", ".ini", ".cfg", ".sh", ".bash", ".zsh", ".js",
        ".ts", ".jsx", ".tsx", ".html", ".css", ".sql", ".conf"
    }
    is_text = suffix in text_extensions
    if not is_text:
        # Check if the bytes look like UTF-8 plain text without null bytes
        if b"\x00" not in file_bytes[:2048]:
            try:
                decoded_sample = file_bytes.decode("utf-8")
                # If printable ratio is high, treat as text
                printable_count = sum(1 for c in decoded_sample if c.isprintable() or c in "\r\n\t")
                if len(decoded_sample) > 0 and (printable_count / len(decoded_sample)) > 0.95:
                    is_text = True
            except UnicodeDecodeError:
                is_text = False

    if is_text:
        try:
            text_content = file_bytes.decode("utf-8", errors="replace")
        except Exception as e:
            raise InputValidationError(f"Could not decode text file: {e}")

        rendered_img, text_items = render_text_to_image(text_content)
        pages = [
            DocumentPage(
                page_number=1,
                image=rendered_img,
                text=text_content,
                precomputed_text_items=text_items,
            )
        ]
        return ProcessedDocument(
            doc_type="text",
            filename=filename,
            pages=pages,
            raw_bytes=file_bytes,
            file_hash=file_hash,
            original_text=text_content,
        )

    # 3. Image (Default)
    try:
        buf = io.BytesIO(file_bytes)
        img = Image.open(buf)
        img.load()
    except Exception as e:
        raise InputValidationError(f"Unsupported or corrupted image file format: {e}")

    # Defend against decompression bombs
    Image.MAX_IMAGE_PIXELS = 100_000_000

    max_dim = 10000
    if img.width > max_dim or img.height > max_dim:
        raise InputValidationError(
            f"Image dimensions ({img.width}x{img.height}) exceed safety limit of {max_dim}px."
        )

    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA" if "A" in img.mode or img.mode == "P" else "RGB")

    pages = [DocumentPage(page_number=1, image=img, text="")]
    return ProcessedDocument(
        doc_type="image",
        filename=filename,
        pages=pages,
        raw_bytes=file_bytes,
        file_hash=file_hash,
    )


def export_sanitized_pdf(sanitized_images: List[Image.Image]) -> bytes:
    """Combines a list of sanitized PIL Images into a multi-page PDF."""
    if not sanitized_images:
        raise ValueError("No sanitized images provided to create PDF.")

    rgb_images = []
    for img in sanitized_images:
        if img.mode == "RGB":
            rgb_images.append(img)
        else:
            # Composite onto white background to avoid black background artifacts on transparent PNGs
            bg = Image.new("RGB", img.size, (255, 255, 255))
            if img.mode in ("RGBA", "LA") or (img.mode == "P" and "transparency" in img.info):
                bg.paste(img, mask=img.convert("RGBA").split()[3])
            else:
                bg.paste(img.convert("RGB"))
            rgb_images.append(bg)

    buf = io.BytesIO()
    rgb_images[0].save(
        buf,
        format="PDF",
        save_all=True,
        append_images=rgb_images[1:] if len(rgb_images) > 1 else [],
        resolution=150.0,
    )
    return buf.getvalue()
