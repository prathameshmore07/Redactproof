import io
import base64
from typing import List, Dict, Any, Optional
from PIL import Image
import streamlit.components.v1 as components

from ..schemas import Finding


def image_to_base64_uri(image: Image.Image, format: str = "PNG") -> str:
    """Converts a PIL Image to a base64 Data URI."""
    buffered = io.BytesIO()
    # Ensure RGB for JPEG or standard PNG
    if format.upper() == "JPEG" and image.mode != "RGB":
        image = image.convert("RGB")
    image.save(buffered, format=format)
    img_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")
    mime = "image/png" if format.upper() == "PNG" else "image/jpeg"
    return f"data:{mime};base64,{img_b64}"


import html

def render_before_after_slider(
    original_img: Image.Image,
    sanitized_img: Image.Image,
    findings: Optional[List[Finding]] = None,
    height_px: int = 650,
    slider_id: str = "redactproof-slider",
) -> None:
    """
    Renders an interactive before/after image reveal slider with glowing neon split-bar,
    touch/mouse draggable divider, crossfade animation toggle, and bounding box inspection.
    """
    # Downscale copy for visual display if massive image to protect browser performance
    max_display_dim = 2000
    disp_orig = original_img
    disp_san = sanitized_img
    if original_img.width > max_display_dim or original_img.height > max_display_dim:
        scale = max_display_dim / max(original_img.width, original_img.height)
        new_w, new_h = max(1, int(original_img.width * scale)), max(1, int(original_img.height * scale))
        disp_orig = original_img.resize((new_w, new_h), Image.Resampling.LANCZOS)
        disp_san = sanitized_img.resize((new_w, new_h), Image.Resampling.LANCZOS)

    orig_b64 = image_to_base64_uri(disp_orig)
    sanitized_b64 = image_to_base64_uri(disp_san)

    # Serialize findings for SVG overlay
    overlay_rects = []
    w, h = max(1, original_img.width), max(1, original_img.height)
    if findings:
        for f in findings:
            if f.action.value in ("redact", "pseudonymize"):
                rect_x = (f.bbox.x1 / w) * 100
                rect_y = (f.bbox.y1 / h) * 100
                rect_w = max(0.5, ((f.bbox.x2 - f.bbox.x1) / w) * 100)
                rect_h = max(0.5, ((f.bbox.y2 - f.bbox.y1) / h) * 100)
                cat = html.escape(str(f.category.value))
                det = html.escape(str(f.detector))
                raw_label = f.plaintext or f.rationale or cat
                label = html.escape(str(raw_label)[:40])
                overlay_rects.append({
                    "x": rect_x,
                    "y": rect_y,
                    "w": rect_w,
                    "h": rect_h,
                    "cat": cat,
                    "det": det,
                    "label": label,
                })

    html_code = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8"/>
    <style>
      * {{
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        user-select: none;
      }}
      body {{
        background: transparent;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
        display: flex;
        flex-direction: column;
        align-items: center;
        overflow: hidden;
      }}
      .comparison-wrapper {{
        position: relative;
        width: 100%;
        max-width: 100%;
        height: {height_px - 70}px;
        border-radius: 14px;
        overflow: hidden;
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.7), 0 0 1px 1px rgba(255, 255, 255, 0.1);
        background: #090d16;
        cursor: col-resize;
      }}
      .img-layer {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        object-fit: contain;
        pointer-events: none;
      }}
      .layer-before {{
        z-index: 1;
      }}
      .layer-after {{
        z-index: 2;
        width: 100%;
        clip-path: polygon(50% 0, 100% 0, 100% 100%, 50% 100%);
        transition: none;
      }}
      .animated-crossfade .layer-after {{
        clip-path: none !important;
        animation: crossfadePulse 4s ease-in-out infinite alternate !important;
      }}
      @keyframes crossfadePulse {{
        0% {{ opacity: 0; }}
        20% {{ opacity: 0; }}
        80% {{ opacity: 1; }}
        100% {{ opacity: 1; }}
      }}
      /* Divider Bar */
      .divider-line {{
        position: absolute;
        top: 0;
        bottom: 0;
        left: 50%;
        width: 3px;
        background: linear-gradient(180deg, #06b6d4 0%, #6366f1 50%, #ec4899 100%);
        box-shadow: 0 0 12px #06b6d4, 0 0 20px #6366f1;
        z-index: 10;
        transform: translateX(-50%);
        pointer-events: none;
        transition: opacity 0.2s ease;
      }}
      .divider-handle {{
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 44px;
        height: 44px;
        border-radius: 50%;
        background: #0f172a;
        border: 2px solid #06b6d4;
        box-shadow: 0 0 15px rgba(6, 182, 212, 0.6), inset 0 0 8px rgba(99, 102, 241, 0.5);
        display: flex;
        align-items: center;
        justify-content: center;
        color: #ffffff;
        font-size: 14px;
        font-weight: bold;
        z-index: 11;
        cursor: grab;
      }}
      .divider-handle:active {{
        cursor: grabbing;
        transform: translate(-50%, -50%) scale(1.1);
      }}
      /* Floating Badges */
      .badge {{
        position: absolute;
        top: 14px;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.8px;
        text-transform: uppercase;
        backdrop-filter: blur(12px);
        z-index: 20;
        pointer-events: none;
        display: flex;
        align-items: center;
        gap: 6px;
      }}
      .badge-before {{
        left: 16px;
        background: rgba(220, 38, 38, 0.25);
        color: #fca5a5;
        border: 1px solid rgba(239, 68, 68, 0.4);
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.3);
      }}
      .badge-after {{
        right: 16px;
        background: rgba(16, 185, 129, 0.25);
        color: #6ee7b7;
        border: 1px solid rgba(16, 185, 129, 0.4);
        box-shadow: 0 0 12px rgba(16, 185, 129, 0.3);
      }}
      .pulse-dot {{
        width: 7px;
        height: 7px;
        border-radius: 50%;
        display: inline-block;
      }}
      .badge-before .pulse-dot {{
        background: #ef4444;
        box-shadow: 0 0 8px #ef4444;
      }}
      .badge-after .pulse-dot {{
        background: #10b981;
        box-shadow: 0 0 8px #10b981;
      }}
      /* Toolbar Controls */
      .slider-controls {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        padding: 12px 6px 4px 6px;
        gap: 12px;
      }}
      .control-btn {{
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(255, 255, 255, 0.12);
        color: #e2e8f0;
        padding: 6px 14px;
        border-radius: 8px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 6px;
        transition: all 0.2s ease;
      }}
      .control-btn:hover {{
        background: rgba(51, 65, 85, 0.9);
        border-color: #06b6d4;
        color: #ffffff;
        box-shadow: 0 0 10px rgba(6, 182, 212, 0.3);
      }}
      .range-slider {{
        flex: 1;
        -webkit-appearance: none;
        height: 6px;
        border-radius: 3px;
        background: #1e293b;
        outline: none;
      }}
      .range-slider::-webkit-slider-thumb {{
        -webkit-appearance: none;
        appearance: none;
        width: 18px;
        height: 18px;
        border-radius: 50%;
        background: #06b6d4;
        cursor: pointer;
        box-shadow: 0 0 8px #06b6d4;
      }}
      /* SVG Bbox Overlays */
      .overlay-svg {{
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        z-index: 5;
        pointer-events: none;
        display: none;
      }}
      .overlay-svg.active {{
        display: block;
      }}
      .bbox-box {{
        fill: rgba(239, 68, 68, 0.2);
        stroke: #ef4444;
        stroke-width: 2;
        stroke-dasharray: 4;
        animation: dash 1s linear infinite;
      }}
      @keyframes dash {{
        to {{ stroke-dashoffset: -8; }}
      }}
    </style>
    </head>
    <body>
      <div class="comparison-wrapper" id="{slider_id}-container">
        <!-- Before Layer (Original) -->
        <img class="img-layer layer-before" src="{orig_b64}" alt="Original"/>

        <!-- After Layer (Sanitized) -->
        <img class="img-layer layer-after" id="{slider_id}-after" src="{sanitized_b64}" alt="Sanitized"/>

        <!-- SVG Redaction Target Boxes -->
        <svg class="overlay-svg" id="{slider_id}-overlay" viewBox="0 0 100 100" preserveAspectRatio="none">
          {''.join([f'<rect class="bbox-box" x="{r["x"]}%" y="{r["y"]}%" width="{r["w"]}%" height="{r["h"]}%"><title>{r["cat"]}: {r["label"]}</title></rect>' for r in overlay_rects])}
        </svg>

        <!-- Divider Line and Handle -->
        <div class="divider-line" id="{slider_id}-divider">
          <div class="divider-handle">
            <span>&#8596;</span>
          </div>
        </div>

        <!-- Badges -->
        <div class="badge badge-before">
          <span class="pulse-dot"></span> BEFORE (ORIGINAL)
        </div>
        <div class="badge badge-after">
          <span class="pulse-dot"></span> AFTER (SANITIZED)
        </div>
      </div>

      <!-- Controls Toolbar -->
      <div class="slider-controls">
        <button class="control-btn" id="{slider_id}-toggle-anim" onclick="toggleCrossfade()">
          <span>&#9654;</span> Auto-Pulse Animation
        </button>
        <button class="control-btn" id="{slider_id}-toggle-bbox" onclick="toggleOverlay()">
          <span>&#128065;</span> Highlight Redacted Boxes
        </button>
        <input type="range" min="0" max="100" value="50" class="range-slider" id="{slider_id}-range" oninput="setSliderPos(this.value)"/>
        <button class="control-btn" onclick="setSliderPos(50)">
          <span>&#8634;</span> Reset (50%)
        </button>
      </div>

      <script>
        const container = document.getElementById("{slider_id}-container");
        const afterImg = document.getElementById("{slider_id}-after");
        const divider = document.getElementById("{slider_id}-divider");
        const rangeSlider = document.getElementById("{slider_id}-range");
        const overlay = document.getElementById("{slider_id}-overlay");
        let isDragging = false;
        let isCrossfading = false;

        function updatePosition(pct) {{
          pct = Math.max(0, Math.min(100, pct));
          afterImg.style.clipPath = `polygon(${{pct}}% 0, 100% 0, 100% 100%, ${{pct}}% 100%)`;
          divider.style.left = `${{pct}}%`;
          rangeSlider.value = pct;
        }}

        function setSliderPos(val) {{
          if (isCrossfading) toggleCrossfade();
          updatePosition(val);
        }}

        function getPercentageFromEvent(e) {{
          const rect = container.getBoundingClientRect();
          const clientX = e.touches ? e.touches[0].clientX : e.clientX;
          const pos = clientX - rect.left;
          return (pos / rect.width) * 100;
        }}

        container.addEventListener("mousedown", (e) => {{
          if (isCrossfading) toggleCrossfade();
          isDragging = true;
          updatePosition(getPercentageFromEvent(e));
        }});

        window.addEventListener("mouseup", () => {{
          isDragging = false;
        }});

        window.addEventListener("mousemove", (e) => {{
          if (!isDragging) return;
          updatePosition(getPercentageFromEvent(e));
        }});

        // Touch support
        container.addEventListener("touchstart", (e) => {{
          if (isCrossfading) toggleCrossfade();
          isDragging = true;
          updatePosition(getPercentageFromEvent(e));
        }}, {{ passive: true }});

        window.addEventListener("touchend", () => {{
          isDragging = false;
        }});

        window.addEventListener("touchmove", (e) => {{
          if (!isDragging) return;
          updatePosition(getPercentageFromEvent(e));
        }}, {{ passive: true }});

        function toggleCrossfade() {{
          isCrossfading = !isCrossfading;
          const btn = document.getElementById("{slider_id}-toggle-anim");
          if (isCrossfading) {{
            container.classList.add("animated-crossfade");
            divider.style.opacity = "0";
            btn.innerHTML = "<span>&#9632;</span> Stop Pulse Animation";
            btn.style.borderColor = "#ec4899";
          }} else {{
            container.classList.remove("animated-crossfade");
            divider.style.opacity = "1";
            btn.innerHTML = "<span>&#9654;</span> Auto-Pulse Animation";
            btn.style.borderColor = "rgba(255, 255, 255, 0.12)";
            updatePosition(rangeSlider.value);
          }}
        }}

        function toggleOverlay() {{
          const active = overlay.classList.toggle("active");
          const btn = document.getElementById("{slider_id}-toggle-bbox");
          if (active) {{
            btn.style.borderColor = "#ef4444";
            btn.style.color = "#fca5a5";
          }} else {{
            btn.style.borderColor = "rgba(255, 255, 255, 0.12)";
            btn.style.color = "#e2e8f0";
          }}
        }}

        // Initialize at 50%
        updatePosition(50);
      </script>
    </body>
    </html>
    """

    components.html(html_code, height=height_px, scrolling=False)
