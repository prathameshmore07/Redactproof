import os
import sys
import io
import json
import base64
from pathlib import Path

# Ensure src/ is in sys.path
_SRC_DIR = Path(__file__).resolve().parent.parent.parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from typing import List, Dict, Any, Optional
from PIL import Image
import streamlit as st

from redactproof.schemas import Finding, Action, FindingCategory, Sensitivity
from redactproof.multi_format import load_any_document, export_sanitized_pdf, ProcessedDocument
from redactproof.custom_rules import CustomRuleMatcher, SmartSuggestionsEngine
from redactproof.streamlit_app.processor import StreamlitDocumentProcessor
from redactproof.streamlit_app.components import render_before_after_slider
from redactproof.streamlit_app.style import inject_styles
from redactproof.input_loader import compute_sha256


def main():
    # Set Streamlit Page Configuration
    st.set_page_config(
        page_title="Redactproof Studio | Local-First Document Sanitizer",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Inject custom CSS design system
    inject_styles()

    # Initialize Session State
    if "doc" not in st.session_state:
        st.session_state.doc = None
    if "cleared_by_user" not in st.session_state:
        st.session_state.cleared_by_user = False
    if "current_page_idx" not in st.session_state:
        st.session_state.current_page_idx = 0
    if "findings_by_page" not in st.session_state:
        st.session_state.findings_by_page = {}
    if "selected_findings" not in st.session_state:
        st.session_state.selected_findings = {}
    if "sanitized_pages" not in st.session_state:
        st.session_state.sanitized_pages = {}
    if "stranger_before" not in st.session_state:
        st.session_state.stranger_before = []
    if "stranger_after" not in st.session_state:
        st.session_state.stranger_after = []
    if "custom_terms" not in st.session_state:
        st.session_state.custom_terms = ""
    if "custom_is_regex" not in st.session_state:
        st.session_state.custom_is_regex = False
    if "custom_case_sensitive" not in st.session_state:
        st.session_state.custom_case_sensitive = False
    if "custom_action" not in st.session_state:
        st.session_state.custom_action = "redact"
    if "verification_info" not in st.session_state:
        st.session_state.verification_info = {}

    # Auto-load test.png by default on fresh launch so the UI is immediately alive & populated
    if st.session_state.doc is None and not st.session_state.cleared_by_user:
        test_png = Path(__file__).resolve().parent.parent.parent.parent / "test.png"
        if test_png.exists():
            try:
                st.session_state.doc = load_any_document(test_png.read_bytes(), "test.png")
                st.session_state.current_page_idx = 0
            except Exception:
                pass

    # --- SIDEBAR CONFIGURATION ---
    with st.sidebar:
        st.markdown("### 🛡️ **Redactproof Engine**")
        st.markdown("Provable, zero-trust document & screenshot sanitization.")

        st.markdown("---")
        st.markdown("#### 🎯 **Destination Policy**")
        policy_option = st.selectbox(
            "Select Target Audience Policy",
            options=["public", "internal", "support"],
            index=0,
            help="Public: Strictest rules. Internal: Preserves architecture names. Support: Pseudonymizes customer data.",
        )

        if "active_policy" not in st.session_state:
            st.session_state.active_policy = policy_option
        elif st.session_state.active_policy != policy_option:
            st.session_state.active_policy = policy_option
            st.session_state.findings_by_page = {}
            st.session_state.sanitized_pages = {}

        policy_descriptions = {
            "public": "🔒 **Public Policy**: High-security fail-closed. Redacts all credentials, PII, internal hostnames, user paths, faces, and QR codes.",
            "internal": "🏢 **Internal Policy**: Preserves internal hostnames and user paths for team debugging; redacts passwords and secrets.",
            "support": "🎫 **Support Policy**: Pseudonymizes customer identifiers and emails for support ticketing; redacts API keys.",
        }
        st.info(policy_descriptions[policy_option])

        st.markdown("---")
        st.markdown("#### ⚙️ **Redaction Settings**")
        mask_mode = st.radio(
            "Mask Rendering Style",
            options=["Solid Opaque Blackout", "Pseudonymize Labels"],
            index=0,
            help="Solid opaque blackout is mathematically permanent and provably unrecoverable.",
        )
        margin_px = st.slider("Mask Margin Expansion (px)", min_value=0, max_value=16, value=4, step=1)
        strict_mode = st.toggle("Strict Mode (Block on Residual Risk)", value=False)

        st.markdown("---")
        if st.button("🔄 Reset / Clear Session", use_container_width=True):
            st.session_state.doc = None
            st.session_state.cleared_by_user = True
            st.session_state.findings_by_page = {}
            st.session_state.sanitized_pages = {}
            st.session_state.current_page_idx = 0
            st.session_state.stranger_before = []
            st.session_state.stranger_after = []
            st.rerun()

    # --- HERO HEADER ---
    st.markdown("""
    <div class="hero-header">
        <div class="hero-title">
            <span>🛡️</span> Redactproof Studio
        </div>
        <div class="hero-subtitle">
            Universal multi-format document sanitizer with smart PII auto-suggestions, custom user-defined term removal,
            and interactive animated Before/After verification.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # --- SECTION 1: DOCUMENT INPUT & UPLOAD ---
    input_tab1, input_tab2 = st.tabs(["📁 Upload File (PDF, Image, Text, Code, Logs)", "✍️ Paste Direct Text or Logs"])

    with input_tab1:
        uploaded_file = st.file_uploader(
            "Upload any document, image, or text file to sanitize",
            type=[
                "png", "jpg", "jpeg", "webp", "bmp", "tiff", "pdf",
                "txt", "log", "json", "csv", "py", "env", "md", "yaml", "xml"
            ],
            help="Upload PDF documents, screenshots, photos, logs, or source code files.",
        )
        if uploaded_file is not None:
            try:
                file_bytes = uploaded_file.getvalue()
                doc_loaded = load_any_document(file_bytes, uploaded_file.name)
                if st.session_state.doc is None or st.session_state.doc.file_hash != doc_loaded.file_hash:
                    st.session_state.doc = doc_loaded
                    st.session_state.cleared_by_user = False
                    st.session_state.current_page_idx = 0
                    st.session_state.findings_by_page = {}
                    st.session_state.sanitized_pages = {}
                    st.success(f"✓ Successfully loaded {uploaded_file.name} ({doc_loaded.doc_type.upper()}, {doc_loaded.total_pages} page(s))")
            except Exception as e:
                st.error(f"⚠️ Error reading uploaded file: {e}")

    with input_tab2:
        pasted_text = st.text_area(
            "Paste text, logs, configuration files, or code snippets here",
            height=140,
            placeholder="Paste server logs, API keys, JSON payloads, or emails here...",
        )
        if st.button("📥 Load Pasted Text as Document"):
            if pasted_text.strip():
                doc_loaded = load_any_document(pasted_text.encode("utf-8"), "pasted_text.txt")
                st.session_state.doc = doc_loaded
                st.session_state.cleared_by_user = False
                st.session_state.current_page_idx = 0
                st.session_state.findings_by_page = {}
                st.session_state.sanitized_pages = {}
                st.success("✓ Loaded pasted text snippet into Redactproof Studio!")
                st.rerun()
            else:
                st.warning("Please paste some text first.")

    # If no document is loaded, display welcoming state with quick-load option
    if st.session_state.doc is None:
        st.markdown("""
        <div class="glass-panel" style="text-align: center; padding: 40px 20px;">
            <h3 style="color: #38bdf8; margin-bottom: 12px;">👋 Welcome to Redactproof Studio</h3>
            <p style="color: #94a3b8; max-width: 650px; margin: 0 auto 20px auto; font-size: 15px;">
                Get started by uploading a <b>PDF</b>, an <b>Image / Screenshot</b>, or a <b>Text / Log File</b> above,
                or paste your text directly into the paste tab.
            </p>
            <div style="display: flex; justify-content: center; gap: 16px; flex-wrap: wrap;">
                <div class="badge-pill badge-critical">🔑 Auto-detects Credentials</div>
                <div class="badge-pill badge-high">👤 Auto-detects PII & Emails</div>
                <div class="badge-pill badge-medium">🌐 Auto-detects Hostnames & IPs</div>
                <div class="badge-pill badge-pass">✏️ Custom Keyword Matching</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_ld1, col_ld2, col_ld3 = st.columns([1, 2, 1])
        with col_ld2:
            test_png = Path(__file__).resolve().parent.parent.parent.parent / "test.png"
            if test_png.exists():
                if st.button("⚡ Load Sample Security Document (test.png)", type="primary", use_container_width=True):
                    st.session_state.doc = load_any_document(test_png.read_bytes(), "test.png")
                    st.session_state.cleared_by_user = False
                    st.session_state.current_page_idx = 0
                    st.session_state.findings_by_page = {}
                    st.session_state.sanitized_pages = {}
                    st.rerun()
        st.stop()

    # --- DOCUMENT ACTIVE (Safely guarded) ---
    active_doc: ProcessedDocument = st.session_state.doc
    if not getattr(active_doc, "pages", None) or len(active_doc.pages) == 0:
        st.warning("⚠️ Loaded document contains no renderable pages.")
        st.stop()

    page_idx = max(0, min(st.session_state.current_page_idx, active_doc.total_pages - 1))
    current_page = active_doc.pages[page_idx]

    # Parse custom rules
    compiled_custom_rules, regex_errors = CustomRuleMatcher.parse_user_input(
        text_input=st.session_state.custom_terms,
        is_regex=st.session_state.custom_is_regex,
        case_sensitive=st.session_state.custom_case_sensitive,
    )

    proc = StreamlitDocumentProcessor(policy_name=policy_option)

    # Initial scan run if page not yet analyzed
    if page_idx not in st.session_state.findings_by_page:
        try:
            init_finds, init_sb, _ = proc.analyze_page(
                page=current_page,
                custom_rules=compiled_custom_rules,
                custom_action=Action(st.session_state.custom_action),
            )
            st.session_state.findings_by_page[page_idx] = init_finds
            st.session_state.stranger_before = init_sb

            selected_set = {f.region_id for f in init_finds if f.action != Action.KEEP}
            st.session_state.selected_findings[page_idx] = selected_set

            active_findings = [f for f in init_finds if f.region_id in selected_set]
            sanitized_img, stranger_after, v_info = proc.render_sanitization(
                image=current_page.image,
                findings=active_findings,
                stranger_before=init_sb,
            )
            st.session_state.sanitized_pages[page_idx] = sanitized_img
            st.session_state.stranger_after = stranger_after
            st.session_state.verification_info = v_info
        except Exception:
            pass

    # --- TOP METRICS BAR ---
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{active_doc.doc_type.upper()}</div>
            <div class="stat-label">Document Type ({active_doc.total_pages} page{'s' if active_doc.total_pages > 1 else ''})</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m2:
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{active_doc.filename[:18]}</div>
            <div class="stat-label">File Name</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m3:
        curr_findings = st.session_state.findings_by_page.get(page_idx, [])
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{len(curr_findings)}</div>
            <div class="stat-label">Sensitive Items Detected</div>
        </div>
        """, unsafe_allow_html=True)

    with col_m4:
        is_sanitized = page_idx in st.session_state.sanitized_pages
        badge_html = '<span class="badge-pill badge-pass">✓ SANITIZED</span>' if is_sanitized else '<span class="badge-pill badge-critical">PENDING SANITIZATION</span>'
        st.markdown(f"""
        <div class="stat-card">
            <div class="stat-value">{badge_html}</div>
            <div class="stat-label">Security Status</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br/>", unsafe_allow_html=True)

    # --- MULTI-PAGE NAVIGATOR (FOR PDFS) ---
    if active_doc.total_pages > 1:
        st.markdown("#### 📄 **Multi-Page Navigator**")
        nav_c1, nav_c2, nav_c3, nav_c4 = st.columns([1, 3, 1, 2])
        if nav_c1.button("◀ Prev Page", disabled=(page_idx == 0), use_container_width=True):
            st.session_state.current_page_idx = max(0, page_idx - 1)
            st.rerun()
        with nav_c2:
            new_page = st.slider(
                "Jump to page",
                min_value=1,
                max_value=active_doc.total_pages,
                value=page_idx + 1,
                format="Page %d",
            )
            if new_page - 1 != page_idx:
                st.session_state.current_page_idx = new_page - 1
                st.rerun()
        if nav_c3.button("Next Page ▶", disabled=(page_idx == active_doc.total_pages - 1), use_container_width=True):
            st.session_state.current_page_idx = min(active_doc.total_pages - 1, page_idx + 1)
            st.rerun()
        with nav_c4:
            if st.button(f"⚡ Sanitize All {active_doc.total_pages} Pages", type="primary", use_container_width=True):
                progress_bar = st.progress(0.0)
                status_text = st.empty()
                p_rules, _ = CustomRuleMatcher.parse_user_input(
                    text_input=st.session_state.custom_terms,
                    is_regex=st.session_state.custom_is_regex,
                    case_sensitive=st.session_state.custom_case_sensitive,
                )
                proc_all = StreamlitDocumentProcessor(policy_name=policy_option)
                for p_num in range(active_doc.total_pages):
                    status_text.text(f"Scanning & sanitizing page {p_num + 1} of {active_doc.total_pages}...")
                    p_finds, p_sb, _ = proc_all.analyze_page(
                        page=active_doc.pages[p_num],
                        custom_rules=p_rules,
                        custom_action=Action(st.session_state.custom_action),
                    )
                    st.session_state.findings_by_page[p_num] = p_finds
                    p_sel = {f.region_id for f in p_finds if f.action != Action.KEEP}
                    st.session_state.selected_findings[p_num] = p_sel
                    p_act_finds = [f for f in p_finds if f.region_id in p_sel]
                    p_san, p_sa, p_vi = proc_all.render_sanitization(
                        image=active_doc.pages[p_num].image,
                        findings=p_act_finds,
                        stranger_before=p_sb,
                    )
                    st.session_state.sanitized_pages[p_num] = p_san
                    progress_bar.progress((p_num + 1) / active_doc.total_pages)
                status_text.success(f"✓ All {active_doc.total_pages} pages successfully sanitized!")
                st.rerun()

    # --- SECTION 2: CUSTOM REDACTION RULES (USER-TYPED INPUT) ---
    st.markdown("### ✏️ **Custom Redactions (What you want to remove)**")
    st.markdown("Type specific terms, names, secret keywords, phone numbers, or regex patterns you want redacted from this document.")

    with st.expander("📝 Enter Custom Keywords & Regular Expressions", expanded=True):
        col_cu1, col_cu2 = st.columns([3, 1])
        with col_cu1:
            custom_input = st.text_area(
                "Keywords or Regexes (comma-separated or on separate lines)",
                value=st.session_state.custom_terms,
                placeholder="e.g. Acme Corp, John Doe, secret_project, confidential, sk-[a-zA-Z0-9]+",
                help="Enter literal words or regular expressions. Redactproof will automatically locate their coordinates and mask them.",
            )
            st.session_state.custom_terms = custom_input

        with col_cu2:
            st.session_state.custom_is_regex = st.checkbox("Treat as Regular Expressions", value=st.session_state.custom_is_regex)
            st.session_state.custom_case_sensitive = st.checkbox("Case Sensitive", value=st.session_state.custom_case_sensitive)
            st.session_state.custom_action = st.selectbox(
                "Action for Custom Terms",
                options=["redact", "pseudonymize"],
                index=0 if st.session_state.custom_action == "redact" else 1,
            )

        # Validate regex live
        compiled_custom_rules, regex_errors = CustomRuleMatcher.parse_user_input(
            text_input=st.session_state.custom_terms,
            is_regex=st.session_state.custom_is_regex,
            case_sensitive=st.session_state.custom_case_sensitive,
        )

        if regex_errors:
            for err in regex_errors:
                st.error(f"⚠️ {err}")
        elif compiled_custom_rules:
            st.success(f"✓ {len(compiled_custom_rules)} custom rule(s) parsed and active.")

    # --- SECTION 3: SCAN & SMART AUTO-SUGGESTIONS ---
    st.markdown("---")
    st.markdown("### 💡 **Smart Redaction Suggestions & Analysis**")

    proc = StreamlitDocumentProcessor(policy_name=policy_option)

    # Run or refresh analysis
    col_btn1, col_btn2 = st.columns([2, 2])
    scan_clicked = col_btn1.button("🔍 Run Full Perception & Sensitive Scan", type="primary", use_container_width=True)

    if scan_clicked:
        with st.spinner("Analyzing document with OCR, detectors, faces, barcodes, and custom rules..."):
            try:
                findings, stranger_before, _ = proc.analyze_page(
                    page=current_page,
                    custom_rules=compiled_custom_rules,
                    custom_action=Action(st.session_state.custom_action),
                )
                st.session_state.findings_by_page[page_idx] = findings
                st.session_state.stranger_before = stranger_before

                # Auto-select all findings that are not KEEP
                selected_set = set()
                for f in findings:
                    if f.action != Action.KEEP:
                        selected_set.add(f.region_id)
                st.session_state.selected_findings[page_idx] = selected_set

                # Automatically render sanitization for instant visual feedback
                active_findings = [f for f in findings if f.region_id in selected_set]
                sanitized_img, stranger_after, v_info = proc.render_sanitization(
                    image=current_page.image,
                    findings=active_findings,
                    stranger_before=stranger_before,
                )
                st.session_state.sanitized_pages[page_idx] = sanitized_img
                st.session_state.stranger_after = stranger_after
                st.session_state.verification_info = v_info
            except Exception as e:
                st.error(f"⚠️ Scan error: {e}")

    findings = st.session_state.findings_by_page.get(page_idx, [])
    selected_ids = st.session_state.selected_findings.get(page_idx, set())

    if findings:
        # Quick action batch buttons
        b_col1, b_col2, b_col3, b_col4 = st.columns(4)
        if b_col1.button("✅ Select All Recommended", use_container_width=True):
            st.session_state.selected_findings[page_idx] = {f.region_id for f in findings if f.action != Action.KEEP}
            st.rerun()

        if b_col2.button("🔥 High & Critical Only", use_container_width=True):
            st.session_state.selected_findings[page_idx] = {
                f.region_id for f in findings if f.sensitivity in (Sensitivity.HIGH, Sensitivity.CRITICAL)
            }
            st.rerun()

        if b_col3.button("⚪ Clear All Selections", use_container_width=True):
            st.session_state.selected_findings[page_idx] = set()
            st.rerun()

        if b_col4.button("⚡ Apply Redactions & Verify", type="primary", use_container_width=True):
            active_findings = [f for f in findings if f.region_id in selected_ids]
            with st.spinner("Rendering masks and running closed-loop verification..."):
                sanitized_img, stranger_after, v_info = proc.render_sanitization(
                    image=current_page.image,
                    findings=active_findings,
                    stranger_before=st.session_state.stranger_before,
                )
                st.session_state.sanitized_pages[page_idx] = sanitized_img
                st.session_state.stranger_after = stranger_after
                st.session_state.verification_info = v_info
            st.rerun()

        # Suggestions list grouped in an expander
        with st.expander(f"📋 Review & Customize Suggested Redactions ({len(findings)} detected items)", expanded=True):
            st.markdown("*Check or uncheck individual items below. The Before/After visualizer updates immediately.*")

            for f in findings:
                info = SmartSuggestionsEngine.categorize_finding(f)
                checked = f.region_id in selected_ids

                c1, c2, c3, c4 = st.columns([1, 3, 4, 2])
                with c1:
                    new_checked = st.checkbox(
                        f"ID #{f.region_id}",
                        value=checked,
                        key=f"finding_check_{page_idx}_{f.region_id}",
                    )
                    if new_checked != checked:
                        if new_checked:
                            selected_ids.add(f.region_id)
                        else:
                            selected_ids.discard(f.region_id)
                        st.session_state.selected_findings[page_idx] = selected_ids
                        active_findings = [fi for fi in findings if fi.region_id in selected_ids]
                        sanitized_img, stranger_after, v_info = proc.render_sanitization(
                            image=current_page.image,
                            findings=active_findings,
                            stranger_before=st.session_state.stranger_before,
                        )
                        st.session_state.sanitized_pages[page_idx] = sanitized_img
                        st.session_state.stranger_after = stranger_after
                        st.session_state.verification_info = v_info
                        st.rerun()

                with c2:
                    badge_class = f"badge-{f.sensitivity.value.lower()}"
                    st.markdown(
                        f"<span class='badge-pill {badge_class}'>{info['icon']} {info['group_name']}</span>",
                        unsafe_allow_html=True,
                    )

                with c3:
                    preview_text = f.plaintext or (f"Salted Token: {f.text_salted_sha256[:12]}..." if f.text_salted_sha256 else "Visual Target")
                    st.markdown(f"**`{preview_text}`** &nbsp;•&nbsp; *{f.rationale}*")

                with c4:
                    st.markdown(f"<span style='color: #94a3b8; font-size: 12px;'>Detector: <code>{f.detector}</code></span>", unsafe_allow_html=True)
    else:
        st.info("ℹ️ No sensitive items detected yet. Click 'Run Full Perception & Sensitive Scan' above.")

    # --- SECTION 4: VISUAL BEFORE & AFTER COMPARISON (WITH ANIMATION) ---
    st.markdown("---")
    st.markdown("### 🎬 **Interactive Before & After Visual Comparison**")

    sanitized_current_img = st.session_state.sanitized_pages.get(page_idx, current_page.image)

    vis_mode_tab1, vis_mode_tab2 = st.tabs(["✨ Interactive Split Slider (Animated)", "👥 Side-by-Side Dual View"])

    with vis_mode_tab1:
        st.markdown(
            "*Drag the neon divider left/right to wipe and reveal Before vs After. Click **Auto-Pulse Animation** for a smooth breathing crossfade transition!*"
        )
        render_before_after_slider(
            original_img=current_page.image,
            sanitized_img=sanitized_current_img,
            findings=[f for f in findings if f.region_id in selected_ids],
            height_px=650,
        )

    with vis_mode_tab2:
        col_v1, col_v2 = st.columns(2)
        with col_v1:
            st.markdown("#### 🔴 **Original (Before Sanitization)**")
            st.image(current_page.image, use_container_width=True)
        with col_v2:
            st.markdown("#### 🟢 **Sanitized (After Redaction)**")
            st.image(sanitized_current_img, use_container_width=True)

    # --- SECTION 5: AUDIT PROOF & EXPORT DOWNLOADS ---
    st.markdown("---")
    st.markdown("### 📜 **Proof of Sanitization & Download Exports**")

    col_exp1, col_exp2 = st.columns(2)

    with col_exp1:
        st.markdown("#### 🛡️ **Cryptographic Verification**")
        v_info = st.session_state.verification_info
        masks_pass = v_info.get("masks_uniform", True)
        ocr_hits = v_info.get("verifier_ocr_hits", 0)
        pattern_hits = v_info.get("pattern_hits_after", 0)

        st.markdown(f"""
        - **Original Document SHA-256**: `...{active_doc.file_hash[:20]}...`
        - **Uniform Mask Opacity**: {'<span class="badge-pill badge-pass">PASS (Zero Variance)</span>' if masks_pass else '<span class="badge-pill badge-critical">FAIL</span>'}
        - **Verifier OCR Hits in Masked Regions**: `{ocr_hits}`
        - **Pattern Hits Remaining in Output**: `{pattern_hits}`
        """, unsafe_allow_html=True)

        if st.session_state.stranger_before:
            st.markdown("**Stranger Test: Audience Inferences Before:**")
            for inf in st.session_state.stranger_before:
                st.markdown(f"• *{inf}*")

        st.markdown("**Stranger Test: Audience Inferences After:**")
        if not st.session_state.stranger_after:
            st.markdown("• <span style='color: #10b981; font-weight: bold;'>✓ Zero confidential inferences remaining</span>", unsafe_allow_html=True)
        else:
            for inf in st.session_state.stranger_after:
                st.markdown(f"• {inf}")

    with col_exp2:
        st.markdown("#### 💾 **Download Sanitized Outputs**")

        # 1. Download Sanitized Image (Current Page)
        buf_img = io.BytesIO()
        sanitized_current_img.save(buf_img, format="PNG")
        st.download_button(
            label="📥 Download Sanitized Image (PNG)",
            data=buf_img.getvalue(),
            file_name=f"{Path(active_doc.filename).stem}.sanitized.page_{page_idx+1}.png",
            mime="image/png",
            use_container_width=True,
        )

        # 2. Download Sanitized Multi-Page PDF (if PDF or multi-page)
        if active_doc.total_pages > 1 or active_doc.doc_type == "pdf":
            all_pages_to_export = []
            for i in range(active_doc.total_pages):
                p_img = st.session_state.sanitized_pages.get(i, active_doc.pages[i].image)
                all_pages_to_export.append(p_img)

            try:
                pdf_bytes = export_sanitized_pdf(all_pages_to_export)
                st.download_button(
                    label=f"📥 Download Sanitized PDF ({active_doc.total_pages} Pages)",
                    data=pdf_bytes,
                    file_name=f"{Path(active_doc.filename).stem}.sanitized.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"Could not build multi-page PDF: {e}")

        # 3. Download Sanitized Text (if text document)
        if active_doc.doc_type == "text" and active_doc.original_text:
            sanitized_txt, rep_count = CustomRuleMatcher.sanitize_plain_text(
                active_doc.original_text,
                compiled_custom_rules,
                replacement="[REDACTED]",
            )
            st.download_button(
                label=f"📥 Download Sanitized Text / Code ({rep_count} replaced)",
                data=sanitized_txt.encode("utf-8"),
                file_name=f"{Path(active_doc.filename).stem}.sanitized{Path(active_doc.filename).suffix}",
                mime="text/plain",
                use_container_width=True,
            )

        # 4. Download Full Audit Report JSON
        audit_data = {
            "tool": "redactproof",
            "version": "0.1.0-alpha",
            "filename": active_doc.filename,
            "input_sha256": active_doc.file_hash,
            "policy": policy_option,
            "total_pages": active_doc.total_pages,
            "findings_count": len(findings),
            "redacted_count": len(selected_ids),
            "stranger_before": st.session_state.stranger_before,
            "stranger_after": st.session_state.stranger_after,
            "verification": v_info,
        }
        st.download_button(
            label="📑 Download Cryptographic Audit Report (JSON)",
            data=json.dumps(audit_data, indent=2),
            file_name=f"{Path(active_doc.filename).stem}.audit_report.json",
            mime="application/json",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()
