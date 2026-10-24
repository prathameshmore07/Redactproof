"use strict";

// --- State ---
const initialUrlParams = new URLSearchParams(window.location.search);
const state = {
  findings: [],
  selectedId: null,
  view: initialUrlParams.get("view") === "preview" ? "preview" : "original",
  zoom: 1,
  imageW: 0,
  imageH: 0,
  undoStack: [],
  redoStack: [],
};


// --- DOM refs ---
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);

const canvasContainer = $(".canvas-container");
const canvasImg = $("#canvas-img");
const overlayLayer = $("#overlay-layer");
const maskLayer = $("#mask-layer");
const findingsList = $(".findings-list");
const btnOriginal = $("#btn-original");
const btnPreview = $("#btn-preview");
const btnZoomIn = $("#btn-zoom-in");
const btnZoomOut = $("#btn-zoom-out");
const btnZoomFit = $("#btn-zoom-fit");
const btnUndo = $("#btn-undo");
const btnRedo = $("#btn-redo");
const btnExport = $("#btn-export");
const countRedact = $(".count-redact");
const countReview = $(".count-review");
const countKeep = $(".count-keep");
const topStatus = $(".topbar-right");
const topPolicy = $("#policy-name");
const topModel = $("#model-name");
const dropZone = $("#drop-zone");
const btnOpenFile = $("#btn-open-file");
const fileInput = $("#file-input");

// --- Init ---
async function init() {
  bindEvents();
  try {
    const res = await fetch("/api/state");
    if (!res.ok) throw new Error("Failed to load state");
    const data = await res.json();
    loadStateData(data);
  } catch (e) {
    if (dropZone) dropZone.style.display = "flex";
    findingsList.innerHTML =
      '<div class="state-message">No image loaded. Drop a screenshot to inspect and redact.</div>';
  }
}

function loadStateData(data) {
  if (!data.loaded) {
    if (dropZone) dropZone.style.display = "flex";
    topStatus.textContent = "Ready. Drop a screenshot or open an image.";
    findingsList.innerHTML =
      '<div class="state-message">No image loaded. Drop a screenshot to inspect and redact.</div>';
    return;
  }

  if (dropZone) dropZone.style.display = "none";
  state.filename = data.filename;
  state.findings = data.findings.map((f) => ({
    ...f,
    _action: f.action,
    _resolved: f.action !== "review",
  }));
  state.imageW = data.dimensions[0];
  state.imageH = data.dimensions[1];

  topPolicy.textContent = data.policy;
  topModel.textContent = data.models || "gemma-4";
  topStatus.textContent = data.findings.length + " regions detected";

  canvasImg.width = state.imageW;
  canvasImg.height = state.imageH;

  const onImgReady = () => {
    zoomFit();
    renderOverlays();
  };

  if (canvasImg.complete && canvasImg.naturalWidth > 0) {
    onImgReady();
  } else {
    canvasImg.onload = onImgReady;
  }
  canvasImg.src = "/api/image/original?" + Date.now();

  renderFindings();
  updateCounts();
  btnOriginal.classList.toggle("active", state.view === "original");
  btnPreview.classList.toggle("active", state.view === "preview");

  if (initialUrlParams.has("select") && state.findings.length > 0) {
    const selIdx = parseInt(initialUrlParams.get("select"), 10) || 0;
    if (state.findings[selIdx]) {
      selectFinding(state.findings[selIdx].region_id);
    }
  }
}

async function uploadFile(file) {
  if (!file) return;
  topStatus.textContent = "Scanning screenshot with Apple Vision & detectors...";
  if (dropZone) {
    dropZone.style.display = "flex";
    const title = dropZone.querySelector(".drop-title");
    const sub = dropZone.querySelector(".drop-subtitle");
    if (title) title.textContent = "Scanning screenshot...";
    if (sub) sub.textContent = file.name;
  }

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const base64Data = reader.result.split(",")[1];
      const res = await fetch("/api/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filename: file.name,
          image_base64: base64Data,
          policy: topPolicy.textContent || "public",
        }),
      });
      if (!res.ok) throw new Error("Upload processing failed");
      const data = await res.json();
      loadStateData(data);
    } catch (err) {
      topStatus.textContent = "Upload failed: " + err.message;
      if (dropZone) {
        const title = dropZone.querySelector(".drop-title");
        const sub = dropZone.querySelector(".drop-subtitle");
        if (title) title.textContent = "Drop screenshot here to redact";
        if (sub) sub.textContent = "or click Open Image to select a file";
      }
    }
  };
  reader.readAsDataURL(file);
}



// --- Render findings list ---
function renderFindings() {
  findingsList.innerHTML = "";

  const groups = { review: [], redact: [], keep: [] };
  for (const f of state.findings) {
    const a = f._action;
    if (a === "review") groups.review.push(f);
    else if (a === "redact" || a === "pseudonymize") groups.redact.push(f);
    else groups.keep.push(f);
  }

  if (groups.review.length) {
    appendGroup("Needs review", "review-group", groups.review);
  }
  if (groups.redact.length) {
    appendGroup("Redact", "redact-group", groups.redact);
  }
  if (groups.keep.length) {
    appendGroup("Keep", "keep-group", groups.keep);
  }
}

function appendGroup(label, cls, items) {
  const hdr = document.createElement("div");
  hdr.className = "group-header " + cls;
  hdr.textContent = label + " (" + items.length + ")";
  findingsList.appendChild(hdr);

  for (const f of items) {
    const row = document.createElement("div");
    row.className = "finding-row" + (f.region_id === state.selectedId ? " selected" : "");
    row.dataset.id = f.region_id;

    const dot = document.createElement("div");
    dot.className = "finding-dot " + f._action;
    row.appendChild(dot);

    const cat = document.createElement("div");
    cat.className = "finding-category";
    cat.textContent = f.category.replace(/_/g, " ");
    cat.title = f.rationale;
    row.appendChild(cat);

    const det = document.createElement("div");
    det.className = "finding-detector";
    det.textContent = shortDetector(f.detector);
    row.appendChild(det);

    const conf = document.createElement("div");
    conf.className = "finding-confidence";
    conf.textContent = Math.round(f.confidence * 100) + "%";
    row.appendChild(conf);

    const actions = document.createElement("div");
    actions.className = "finding-actions";

    if (f._action === "review" || f._action === "keep") {
      const acc = document.createElement("button");
      acc.className = "action-btn accept";
      acc.textContent = "Redact";
      acc.title = "Accept redaction (A)";
      acc.addEventListener("click", (e) => {
        e.stopPropagation();
        setAction(f.region_id, "redact");
      });
      actions.appendChild(acc);
    }

    if (f._action === "review" || f._action === "redact") {
      const rej = document.createElement("button");
      rej.className = "action-btn reject";
      rej.textContent = "Keep";
      rej.title = "Reject, keep visible (R)";
      rej.addEventListener("click", (e) => {
        e.stopPropagation();
        setAction(f.region_id, "keep");
      });
      actions.appendChild(rej);
    }

    row.appendChild(actions);

    row.addEventListener("click", () => selectFinding(f.region_id));
    findingsList.appendChild(row);

    // Detail drawer
    const drawer = document.createElement("div");
    drawer.className = "detail-drawer" + (f.region_id === state.selectedId ? " open" : "");
    drawer.dataset.drawerId = f.region_id;
    drawer.innerHTML = buildDetail(f);
    findingsList.appendChild(drawer);
  }
}

function buildDetail(f) {
  const bbox = f.bbox;
  let html = "";
  html += detailRow("Rationale", f.rationale);
  html += detailRow("Detector", f.detector);
  html += detailRow("Sensitivity", f.sensitivity || "--");
  html += detailRow("BBox", `[${bbox[0]}, ${bbox[1]}, ${bbox[2]}, ${bbox[3]}]`, true);

  if (f.plaintext) {
    html += `<div class="detail-row">
      <div class="detail-label">Text</div>
      <div class="detail-value mono masked-text" onclick="this.classList.toggle('revealed')"
        data-plain="${escapeAttr(f.plaintext)}"
        data-masked="${"\u2588".repeat(Math.min(f.plaintext.length, 32))}">
        ${ "\u2588".repeat(Math.min(f.plaintext.length, 32)) }
      </div>
    </div>`;
  }
  return html;
}

function detailRow(label, value, mono) {
  return `<div class="detail-row">
    <div class="detail-label">${label}</div>
    <div class="detail-value${mono ? " mono" : ""}">${escapeHtml(value || "--")}</div>
  </div>`;
}

function shortDetector(d) {
  if (!d) return "";
  if (d.startsWith("regex")) return "regex";
  if (d.startsWith("gemma")) return "gemma";
  if (d.includes("entropy")) return "entropy";
  if (d.includes("luhn")) return "luhn";
  if (d.includes("ip") || d.includes("host")) return "ip";
  if (d.includes("path")) return "path";
  if (d.includes("url")) return "url";
  if (d.includes("injection")) return "guard";
  if (d.includes("vision") || d.includes("face")) return "vision";
  if (d.includes("barcode")) return "vision";
  return d.slice(0, 8);
}

// --- Actions ---
function setAction(id, action) {
  const f = state.findings.find((x) => x.region_id === id);
  if (!f) return;
  const prev = f._action;
  pushUndo(id, prev);
  f._action = action;
  f._resolved = true;
  renderFindings();
  renderOverlays();
  updateCounts();
}

function pushUndo(id, prevAction) {
  state.undoStack.push({ id, action: prevAction });
  state.redoStack = [];
}

function undo() {
  const entry = state.undoStack.pop();
  if (!entry) return;
  const f = state.findings.find((x) => x.region_id === entry.id);
  if (!f) return;
  state.redoStack.push({ id: entry.id, action: f._action });
  f._action = entry.action;
  f._resolved = entry.action !== "review";
  renderFindings();
  renderOverlays();
  updateCounts();
}

function redo() {
  const entry = state.redoStack.pop();
  if (!entry) return;
  const f = state.findings.find((x) => x.region_id === entry.id);
  if (!f) return;
  state.undoStack.push({ id: entry.id, action: f._action });
  f._action = entry.action;
  f._resolved = entry.action !== "review";
  renderFindings();
  renderOverlays();
  updateCounts();
}

function selectFinding(id) {
  state.selectedId = state.selectedId === id ? null : id;
  renderFindings();
  renderOverlays();

  // Scroll selected box into view
  if (state.selectedId !== null) {
    const box = overlayLayer.querySelector(`[data-id="${state.selectedId}"]`);
    if (box) box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }
}

// --- Render overlays ---
function renderOverlays() {
  overlayLayer.innerHTML = "";
  maskLayer.innerHTML = "";

  if (!state.imageW || !state.imageH) return;

  const img = canvasImg;
  const currentW = img.clientWidth > 0 ? img.clientWidth : state.imageW;
  const currentH = img.clientHeight > 0 ? img.clientHeight : state.imageH;
  const scaleX = currentW / state.imageW;
  const scaleY = currentH / state.imageH;

  for (const f of state.findings) {
    if (state.view === "preview" && (f._action === "redact" || f._action === "pseudonymize")) {
      // Mask rect
      const mask = document.createElement("div");
      mask.className = "mask-rect";
      mask.style.left = f.bbox[0] * scaleX + "px";
      mask.style.top = f.bbox[1] * scaleY + "px";
      mask.style.width = (f.bbox[2] - f.bbox[0]) * scaleX + "px";
      mask.style.height = (f.bbox[3] - f.bbox[1]) * scaleY + "px";
      maskLayer.appendChild(mask);
    }

    if (state.view === "original" || f._action === "review" || f._action === "keep") {
      const box = document.createElement("div");
      box.className = "box-overlay" + (f.region_id === state.selectedId ? " selected" : "");
      box.dataset.action = f._action;
      box.dataset.id = f.region_id;
      box.style.left = f.bbox[0] * scaleX + "px";
      box.style.top = f.bbox[1] * scaleY + "px";
      box.style.width = (f.bbox[2] - f.bbox[0]) * scaleX + "px";
      box.style.height = (f.bbox[3] - f.bbox[1]) * scaleY + "px";
      box.addEventListener("click", () => selectFinding(f.region_id));
      overlayLayer.appendChild(box);
    }
  }
}

// --- Zoom ---
function setZoom(z) {
  state.zoom = Math.max(0.2, Math.min(4, z));
  canvasContainer.style.transform = `scale(${state.zoom})`;
}

function zoomFit() {
  const viewport = $(".canvas-viewport");
  if (!viewport || !state.imageW || !state.imageH) return;
  const vw = viewport.clientWidth - 48;
  const vh = viewport.clientHeight - 48;
  if (vw <= 0 || vh <= 0) return;
  const fit = Math.min(vw / state.imageW, vh / state.imageH, 1);
  setZoom(Math.max(0.2, fit));
}


// --- Counts ---
function updateCounts() {
  let r = 0, rev = 0, k = 0;
  for (const f of state.findings) {
    if (f._action === "redact" || f._action === "pseudonymize") r++;
    else if (f._action === "review") rev++;
    else k++;
  }
  countRedact.textContent = r + " redact";
  countReview.textContent = rev + " need review";
  countKeep.textContent = k + " keep";

  btnExport.disabled = rev > 0;
  btnExport.title = rev > 0 ? rev + " review items remain. Resolve all before export." : "Export sanitized image (Cmd+Enter)";
}

// --- View toggle ---
function setView(v) {
  state.view = v;
  btnOriginal.classList.toggle("active", v === "original");
  btnPreview.classList.toggle("active", v === "preview");
  renderOverlays();
}

// --- Export ---
async function doExport() {
  const unresolved = state.findings.filter((f) => f._action === "review").length;
  if (unresolved > 0) return;

  btnExport.textContent = "Exporting...";
  btnExport.disabled = true;

  try {
    const payload = {
      policy: topPolicy.textContent,
      decisions: state.findings.map((f) => ({
        region_id: f.region_id,
        action: f._action,
      })),
    };
    const res = await fetch("/api/apply_decisions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error("Export failed");
    const result = await res.json();

    btnExport.textContent = "Exported";
    topStatus.textContent = "Sanitized image written. Verification complete.";

    // Trigger direct browser download of the sanitized image
    const a = document.createElement("a");
    a.href = "/api/image/sanitized?" + Date.now();
    a.download = (state.filename ? state.filename.replace(/\.[^/.]+$/, "") : "screenshot") + ".sanitized.png";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    // Switch to preview
    setView("preview");
    canvasImg.src = "/api/image/sanitized?" + Date.now();
  } catch (e) {
    btnExport.textContent = "Export";
    btnExport.disabled = false;
    topStatus.textContent = "Export failed. " + e.message;
  }
}

// --- Masked text toggle ---
document.addEventListener("click", (e) => {
  if (e.target.classList.contains("masked-text")) {
    const el = e.target;
    if (el.classList.contains("revealed")) {
      el.textContent = el.dataset.masked;
      el.classList.remove("revealed");
    } else {
      el.textContent = el.dataset.plain;
      el.classList.add("revealed");
    }
  }
});

// --- Keyboard & Event Bindings ---
function bindEvents() {
  btnOriginal.addEventListener("click", () => setView("original"));
  btnPreview.addEventListener("click", () => setView("preview"));
  btnZoomIn.addEventListener("click", () => setZoom(state.zoom * 1.25));
  btnZoomOut.addEventListener("click", () => setZoom(state.zoom / 1.25));
  btnZoomFit.addEventListener("click", zoomFit);
  btnUndo.addEventListener("click", undo);
  btnRedo.addEventListener("click", redo);
  btnExport.addEventListener("click", doExport);

  if (btnOpenFile && fileInput) {
    btnOpenFile.addEventListener("click", () => fileInput.click());
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        uploadFile(e.target.files[0]);
      }
    });
  }

  // Drag and drop anywhere on window
  window.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (dropZone) {
      dropZone.style.display = "flex";
      dropZone.classList.add("active");
    }
  });

  window.addEventListener("dragleave", (e) => {
    if (e.relatedTarget === null && dropZone) {
      dropZone.classList.remove("active");
      if (state.imageW > 0) dropZone.style.display = "none";
    }
  });

  window.addEventListener("drop", (e) => {
    e.preventDefault();
    if (dropZone) dropZone.classList.remove("active");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]) {
      uploadFile(e.dataTransfer.files[0]);
    } else if (state.imageW > 0 && dropZone) {
      dropZone.style.display = "none";
    }
  });


  window.addEventListener("resize", () => {
    renderOverlays();
  });

  document.addEventListener("keydown", (e) => {
    // Don't capture if user is in an input
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;

    const key = e.key.toLowerCase();

    if (key === "j" || key === "k") {
      e.preventDefault();
      navigateFinding(key === "j" ? 1 : -1);
    } else if (key === "a" && state.selectedId !== null) {
      e.preventDefault();
      setAction(state.selectedId, "redact");
    } else if (key === "r" && state.selectedId !== null) {
      e.preventDefault();
      setAction(state.selectedId, "keep");
    } else if (key === " ") {
      e.preventDefault();
      setView(state.view === "original" ? "preview" : "original");
    } else if (key === "z" && !e.metaKey && !e.ctrlKey) {
      e.preventDefault();
      zoomFit();
    } else if (key === "z" && (e.metaKey || e.ctrlKey) && !e.shiftKey) {
      e.preventDefault();
      undo();
    } else if (key === "z" && (e.metaKey || e.ctrlKey) && e.shiftKey) {
      e.preventDefault();
      redo();
    } else if (key === "enter" && (e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      doExport();
    }
  });
}

function navigateFinding(dir) {
  if (!state.findings.length) return;
  const ids = state.findings.map((f) => f.region_id);
  const idx = state.selectedId !== null ? ids.indexOf(state.selectedId) : -1;
  let next = idx + dir;
  if (next < 0) next = ids.length - 1;
  if (next >= ids.length) next = 0;
  selectFinding(ids[next]);

  // Scroll finding into view in panel
  const row = findingsList.querySelector(`[data-id="${ids[next]}"]`);
  if (row) row.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// --- Helpers ---
function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function escapeAttr(s) {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// --- Boot ---
init();
