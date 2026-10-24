import io
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn
from PIL import Image

from ..pipeline import RedactproofPipeline
from ..input_loader import load_and_validate_image
from ..schemas import Action, FindingCategory, Finding, BoundingBox
from ..redaction.renderer import RedactionRenderer
from ..verify.loop import ClosedLoopVerifier
from ..verify.adversary import ModelAdversaryVerifier
from ..audit.report import AuditReportGenerator
from ..input_loader import compute_sha256

app = FastAPI(title="Redactproof Local Review Server")

# State for the active review session
session_state: Dict[str, Any] = {
    "input_path": None,
    "policy_name": "public",
    "image": None,
    "findings": [],
    "text_items": [],
    "pipeline": None,
    "sanitized_image": None,
    "output_path": None,
    "audit_report": None,
}

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Mount static directory AFTER defining API routes (added at bottom before uvicorn)

@app.get("/", response_class=HTMLResponse)
def get_index():
    index_file = STATIC_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Index HTML not found")
    return index_file.read_text(encoding="utf-8")

@app.get("/api/state")
def get_state():
    if not session_state.get("input_path"):
        return {
            "loaded": False,
            "policy": session_state.get("policy_name", "public"),
            "models": "gemma-4",
            "findings": [],
            "dimensions": [0, 0],
        }

    # Serialize findings
    serialized_findings = []
    for f in session_state["findings"]:
        serialized_findings.append({
            "region_id": f.region_id,
            "bbox": [f.bbox.x1, f.bbox.y1, f.bbox.x2, f.bbox.y2],
            "category": f.category.value,
            "detector": f.detector,
            "confidence": f.confidence,
            "action": f.action.value,
            "rationale": f.rationale,
            "sensitivity": f.sensitivity.value,
            "plaintext": getattr(f, "plaintext", ""),
        })

    return {
        "loaded": True,
        "filename": session_state["input_path"].name,
        "policy": session_state["policy_name"],
        "dimensions": [session_state["image"].width, session_state["image"].height],
        "findings": serialized_findings,
        "stranger_before": session_state.get("stranger_before", []),
        "stranger_after": session_state.get("stranger_after", []),
    }

class UploadPayload(BaseModel):
    filename: str
    image_base64: str
    policy: str = "public"

@app.post("/api/upload")
def upload_image(payload: UploadPayload):
    raw_bytes = base64.b64decode(payload.image_base64)
    temp_dir = Path.home() / ".cache" / "redactproof"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / payload.filename
    temp_path.write_bytes(raw_bytes)
    load_and_process_session(temp_path, policy=payload.policy)
    return get_state()



@app.get("/api/image/original")
def get_original_image():
    if not session_state["input_path"]:
        raise HTTPException(status_code=400, detail="No image")
    return FileResponse(session_state["input_path"])

@app.get("/api/image/sanitized")
def get_sanitized_image():
    if not session_state.get("sanitized_path"):
        raise HTTPException(status_code=404, detail="Not yet sanitized")
    return FileResponse(session_state["sanitized_path"])

class DecisionPayload(BaseModel):
    region_id: int
    action: str  # "keep", "redact", "pseudonymize"

class DecisionsBatch(BaseModel):
    policy: str
    decisions: List[DecisionPayload]

@app.post("/api/apply_decisions")
def apply_decisions(payload: DecisionsBatch):
    decision_map = {d.region_id: d.action for d in payload.decisions}
    image = session_state["image"]
    findings = session_state["findings"]

    # Update actions based on user decisions
    for f in findings:
        if f.region_id in decision_map:
            f.action = Action(decision_map[f.region_id])

    # Re-render with approved decisions
    renderer = RedactionRenderer()
    canvas, rendered_masks = renderer.render(image, findings)

    # Save to sanitized output
    out_path = session_state["input_path"].parent / f"{session_state['input_path'].stem}.sanitized.png"
    salt = "redactproof-review"
    adversary_verifier = ModelAdversaryVerifier(session_state["pipeline"].gemma)
    verifier_loop = ClosedLoopVerifier(
        policy=session_state["pipeline"].policy,
        adversary=adversary_verifier,
        renderer=renderer,
    )

    v_result = verifier_loop.run_verification_loop(
        original_image=image,
        current_canvas=canvas,
        output_file_path=out_path,
        initial_findings=findings,
        initial_mask_boxes=rendered_masks,
        original_sha256=compute_sha256(session_state["input_path"]),
        stranger_inferences_before=session_state.get("stranger_before", []),
        salt=salt,
    )

    session_state["sanitized_path"] = out_path
    session_state["stranger_after"] = v_result.assessed_judgments.stranger_test_after

    return {
        "success": True,
        "output_path": str(out_path),
        "verified": v_result.verified_facts.model_dump(),
        "assessed": v_result.assessed_judgments.model_dump(),
        "stranger_after": v_result.assessed_judgments.stranger_test_after,
    }

def load_and_process_session(input_path: Path, policy: str = "public"):
    input_path = Path(input_path).resolve()
    loaded = load_and_validate_image(input_path)
    pipeline = RedactproofPipeline(policy_name=policy, include_plaintext_in_report=True)

    # Initial scan
    text_items = pipeline.ocr_primary.extract_text(loaded.image)
    faces = pipeline.face_detector.detect_faces(loaded.image)
    codes = pipeline.code_detector.detect_codes(loaded.image)
    detectors_findings = pipeline.detectors.detect_all(
        items=text_items,
        allowlist_domains=pipeline.policy.allowlist.domains,
        salt="redactproof-review",
    )
    injections = pipeline.gemma.injection_guard.inspect_text_items(text_items) if hasattr(pipeline.gemma, "injection_guard") else []
    all_det = faces + codes + detectors_findings + injections
    stranger_before = pipeline.gemma.stranger_test(text_items, policy)
    gemma_finds, _ = pipeline.gemma.review_ambiguous_and_relational(text_items, policy)
    final_findings = pipeline.policy_engine.apply_policy(all_det, gemma_finds)

    # Attach plaintext for user inspection in local UI
    item_map = {it.region_id: it.text for it in text_items}
    for f in final_findings:
        if f.region_id in item_map:
            f.plaintext = item_map[f.region_id]

    session_state["input_path"] = input_path
    session_state["policy_name"] = policy
    session_state["image"] = loaded.image
    session_state["text_items"] = text_items
    session_state["findings"] = final_findings
    session_state["pipeline"] = pipeline
    session_state["stranger_before"] = stranger_before
    session_state["sanitized_path"] = None

def start_review_server(input_path: Optional[Path] = None, policy: str = "public", port: int = 8000):
    session_state["policy_name"] = policy
    if input_path:
        load_and_process_session(input_path, policy=policy)

    # Mount static files last so API routes take priority
    app.mount("/", StaticFiles(directory=str(STATIC_DIR)), name="static")

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")

