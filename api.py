import os
import json
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi import Depends
from fastapi import Header
from fastapi import Query
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel, Field

from run_manager import RunManager
from wordlist_registry import WordlistRegistry

app = FastAPI(title="Keraunos API", version="2.0.0")
run_manager = RunManager()
wordlist_registry = WordlistRegistry()

# Global LLM preference
_llm_enabled = True

# ── WebSocket connection manager ────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, Set[WebSocket]] = {}  # run_id -> set of websockets

    async def connect(self, run_id: str, websocket: WebSocket):
        await websocket.accept()
        if run_id not in self.active:
            self.active[run_id] = set()
        self.active[run_id].add(websocket)

    def disconnect(self, run_id: str, websocket: WebSocket):
        if run_id in self.active:
            self.active[run_id].discard(websocket)
            if not self.active[run_id]:
                del self.active[run_id]

    async def broadcast(self, run_id: str, message: dict):
        if run_id not in self.active:
            return
        payload = json.dumps(message)
        dead = set()
        for ws in self.active[run_id]:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active[run_id].discard(ws)

ws_manager = ConnectionManager()

# ── Confirmation system ─────────────────────────────────────────────
_confirmation_events: Dict[str, asyncio.Event] = {}
_confirmation_results: Dict[str, bool] = {}

# ── Startup: wire dependencies ──────────────────────────────────────
@app.on_event("startup")
async def startup():
    loop = asyncio.get_event_loop()
    run_manager.set_ws_manager(ws_manager, loop, _confirmation_events, _confirmation_results)


# ── Auth ────────────────────────────────────────────────────────────
def require_api_key(x_api_key: str = Header(default="")):
    configured = os.getenv("KERAUNOS_API_KEY", "").strip()
    if not configured:
        return
    if x_api_key != configured:
        raise HTTPException(status_code=401, detail="Unauthorized")

# ── Models ──────────────────────────────────────────────────────────
class CreateRunRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP")
    scope: str = Field(default="")
    mode: str = Field(default="legacy", pattern="^(system|webapp|ai_agent|legacy)$")
    max_steps: int = Field(default=25, ge=1, le=500)
    policy_path: str = Field(default="policy.json")
    settings: Dict[str, Any] = Field(default_factory=dict)

class RegisterWordlistRequest(BaseModel):
    name: str = Field(..., min_length=1)
    path: str = Field(..., min_length=1)
    description: str = Field(default="")

class ConfirmationResponse(BaseModel):
    confirm_id: str
    approved: bool

# ── Dashboard ───────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    template_path = Path(__file__).parent / "templates" / "dashboard.html"
    return HTMLResponse(template_path.read_text(encoding="utf-8"))

# ── Health ──────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok"}

# ── LLM Control ─────────────────────────────────────────────────────
@app.get("/llm/status")
def get_llm_status():
    from llm_interface import LLMInterface
    try:
        llm = LLMInterface()
        llm.enabled = _llm_enabled
        connected = llm.check_connection() if _llm_enabled else False
        model = llm.model
        provider = getattr(llm, "provider", "unknown")
        error = ""
    except Exception as exc:
        connected = False
        model = ""
        provider = os.getenv("KERAUNOS_LLM_PROVIDER", "unknown")
        error = str(exc)
    return {
        "enabled": _llm_enabled,
        "connected": connected,
        "model": model,
        "provider": provider,
        "error": error,
    }

@app.post("/llm/toggle")
def toggle_llm():
    global _llm_enabled
    _llm_enabled = not _llm_enabled
    return {"enabled": _llm_enabled}

# ── Reports ─────────────────────────────────────────────────────────
@app.get("/reports")
def list_reports(_: None = Depends(require_api_key)):
    """List valid reports for completed/partial runs."""
    reports = []
    for run in run_manager.list_runs(limit=500):
        if run.get("status") not in {"complete", "partial"}:
            continue
        report_path = run.get("report_path")
        if not report_path:
            continue
        path_obj = Path(report_path)
        if not path_obj.exists():
            continue
        reports.append({
            "run_id": run["id"],
            "filename": path_obj.name,
            "path": f"/runs/{run['id']}/report",
            "pdf_path": f"/runs/{run['id']}/report/pdf",
            "created_at": datetime.fromtimestamp(path_obj.stat().st_mtime, timezone.utc).isoformat(),
            "status": run.get("status", "complete"),
        })

    # Include legacy direct reports in ./data.
    data_dir = Path("./data")
    for report in data_dir.glob("report_*.html"):
        if not any(r["filename"] == report.name for r in reports):
            reports.append({
                "run_id": "direct",
                "filename": report.name,
                "path": f"/data/{report.name}",
                "created_at": datetime.fromtimestamp(report.stat().st_mtime, timezone.utc).isoformat(),
                "status": "legacy",
            })
    return {"items": sorted(reports, key=lambda x: x["created_at"], reverse=True)}


@app.get("/data/{filename}")
def get_direct_report(filename: str, _: None = Depends(require_api_key)):
    # Only allow direct access to report files in ./data.
    if Path(filename).name != filename or not filename.startswith("report_") or not filename.endswith(".html"):
        raise HTTPException(status_code=400, detail="Invalid report filename")

    base_dir = Path("./data").resolve()
    path = (base_dir / filename).resolve()
    if base_dir not in path.parents:
        raise HTTPException(status_code=400, detail="Invalid report path")

    if not path.exists():
        raise HTTPException(status_code=404)
    return FileResponse(path)

# ── Runs ────────────────────────────────────────────────────────────
@app.post("/runs")
def create_run(request: CreateRunRequest, _: None = Depends(require_api_key)):
    return run_manager.create_run(
        target=request.target,
        scope=request.scope,
        mode=request.mode,
        max_steps=request.max_steps,
        policy_path=request.policy_path,
        llm_enabled=_llm_enabled,
        settings=request.settings,
    )

@app.get("/modes")
def list_modes():
    return {
        "items": [
            {
                "id": "webapp",
                "label": "Web App Assessment",
                "description": "Deep LLM-driven testing for XSS, SQLi, SSRF, and web vulnerabilities.",
            },
            {
                "id": "system",
                "label": "System Assessment",
                "description": "Deep LLM-driven testing for network protocols, services, and infrastructure.",
            },
            {
                "id": "ai_agent",
                "label": "AI Agent Assessment",
                "description": "Deep LLM-driven testing for guardrails, prompt injection, and data leakage.",
            },
            {
                "id": "legacy",
                "label": "Legacy Autonomous Mode",
                "description": "Standard discovery and enumeration orchestration.",
            },
        ]
    }

@app.get("/runs")
def list_runs(limit: int = 50, _: None = Depends(require_api_key)):
    return {"items": run_manager.list_runs(limit=limit)}

@app.get("/runs/{run_id}")
def get_run(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.get("/runs/{run_id}/report")
def get_report(run_id: str, _: None = Depends(require_api_key)):
    report_path = run_manager.get_report_path(run_id)
    if not report_path:
        raise HTTPException(status_code=404, detail="Report not found or run not completed")
    return FileResponse(report_path, media_type="text/html")

@app.get("/runs/{run_id}/report/pdf")
def get_report_pdf(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.get_run(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")

    from data_store import DataStore
    from reporting import ReportGenerator

    pdf_path = ReportGenerator(DataStore(run["run_dir"])).generate(format="pdf")
    return FileResponse(pdf_path, media_type="application/pdf", filename=Path(pdf_path).name)

@app.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.request_cancel(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.post("/runs/{run_id}/pause")
def pause_run(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.request_pause(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.post("/runs/{run_id}/resume")
def resume_run(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.request_resume(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run

@app.post("/runs/{run_id}/confirm")
async def confirm_action_endpoint(run_id: str, body: ConfirmationResponse, _: None = Depends(require_api_key)):
    """Handle confirmation responses from the dashboard."""
    confirm_id = body.confirm_id
    if confirm_id not in _confirmation_events:
        raise HTTPException(status_code=404, detail="No pending confirmation with that ID")
    _confirmation_results[confirm_id] = body.approved
    _confirmation_events[confirm_id].set()
    return {"status": "ok", "approved": body.approved}

# ── WebSocket ───────────────────────────────────────────────────────
@app.websocket("/ws/{run_id}")
async def websocket_endpoint(websocket: WebSocket, run_id: str, x_api_key: str = Query(default="")):
    configured = os.getenv("KERAUNOS_API_KEY", "").strip()
    if configured:
        header_key = websocket.headers.get("x-api-key", "")
        if header_key != configured and x_api_key != configured:
            await websocket.close(code=1008)
            return

    await ws_manager.connect(run_id, websocket)
    
    # Send initial state (history + findings) if available
    run = run_manager.get_run(run_id)
    if run and os.path.exists(run["state_path"]):
        try:
            with open(run["state_path"], "r", encoding="utf-8") as f:
                state = json.load(f)
            await websocket.send_text(json.dumps({
                "stage": "initial_state",
                "payload": {
                    "history": state.get("history", []),
                    "findings": state.get("findings", []),
                    "reasoning_trace": state.get("reasoning_trace", []),
                    "status": run["status"]
                }
            }))
        except Exception:
            pass

    try:
        while True:
            # Keep connection alive, receive any messages (heartbeats)
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30)
            except asyncio.TimeoutError:
                # Send heartbeat to keep alive
                try:
                    await websocket.send_text(json.dumps({"stage": "heartbeat"}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(run_id, websocket)

# ── Wordlists ───────────────────────────────────────────────────────
@app.get("/wordlists")
def list_wordlists(_: None = Depends(require_api_key)):
    return {"items": wordlist_registry.list_wordlists()}

@app.post("/wordlists")
def register_wordlist(request: RegisterWordlistRequest, _: None = Depends(require_api_key)):
    try:
        return wordlist_registry.register_wordlist(request.name, request.path, request.description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

@app.delete("/wordlists/{name}")
def delete_wordlist(name: str, _: None = Depends(require_api_key)):
    removed = wordlist_registry.remove_wordlist(name)
    if not removed:
        raise HTTPException(status_code=404, detail="Wordlist not found")
    return removed
