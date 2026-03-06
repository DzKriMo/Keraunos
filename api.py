import os

from fastapi import FastAPI, HTTPException
from fastapi import Depends
from fastapi import Header
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from run_manager import RunManager

app = FastAPI(title="Keraunos API", version="0.1.0")
run_manager = RunManager()


def require_api_key(x_api_key: str = Header(default="")):
    configured = os.getenv("KERAUNOS_API_KEY", "").strip()
    if not configured:
        return
    if x_api_key != configured:
        raise HTTPException(status_code=401, detail="Unauthorized")


class CreateRunRequest(BaseModel):
    target: str = Field(..., description="Target hostname or IP")
    scope: str = Field(default="")
    max_steps: int = Field(default=25, ge=1, le=500)
    policy_path: str = Field(default="policy.json")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/runs")
def create_run(request: CreateRunRequest, _: None = Depends(require_api_key)):
    return run_manager.create_run(
        target=request.target,
        scope=request.scope,
        max_steps=request.max_steps,
        policy_path=request.policy_path,
    )


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


@app.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, _: None = Depends(require_api_key)):
    run = run_manager.request_cancel(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
