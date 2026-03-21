import time

import run_manager
from run_manager import RunManager


class _FakeOrchestrator:
    last_approved = None

    def __init__(self, *args, **kwargs):
        self.confirm_callback = kwargs["confirm_callback"]

    def run(self):
        _FakeOrchestrator.last_approved = self.confirm_callback("test confirmation")
        return {"status": "complete", "steps": 0, "findings": 0}


def test_confirmation_fails_closed_without_dashboard(tmp_path, monkeypatch):
    monkeypatch.setattr(run_manager, "Orchestrator", _FakeOrchestrator)
    manager = RunManager(base_data_dir=str(tmp_path), max_workers=1)

    run = manager.create_run("example.com")
    run_id = run["id"]

    deadline = time.time() + 5
    while time.time() < deadline:
        current = manager.get_run(run_id)
        if current and current["status"] in {"complete", "failed", "cancelled", "partial"}:
            break
        time.sleep(0.05)

    assert _FakeOrchestrator.last_approved is False


def test_create_run_persists_safe_mode(tmp_path):
    manager = RunManager(base_data_dir=str(tmp_path), max_workers=1)
    run = manager.create_run("http://example.com", mode="webapp", settings={"ports": [80]})
    assert run["mode"] == "webapp"
    assert run["settings_json"] == {"ports": [80]}
