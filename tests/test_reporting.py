import shutil
import uuid
from pathlib import Path

from data_store import DataStore
from reporting import ReportGenerator


class _StubLLM:
    def query(self, prompt_type, context):
        assert prompt_type == "report_executive"
        return {"result": "Executive summary text.", "reasoning": ""}


def test_report_generation_curates_noisy_findings():
    work_dir = Path("test_output") / f"reporting_{uuid.uuid4().hex}"
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        store = DataStore(str(work_dir))
        store.save_state(
            {
                "target": "http://localhost:3000",
                "history": [
                    {"tool": "web_interact", "params": {"path": "/login"}, "result": {}},
                    {"tool": "web_interact", "params": {"path": "/search"}, "result": {}},
                ],
                "findings": [
                    {
                        "name": "Browser workflow evidence captured",
                        "severity": "Low",
                        "description": "noise",
                        "evidence": "shot.png",
                        "remediation": "ignore",
                    },
                    {
                        "name": "Session cookie missing HttpOnly",
                        "severity": "Medium",
                        "description": "cookie issue",
                        "evidence": "connect.sid cookie set by http://localhost:3000/login without HttpOnly.",
                        "remediation": "set httponly",
                        "affected_resource": "http://localhost:3000/login",
                        "fingerprint": "cookie_httponly:connect.sid:/login",
                    },
                    {
                        "name": "Session cookie missing HttpOnly",
                        "severity": "Medium",
                        "description": "cookie issue duplicate",
                        "evidence": "connect.sid cookie set by http://localhost:3000/login without HttpOnly.",
                        "remediation": "set httponly",
                        "affected_resource": "http://localhost:3000/login",
                        "fingerprint": "cookie_httponly:connect.sid:/login",
                    },
                ],
            }
        )

        generator = ReportGenerator(store)
        generator.llm = _StubLLM()
        report_path = Path(generator.generate(format="html"))
        html = report_path.read_text(encoding="utf-8")

        assert "Executive summary text." in html
        assert "Browser workflow evidence captured" not in html
        assert html.count("Session cookie missing HttpOnly") == 1
        assert "/search" in html
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
