import json
import os
import sqlite3
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from orchestrator import Orchestrator


class RunManager:
    def __init__(self, base_data_dir: str = "./data", db_name: str = "runs.db", max_workers: int = 3):
        self.base_data_dir = Path(base_data_dir)
        self.base_data_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir = self.base_data_dir / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.base_data_dir / db_name
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._init_db()

    def create_run(self, target: str, scope: str = "", max_steps: int = 25, policy_path: str = "policy.json") -> Dict:
        run_id = uuid.uuid4().hex
        now = self._now()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        state_path = run_dir / "state.json"

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    id, target, scope, status, created_at, updated_at, max_steps, run_dir, state_path, policy_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, target, scope, "queued", now, now, max_steps, str(run_dir), str(state_path), policy_path),
            )
            conn.commit()

        self.executor.submit(self._execute_run, run_id)
        return self.get_run(run_id)

    def get_run(self, run_id: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def list_runs(self, limit: int = 50):
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_report_path(self, run_id: str) -> Optional[str]:
        run = self.get_run(run_id)
        if not run:
            return None
        report_path = run.get("report_path")
        if report_path and os.path.exists(report_path):
            return report_path
        return None

    def request_cancel(self, run_id: str) -> Optional[Dict]:
        run = self.get_run(run_id)
        if not run:
            return None
        if run["status"] in {"complete", "failed", "cancelled"}:
            return run
        self._update_run(run_id, cancel_requested=1, updated_at=self._now(), last_event="cancel_requested")
        return self.get_run(run_id)

    def _execute_run(self, run_id: str):
        run = self.get_run(run_id)
        if not run:
            return

        self._update_run(run_id, status="running", updated_at=self._now(), last_event="run_started")

        def progress_callback(stage: str, payload: Dict):
            self._update_run(
                run_id,
                updated_at=self._now(),
                last_event=stage,
                last_event_payload=json.dumps(payload),
            )

        try:
            orchestrator = Orchestrator(
                run["target"],
                run["scope"],
                data_dir=run["run_dir"],
                max_steps=run["max_steps"],
                require_user_confirmation=False,
                policy_path=run["policy_path"],
                progress_callback=progress_callback,
                should_stop_callback=lambda: self._is_cancel_requested(run_id),
            )
            result = orchestrator.run()
            report_path = self._find_report_path(run["run_dir"])
            status = result.get("status", "complete")
            if status == "cancelled":
                self._update_run(
                    run_id,
                    status="cancelled",
                    updated_at=self._now(),
                    cancelled_at=self._now(),
                    report_path=report_path,
                    error_message="",
                )
                return
            self._update_run(
                run_id,
                status=status,
                updated_at=self._now(),
                report_path=report_path,
                error_message="",
            )
        except Exception as exc:
            self._update_run(run_id, status="failed", updated_at=self._now(), error_message=str(exc))

    def _find_report_path(self, run_dir: str) -> Optional[str]:
        candidates = list(Path(run_dir).glob("report_*.html"))
        if not candidates:
            return None
        return str(candidates[0])

    def _update_run(self, run_id: str, **fields):
        if not fields:
            return
        keys = list(fields.keys())
        values = [fields[key] for key in keys]
        assignments = ", ".join([f"{key} = ?" for key in keys])
        with self._connect() as conn:
            conn.execute(f"UPDATE runs SET {assignments} WHERE id = ?", (*values, run_id))
            conn.commit()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    max_steps INTEGER NOT NULL,
                    run_dir TEXT NOT NULL,
                    state_path TEXT NOT NULL,
                    policy_path TEXT NOT NULL,
                    report_path TEXT,
                    error_message TEXT DEFAULT '',
                    last_event TEXT DEFAULT '',
                    last_event_payload TEXT DEFAULT '',
                    cancel_requested INTEGER DEFAULT 0,
                    cancelled_at TEXT DEFAULT ''
                )
                """
            )
            existing_cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(runs)").fetchall()
            }
            if "cancel_requested" not in existing_cols:
                conn.execute("ALTER TABLE runs ADD COLUMN cancel_requested INTEGER DEFAULT 0")
            if "cancelled_at" not in existing_cols:
                conn.execute("ALTER TABLE runs ADD COLUMN cancelled_at TEXT DEFAULT ''")
            conn.commit()

    def _connect(self):
        # sqlite connection objects are not thread-safe; each method gets its own.
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _row_to_dict(self, row):
        if not row:
            return None
        columns = [
            "id",
            "target",
            "scope",
            "status",
            "created_at",
            "updated_at",
            "max_steps",
            "run_dir",
            "state_path",
            "policy_path",
            "report_path",
            "error_message",
            "last_event",
            "last_event_payload",
            "cancel_requested",
            "cancelled_at",
        ]
        item = dict(zip(columns, row))
        payload = item.get("last_event_payload")
        if payload:
            try:
                item["last_event_payload"] = json.loads(payload)
            except json.JSONDecodeError:
                pass
        return item

    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    def _is_cancel_requested(self, run_id: str) -> bool:
        run = self.get_run(run_id)
        if not run:
            return False
        return bool(run.get("cancel_requested", 0))
