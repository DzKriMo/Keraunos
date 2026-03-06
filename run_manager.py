import json
import os
import sqlite3
import uuid
import asyncio
import threading
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
        # These are set by the FastAPI app on startup
        self._ws_manager = None
        self._event_loop = None
        self._confirmation_events = None
        self._confirmation_results = None

    def set_ws_manager(self, ws_manager, loop, confirmation_events, confirmation_results):
        """Called by FastAPI startup to inject WebSocket dependencies."""
        self._ws_manager = ws_manager
        self._event_loop = loop
        self._confirmation_events = confirmation_events
        self._confirmation_results = confirmation_results

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
            # Broadcast over WebSocket
            self._broadcast(run_id, stage, payload)

            # After tool_executed, also broadcast updated findings
            if stage == "tool_executed":
                self._broadcast_findings(run_id)

        def dashboard_confirm(description: str) -> bool:
            """Request confirmation from the dashboard via WebSocket."""
            confirm_id = uuid.uuid4().hex

            if not self._event_loop or not self._confirmation_events:
                # No dashboard connected — fallback to auto-approve
                return True

            # Create an asyncio Event for this confirmation
            event = asyncio.Event()
            self._confirmation_events[confirm_id] = event
            self._confirmation_results[confirm_id] = False

            # Broadcast confirmation request to dashboard
            self._broadcast(run_id, "confirmation_required", {
                "confirm_id": confirm_id,
                "description": description,
            })

            # Wait for response (blocking from thread, with timeout)
            future = asyncio.run_coroutine_threadsafe(
                self._wait_for_confirmation(event), self._event_loop
            )
            try:
                future.result(timeout=300)  # 5 minute timeout
            except Exception:
                # Timeout or error — deny
                self._cleanup_confirmation(confirm_id)
                return False

            approved = self._confirmation_results.get(confirm_id, False)
            self._cleanup_confirmation(confirm_id)
            return approved

        try:
            orchestrator = Orchestrator(
                run["target"],
                run["scope"],
                data_dir=run["run_dir"],
                max_steps=run["max_steps"],
                require_user_confirmation=True,
                policy_path=run["policy_path"],
                progress_callback=progress_callback,
                should_stop_callback=lambda: self._is_cancel_requested(run_id),
                confirm_callback=dashboard_confirm,
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
                self._broadcast(run_id, "cancelled", {"reason": "stop_requested"})
                return
            self._update_run(
                run_id,
                status=status,
                updated_at=self._now(),
                report_path=report_path,
                error_message="",
            )
            self._broadcast(run_id, "completed", {"steps": result.get("steps", 0)})
        except Exception as exc:
            self._update_run(run_id, status="failed", updated_at=self._now(), error_message=str(exc))
            self._broadcast(run_id, "error", {"message": str(exc)})

    async def _wait_for_confirmation(self, event: asyncio.Event):
        await event.wait()

    def _cleanup_confirmation(self, confirm_id: str):
        self._confirmation_events.pop(confirm_id, None)
        self._confirmation_results.pop(confirm_id, None)

    def _broadcast(self, run_id: str, stage: str, payload: dict):
        """Send an event to all WebSocket connections for this run."""
        if not self._ws_manager or not self._event_loop:
            return
        msg = {"stage": stage, "payload": payload}
        try:
            asyncio.run_coroutine_threadsafe(
                self._ws_manager.broadcast(run_id, msg), self._event_loop
            )
        except Exception:
            pass

    def _broadcast_findings(self, run_id: str):
        """Broadcast current findings to dashboard."""
        run = self.get_run(run_id)
        if not run:
            return
        state_path = run.get("state_path")
        if not state_path or not os.path.exists(state_path):
            return
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            findings = state.get("findings", [])
            self._broadcast(run_id, "findings_updated", {"findings": findings})
        except Exception:
            pass

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
