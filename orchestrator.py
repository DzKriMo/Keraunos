import time
from typing import Dict, Any

from confirmation import confirm_action
from data_store import DataStore
from llm_interface import LLMInterface
from analysis_engine import AnalysisEngine
from policy_engine import PolicyEngine
from tool_wrappers import ToolWrapperFactory


class Orchestrator:
    def __init__(
        self,
        target: str,
        scope: str,
        data_dir: str = "./data",
        max_steps: int = 25,
        require_user_confirmation: bool = True,
        policy_path: str = "policy.json",
        progress_callback=None,
        should_stop_callback=None,
    ):
        self.target = target
        self.scope = scope
        self.max_steps = max_steps
        self.require_user_confirmation = require_user_confirmation
        self.progress_callback = progress_callback
        self.should_stop_callback = should_stop_callback
        self.data_store = DataStore(data_dir)
        self.llm = LLMInterface()
        self.tool_factory = ToolWrapperFactory()
        self.analysis_engine = AnalysisEngine()
        self.policy = PolicyEngine(policy_path)
        self.state = self._load_state() or {
            "phase": "recon",
            "history": [],
            "findings": [],
            "target": target,
            "scope": scope
        }

    def _load_state(self) -> Dict[str, Any]:
        return self.data_store.load_state()

    def _save_state(self):
        self.data_store.save_state(self.state)

    def run(self):
        print(f"[*] Starting autonomous pentest on {self.target}")
        self._emit_progress("started", {"target": self.target, "scope": self.scope})
        for _ in range(self.max_steps):
            if self._should_stop():
                self._emit_progress("cancelled", {"reason": "stop_requested"})
                return {"status": "cancelled", "steps": len(self.state["history"]), "findings": len(self.state["findings"])}
            # Get current context for LLM
            context = self._build_context()
            # Ask LLM what to do next
            action = self.ask_llm("next_action", context)
            if action["type"] == "complete":
                print("[*] Assessment complete. Generating report...")
                self._generate_report()
                self._emit_progress("completed", {"steps": len(self.state["history"])})
                break
            elif action["type"] == "tool":
                tool_name = action["tool"]
                params = action.get("params", {})
                params = self._apply_tool_constraints(tool_name, params)
                allowed, reason, needs_confirmation = self._policy_check(tool_name, params)
                if not allowed:
                    self._record_event(tool_name, params, {"error": f"Policy denied: {reason}"})
                    self._emit_progress("policy_denied", {"tool": tool_name, "reason": reason})
                    continue
                if self._requires_confirmation(tool_name, params, needs_confirmation):
                    if not confirm_action(f"Run {tool_name} with params {params}"):
                        self._record_event(tool_name, params, {"error": "Action cancelled by user"})
                        self._emit_progress("cancelled", {"tool": tool_name})
                        continue
                # Execute tool
                try:
                    result = self.execute_tool(tool_name, params)
                except Exception as exc:
                    result = {"error": str(exc)}
                self._record_event(tool_name, params, result)
                self._refresh_findings()
                self._save_state()
                self._emit_progress("tool_executed", {"tool": tool_name, "ok": "error" not in result})
            elif action["type"] == "analysis":
                # LLM wants to analyze existing data
                analysis = self.ask_llm("analyze", context)
                self.state["findings"].extend(analysis.get("findings", []))
                self._refresh_findings()
                self._save_state()
                self._emit_progress("analysis_complete", {"findings": len(analysis.get("findings", []))})
            else:
                print(f"[!] Unknown action type: {action['type']}")
                break
        else:
            print(f"[!] Reached max steps ({self.max_steps}). Generating partial report...")
            self._generate_report()
            self._emit_progress("max_steps_reached", {"max_steps": self.max_steps})
            return {"status": "partial", "steps": self.max_steps, "findings": len(self.state["findings"])}

        return {"status": "complete", "steps": len(self.state["history"]), "findings": len(self.state["findings"])}

    def ask_llm(self, prompt_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            prompt = self.llm.build_prompt(prompt_type, context)
            response = self.llm.query(prompt)
            parsed = self.llm.parse_response(response)
            if prompt_type == "analyze" and isinstance(parsed, list):
                return {"findings": parsed}
            return parsed
        except Exception:
            return self._fallback_action(prompt_type, context)

    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        wrapper = self.tool_factory.get_wrapper(tool_name)
        exec_params = dict(params)
        exec_params["__stop_callback"] = self._should_stop
        return wrapper.run(exec_params)

    def _requires_confirmation(self, tool_name: str, params: Dict[str, Any], policy_requested: bool) -> bool:
        if not self.require_user_confirmation:
            return False
        if policy_requested:
            return True
        if tool_name == "nmap":
            flags = params.get("flags", "")
            return any(flag in flags for flag in ["-sS", "-A", "-O", "--script"])
        return False

    def _build_context(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scope": self.scope,
            "phase": self.state["phase"],
            "history": self.state["history"][-10:],  # last 10 actions
            "findings": self.state["findings"]
        }

    def _generate_report(self):
        from reporting import ReportGenerator

        report_gen = ReportGenerator(self.data_store)
        report_gen.generate()
        self._emit_progress("report_generated", {"target": self.target})

    def _fallback_action(self, prompt_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        if prompt_type == "analyze":
            return {"findings": []}
        tools_run = [item.get("tool") for item in self.state.get("history", []) if item.get("tool")]
        if "nmap" not in tools_run:
            return {"type": "tool", "tool": "nmap", "params": {"target": self.target, "flags": "-sV"}}
        if "http_probe" not in tools_run:
            return {"type": "tool", "tool": "http_probe", "params": {"target": self.target, "scheme": "http"}}
        if "searchsploit" not in tools_run:
            return {"type": "tool", "tool": "searchsploit", "params": {"query": self.target}}
        if "wpscan" not in tools_run:
            return {"type": "tool", "tool": "wpscan", "params": {"url": f"http://{self.target}"}}
        if "sqlmap" not in tools_run:
            return {"type": "tool", "tool": "sqlmap", "params": {"url": f"http://{self.target}"}}
        return {"type": "complete"}

    def _policy_check(self, tool_name: str, params: Dict[str, Any]):
        try:
            wrapper = self.tool_factory.get_wrapper(tool_name)
        except Exception:
            return False, f"Unknown tool '{tool_name}'", False
        risk_level = getattr(wrapper, "risk_level", "low")
        return self.policy.evaluate(tool_name, params, self.target, risk_level)

    def _record_event(self, tool_name: str, params: Dict[str, Any], result: Dict[str, Any]):
        self.state["history"].append(
            {
                "timestamp": time.time(),
                "tool": tool_name,
                "params": params,
                "result": result,
            }
        )
        self._save_state()

    def _refresh_findings(self):
        deterministic = self.analysis_engine.derive_findings(self.state.get("history", []))
        merged = self.state.get("findings", []) + deterministic
        seen = set()
        deduped = []
        for finding in merged:
            key = (finding.get("name"), finding.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        self.state["findings"] = deduped

    def _emit_progress(self, stage: str, payload: Dict[str, Any]):
        if self.progress_callback:
            self.progress_callback(stage, payload)

    def _should_stop(self):
        return bool(self.should_stop_callback and self.should_stop_callback())

    def _apply_tool_constraints(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        constrained = dict(params)
        policy = self.policy.policy
        max_timeout = int(policy.get("max_tool_timeout_seconds", 300))
        tool_timeouts = policy.get("tool_timeouts", {})
        default_timeout = int(tool_timeouts.get(tool_name, max_timeout))
        requested_timeout = int(constrained.get("timeout", default_timeout))
        constrained["timeout"] = max(1, min(requested_timeout, max_timeout))
        return constrained
