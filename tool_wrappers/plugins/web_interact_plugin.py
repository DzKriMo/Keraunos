import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import requests

from tool_wrappers.base import ToolWrapper


class WebInteractWrapper(ToolWrapper):
    """
    Visible web interaction tool.

    Supports plain HTTP requests and optional Playwright-backed browser actions for
    live dashboard telemetry in `webapp` mode.
    """

    tool_name = "web_interact"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        target = params.get("target")
        if not target:
            raise ValueError("web_interact target is required")

        path = params.get("path", "/")
        method = str(params.get("method", "GET")).upper()
        payload = params.get("payload", {}) or {}
        headers = params.get("headers", {}) or {}
        json_payload = params.get("json")
        files = params.get("files")
        cookies = params.get("cookies", {}) or {}
        timeout = int(params.get("timeout", 30))
        browser = bool(params.get("browser"))
        browser_action = str(params.get("browser_action", "goto")).lower()
        session_name = str(params.get("session_name", "") or "").strip()
        run_dir = Path(params.get("__run_dir", "."))

        url = self._build_url(target, path, payload if method == "GET" else {})
        if browser:
            browser_result = self._run_browser(url, params, timeout)
            if browser_result:
                return browser_result

        try:
            session = requests.Session()
            if session_name:
                self._load_session_cookies(session, run_dir, session_name)
            if cookies:
                session.cookies.update(cookies)
            request_kwargs = {
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": bool(params.get("allow_redirects", True)),
            }
            if method == "GET":
                response = session.get(url, **request_kwargs)
            else:
                if files:
                    request_kwargs["files"] = self._build_files(files)
                    request_kwargs["data"] = payload
                elif json_payload is not None:
                    request_kwargs["json"] = json_payload
                else:
                    request_kwargs["data"] = payload
                response = session.request(method, url, **request_kwargs)

            if session_name:
                self._save_session_cookies(session, run_dir, session_name)

            telemetry = {
                "transport": "http",
                "action": "request",
                "method": method,
                "request_url": url,
                "final_url": response.url,
                "status_code": response.status_code,
                "content_length": len(response.text),
            }
            return {
                "method": method,
                "url": url,
                "full_url": response.url,
                "status_code": response.status_code,
                "navigation_url": response.url,
                "payload_sent": payload,
                "json_sent": json_payload,
                "response_preview": response.text[:4000],
                "headers": dict(response.headers),
                "cookies": requests.utils.dict_from_cookiejar(session.cookies),
                "session_name": session_name,
                "raw": self._format_http_result(response, telemetry),
                "browser_action": browser_action,
                "telemetry": telemetry,
            }
        except Exception as e:
            return {
                "error": str(e),
                "url": url,
                "navigation_url": url,
                "browser_action": browser_action,
                "raw": str(e),
            }

    def _session_path(self, run_dir: Path, session_name: str) -> Path:
        safe_name = "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in session_name)
        session_dir = run_dir / "http_sessions"
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir / f"{safe_name}.json"

    def _load_session_cookies(self, session: requests.Session, run_dir: Path, session_name: str) -> None:
        session_path = self._session_path(run_dir, session_name)
        if not session_path.exists():
            return
        try:
            cookie_map = json.loads(session_path.read_text(encoding="utf-8"))
            if isinstance(cookie_map, dict):
                session.cookies.update(cookie_map)
        except Exception:
            return

    def _save_session_cookies(self, session: requests.Session, run_dir: Path, session_name: str) -> None:
        session_path = self._session_path(run_dir, session_name)
        cookie_map = requests.utils.dict_from_cookiejar(session.cookies)
        session_path.write_text(json.dumps(cookie_map, indent=2), encoding="utf-8")

    def _build_url(self, target: str, path: str, query: Dict[str, Any]) -> str:
        base = target if target.startswith(("http://", "https://")) else f"http://{target}"
        if not path.startswith("/"):
            path = f"/{path}"
        url = f"{base.rstrip('/')}{path}"
        if query:
            encoded = urlencode(query, doseq=True)
            connector = "&" if "?" in url else "?"
            url = f"{url}{connector}{encoded}"
        return url

    def _run_browser(self, url: str, params: Dict[str, Any], timeout: int) -> Optional[Dict[str, Any]]:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return {
                "error": "Browser mode requires playwright. Install dependencies and run `playwright install chromium`.",
                "url": url,
                "navigation_url": url,
                "raw": "Browser automation unavailable",
                "browser_action": params.get("browser_action", "goto"),
            }

        browser_action = str(params.get("browser_action", "goto")).lower()
        selector = params.get("selector", "")
        value = params.get("value", "")
        wait_ms = int(params.get("wait_ms", 750))
        run_dir = Path(params.get("__run_dir", "."))
        shots_dir = run_dir / "browser_shots"
        shots_dir.mkdir(parents=True, exist_ok=True)
        shot_name = f"{int(time.time() * 1000)}_{browser_action}.png"
        screenshot_path = shots_dir / shot_name
        browser_settings = (params.get("__run_settings") or {}).get("browser", {})
        headless = bool(browser_settings.get("headless", True))

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=headless)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.set_default_timeout(timeout * 1000)

            request_url = url
            page.goto(url, wait_until="domcontentloaded")

            if browser_action == "fill" and selector:
                page.fill(selector, str(value))
            elif browser_action == "click" and selector:
                page.click(selector)
            elif browser_action == "type" and selector:
                page.type(selector, str(value))
            elif browser_action == "evaluate":
                value = str(page.evaluate(str(value or "document.body.innerText")))
            elif browser_action == "request":
                page.evaluate(
                    """async (cfg) => {
                        const init = { method: cfg.method || 'GET', headers: cfg.headers || {} };
                        if (cfg.body) init.body = cfg.body;
                        const res = await fetch(cfg.url, init);
                        const text = await res.text();
                        return { status: res.status, url: res.url, body: text.slice(0, 4000) };
                    }""",
                    {
                        "url": url,
                        "method": params.get("method", "GET"),
                        "headers": params.get("headers", {}),
                        "body": params.get("body"),
                    },
                )

            if wait_ms > 0:
                page.wait_for_timeout(wait_ms)

            title = page.title()
            content = page.content()[:5000]
            page.screenshot(path=str(screenshot_path), full_page=True)
            final_url = page.url
            browser.close()

        telemetry = {
            "transport": "browser",
            "action": browser_action,
            "selector": selector,
            "request_url": request_url,
            "final_url": final_url,
            "title": title,
            "screenshot_path": str(screenshot_path),
        }
        return {
            "method": params.get("method", "GET"),
            "url": request_url,
            "full_url": final_url,
            "status_code": 200,
            "navigation_url": final_url,
            "response_preview": content,
            "browser_action": browser_action,
            "browser_selector": selector,
            "browser_value": value if isinstance(value, str) else json.dumps(value),
            "browser_screenshot": str(screenshot_path),
            "headers": {},
            "telemetry": telemetry,
            "raw": self._format_browser_result(telemetry, content),
        }

    def _build_files(self, files: Dict[str, Any]) -> Dict[str, Any]:
        built = {}
        for field, spec in files.items():
            if isinstance(spec, dict):
                filename = spec.get("filename", f"{field}.txt")
                content = spec.get("content", "")
                content_type = spec.get("content_type", "text/plain")
                built[field] = (filename, content, content_type)
            else:
                built[field] = spec
        return built

    def _format_http_result(self, response: requests.Response, telemetry: Dict[str, Any]) -> str:
        body = response.text[:2000]
        return (
            f"[HTTP] {telemetry['method']} {telemetry['request_url']}\n"
            f"[HTTP] Status: {telemetry['status_code']}\n"
            f"[HTTP] Final URL: {telemetry['final_url']}\n\n"
            f"{body}"
        )

    def _format_browser_result(self, telemetry: Dict[str, Any], content: str) -> str:
        return (
            f"[BROWSER] Action: {telemetry['action']}\n"
            f"[BROWSER] URL: {telemetry['final_url']}\n"
            f"[BROWSER] Title: {telemetry.get('title', '')}\n"
            f"[BROWSER] Screenshot: {telemetry.get('screenshot_path', '')}\n\n"
            f"{content[:2000]}"
        )
