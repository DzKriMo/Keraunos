import asyncio
import json
from typing import Any, Dict, List

import websockets

from tool_wrappers.base import ToolWrapper


class WebSocketInteractWrapper(ToolWrapper):
    """Interact with WebSocket endpoints for auth and message-flow testing."""

    tool_name = "websocket_interact"
    risk_level = "medium"

    def run(self, params: dict) -> dict:
        url = params.get("url")
        if not url:
            target = params.get("target")
            path = params.get("path", "/ws")
            if not target:
                raise ValueError("websocket_interact requires url or target")
            base = target if target.startswith(("ws://", "wss://")) else f"ws://{target}"
            if not path.startswith("/"):
                path = f"/{path}"
            url = f"{base.rstrip('/')}{path}"

        messages = params.get("messages", [])
        if isinstance(messages, (str, dict)):
            messages = [messages]
        timeout = int(params.get("timeout", 15))
        headers = params.get("headers", {}) or {}
        if not messages:
            messages = ["dump_state", json.dumps({"action": "dump_state"})]

        try:
            result = asyncio.run(self._exchange(url, messages, timeout, headers))
        except Exception as exc:
            result = {
                "url": url,
                "messages_sent": messages,
                "messages_received": [],
                "status": "error",
                "error": str(exc),
            }
        result["navigation_url"] = self._browser_friendly_url(url)
        result["raw"] = json.dumps(result, indent=2)
        return result

    async def _exchange(self, url: str, messages: List[Any], timeout: int, headers: Dict[str, Any]) -> Dict[str, Any]:
        received = []
        origin = headers.get("Origin") or self._browser_friendly_url(url)
        connect_kwargs = {
            "open_timeout": timeout,
            "close_timeout": timeout,
            "origin": origin,
        }
        if headers:
            connect_kwargs["additional_headers"] = headers

        async with websockets.connect(url, **connect_kwargs) as ws:
            try:
                banner = await asyncio.wait_for(ws.recv(), timeout=1)
                received.append(banner)
            except asyncio.TimeoutError:
                pass
            for item in messages:
                payload = json.dumps(item) if isinstance(item, dict) else str(item)
                await ws.send(payload)
                try:
                    reply = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    received.append(reply)
                except asyncio.TimeoutError:
                    received.append("<timeout>")
            return {
                "url": url,
                "messages_sent": messages,
                "messages_received": received,
                "status": "connected",
            }

    def _browser_friendly_url(self, url: str) -> str:
        if url.startswith("wss://"):
            return "https://" + url[len("wss://"):]
        if url.startswith("ws://"):
            return "http://" + url[len("ws://"):]
        return url
