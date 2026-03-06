"""Async event bus for broadcasting orchestrator events to WebSocket clients."""

import asyncio
import json
import time
from typing import Any, Dict, Set


class EventBus:
    """Thread-safe event bus that bridges the synchronous orchestrator with async WebSocket clients."""

    def __init__(self):
        self._subscribers: Set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._history: list = []  # Keep last 200 events for late-joining clients
        self._pending_confirmation: dict | None = None
        self._confirmation_event: asyncio.Event | None = None
        self._confirmation_result: bool = False

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self._subscribers.discard(queue)

    def emit(self, event_type: str, payload: Dict[str, Any] | None = None):
        """Emit an event from any thread. Safe to call from sync orchestrator code."""
        event = {
            "type": event_type,
            "timestamp": time.time(),
            "data": payload or {},
        }
        self._history.append(event)
        if len(self._history) > 200:
            self._history = self._history[-200:]

        if self._loop and not self._loop.is_closed():
            self._loop.call_soon_threadsafe(self._dispatch, event)

    def _dispatch(self, event: dict):
        dead = set()
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                dead.add(queue)
        self._subscribers -= dead

    def get_history(self) -> list:
        return list(self._history)

    # ── Confirmation flow ──────────────────────────────────────────
    async def request_confirmation(self, description: str, tool: str, params: dict) -> bool:
        """Request confirmation from a dashboard client. Called from the orchestrator thread via async bridge."""
        self._confirmation_event = asyncio.Event()
        self._confirmation_result = False
        self._pending_confirmation = {
            "description": description,
            "tool": tool,
            "params": params,
        }
        self.emit("confirmation_required", self._pending_confirmation)
        await self._confirmation_event.wait()
        self._pending_confirmation = None
        return self._confirmation_result

    def resolve_confirmation(self, approved: bool):
        """Called when a client responds to the confirmation prompt."""
        self._confirmation_result = approved
        if self._confirmation_event:
            if self._loop:
                self._loop.call_soon_threadsafe(self._confirmation_event.set)

    @property
    def pending_confirmation(self):
        return self._pending_confirmation


# Global singleton
event_bus = EventBus()
