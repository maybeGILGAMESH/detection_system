"""Real-time event bus for broadcasting processing events to WebSocket clients.

All AI layers publish events here; the dashboard consumes them via WebSocket.
"""

import asyncio
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

# All connected WebSocket clients
_subscribers: list[asyncio.Queue] = []
_lock = asyncio.Lock()

# History buffer (last N events for new clients)
_history: list[dict] = []
_HISTORY_MAX = 200


def _make_event(
    event_type: str,
    email_id: str = "",
    layer: str = "",
    data: dict[str, Any] | None = None,
) -> dict:
    """Create a structured event dict."""
    return {
        "ts": time.time(),
        "type": event_type,
        "email_id": email_id,
        "layer": layer,
        "data": data or {},
    }


async def publish(
    event_type: str,
    email_id: str = "",
    layer: str = "",
    data: dict[str, Any] | None = None,
):
    """Publish an event to all connected WebSocket clients."""
    event = _make_event(event_type, email_id, layer, data)

    # Add to history (skip CoT tokens — too many, would bloat history)
    if event_type != "l3_cot_token":
        _history.append(event)
        if len(_history) > _HISTORY_MAX:
            _history.pop(0)

    # Broadcast to subscribers
    async with _lock:
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)


async def subscribe() -> asyncio.Queue:
    """Subscribe to events. Returns a queue to read from."""
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    async with _lock:
        _subscribers.append(q)
    return q


async def unsubscribe(q: asyncio.Queue):
    """Unsubscribe from events."""
    async with _lock:
        if q in _subscribers:
            _subscribers.remove(q)


def get_history() -> list[dict]:
    """Get recent event history (for new clients catching up)."""
    return list(_history)

