"""Simple in-memory TTL cache for L1 checker results.

Avoids hitting external APIs repeatedly for the same URL/IP/domain
within a short window.
"""

import time
from typing import Any

_DEFAULT_TTL = 600  # 10 minutes

_store: dict[str, tuple[float, Any]] = {}


def get(key: str) -> Any | None:
    """Return cached value if it exists and hasn't expired, else None."""
    entry = _store.get(key)
    if entry is None:
        return None
    expires_at, value = entry
    if time.monotonic() > expires_at:
        _store.pop(key, None)
        return None
    return value


def put(key: str, value: Any, ttl: float = _DEFAULT_TTL) -> None:
    """Store a value with a TTL (seconds)."""
    _store[key] = (time.monotonic() + ttl, value)


def make_key(source: str, indicator: str) -> str:
    """Build a cache key from the checker source and indicator."""
    return f"{source}:{indicator.lower().strip()}"
