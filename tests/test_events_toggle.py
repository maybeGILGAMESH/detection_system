"""Tests for events.py and layer_toggle.py."""

import asyncio
import pytest

from app import events
from app.layer_toggle import layer_state, set_layer, get_layers, is_enabled


# --- events.py ---

@pytest.mark.asyncio
async def test_publish_and_subscribe():
    """Publish an event and receive it via subscriber queue."""
    q = await events.subscribe()
    await events.publish("test_event", "email1", "L1", {"key": "val"})

    event = q.get_nowait()
    assert event["type"] == "test_event"
    assert event["email_id"] == "email1"
    assert event["layer"] == "L1"
    assert event["data"]["key"] == "val"
    assert "ts" in event

    await events.unsubscribe(q)


@pytest.mark.asyncio
async def test_publish_without_data():
    """Publish event with no data dict."""
    q = await events.subscribe()
    await events.publish("simple", "e2", "L2")

    event = q.get_nowait()
    assert event["type"] == "simple"
    assert event["data"] == {}

    await events.unsubscribe(q)


@pytest.mark.asyncio
async def test_subscribe_unsubscribe():
    """After unsubscribing, queue should no longer receive events."""
    q = await events.subscribe()
    await events.unsubscribe(q)
    await events.publish("after_unsub", "e3", "L3")
    assert q.empty()


@pytest.mark.asyncio
async def test_unsubscribe_nonexistent():
    """Unsubscribing a queue not in the list should not raise."""
    fake_q = asyncio.Queue()
    await events.unsubscribe(fake_q)


@pytest.mark.asyncio
async def test_get_history():
    """Published events should appear in history."""
    events._history.clear()
    await events.publish("hist_event", "h1", "L1", {"x": 1})
    history = events.get_history()
    assert len(history) >= 1
    assert history[-1]["type"] == "hist_event"


@pytest.mark.asyncio
async def test_cot_tokens_not_in_history():
    """l3_cot_token events should NOT be stored in history."""
    events._history.clear()
    await events.publish("l3_cot_token", "c1", "L3", {"token": "a"})
    history = events.get_history()
    cot_events = [e for e in history if e["type"] == "l3_cot_token"]
    assert len(cot_events) == 0


@pytest.mark.asyncio
async def test_full_queue_drops_dead():
    """When a subscriber queue is full, it's removed from subscribers."""
    q = asyncio.Queue(maxsize=1)
    async with events._lock:
        events._subscribers.append(q)

    q.put_nowait({"dummy": True})
    await events.publish("overflow", "o1", "L1", {"data": "big"})

    async with events._lock:
        assert q not in events._subscribers


def test_make_event():
    """Test internal _make_event function."""
    event = events._make_event("test", "eid", "L2", {"foo": "bar"})
    assert event["type"] == "test"
    assert event["email_id"] == "eid"
    assert event["layer"] == "L2"
    assert event["data"]["foo"] == "bar"


def test_make_event_no_data():
    event = events._make_event("test", "eid", "L2")
    assert event["data"] == {}


# --- layer_toggle.py ---

def test_set_layer_enable_disable():
    set_layer("L1", False)
    assert not is_enabled("L1")
    set_layer("L1", True)
    assert is_enabled("L1")


def test_set_layer_unknown():
    result = set_layer("L99", True)
    assert result is False


def test_get_layers():
    layers = get_layers()
    assert "L1" in layers
    assert "L2" in layers
    assert "L3" in layers
    assert isinstance(layers["L1"], bool)


def test_is_enabled_default():
    assert is_enabled("NONEXISTENT") is True


def test_set_layer_returns_true():
    assert set_layer("L2", True) is True
    assert set_layer("L3", False) is True
    set_layer("L3", True)
