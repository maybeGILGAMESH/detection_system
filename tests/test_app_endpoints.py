"""Tests for main.py — all FastAPI endpoints via TestClient."""

import json
import pytest
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture(scope="module")
def client():
    """Create a TestClient with mocked heavy dependencies in lifespan."""
    mock_ctrl = MagicMock()
    with patch("app.gateway.smtp_handler.start_smtp_server", return_value=mock_ctrl), \
         patch("app.l2_classifier.service.load_model"), \
         patch("app.l1_threat_intel.checkers.http_client.close_client", new_callable=AsyncMock):
        from starlette.testclient import TestClient
        from app.main import app
        with TestClient(app) as c:
            yield c


def test_favicon(client):
    r = client.get("/favicon.ico")
    assert r.status_code == 200
    assert "svg" in r.headers["content-type"]


def test_dashboard(client):
    r = client.get("/")
    assert r.status_code == 200


def test_api_info(client):
    r = client.get("/api/info")
    assert r.status_code == 200
    data = r.json()
    assert "architecture" in data
    assert "L1" in data["architecture"]


def test_get_layers(client):
    r = client.get("/api/v1/layers")
    assert r.status_code == 200
    data = r.json()
    assert "L1" in data
    assert "L2" in data
    assert "L3" in data


def test_set_layer_state(client):
    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/layers", json={"layer": "L1", "enabled": False})
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"

    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/layers", json={"layer": "L1", "enabled": True})
        assert r.status_code == 200


def test_set_layer_state_unknown(client):
    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/layers", json={"layer": "L99", "enabled": True})
        assert r.status_code == 200
        assert "error" in r.json()


def test_events_history(client):
    r = client.get("/api/events/history")
    assert r.status_code == 200
    assert "events" in r.json()


def test_operator_pending(client):
    r = client.get("/api/v1/operator/pending")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data
    assert "items" in data


def test_operator_decisions(client):
    r = client.get("/api/v1/operator/decisions")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data


def test_operator_decide_not_found(client):
    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/operator/decide", json={
            "email_id": "nonexistent",
            "operator_label": "phishing",
            "comment": "test",
        })
        assert r.status_code == 200
        data = r.json()
        assert "error" in data


def test_operator_decide_success(client):
    from app import operator_store
    from app.schemas import ParsedEmail, L2Result, JudgeVerdict, Label, Verdict

    email = ParsedEmail(sender="a@b.com", subject="Test", body="Hello")
    l2 = L2Result(confidence=0.5, label=Label.SAFE)
    j = JudgeVerdict(
        verdict=Label.UNCERTAIN, confidence=0.5,
        reasoning="unclear", recommended_action=Verdict.OPERATOR_REVIEW,
    )
    operator_store.add_pending("test123", email, l2, j, "")

    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/operator/decide", json={
            "email_id": "test123",
            "operator_label": "phishing",
            "comment": "clearly phishing",
        })
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "ok"


def test_operator_retrain_not_enough(client):
    from app import operator_store
    operator_store.clear_decisions()
    with patch("app.main.events.publish", new_callable=AsyncMock):
        r = client.post("/api/v1/operator/retrain")
        assert r.status_code == 200
        assert "error" in r.json()


def test_operator_retrain_start(client):
    from app import operator_store
    operator_store.clear_decisions()
    for i in range(6):
        operator_store._decisions.append({
            "email_id": f"e{i}", "subject": "Test", "body": "Body",
            "operator_label": "phishing",
        })

    with patch("app.main.events.publish", new_callable=AsyncMock), \
         patch("subprocess.Popen") as mock_popen:
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.poll.return_value = None
        mock_popen.return_value = mock_proc
        r = client.post("/api/v1/operator/retrain")
        assert r.status_code == 200
        data = r.json()
        assert data.get("status") == "started"

    operator_store.clear_decisions()


def test_user_inbox(client):
    r = client.get("/api/v1/inbox")
    assert r.status_code == 200
    data = r.json()
    assert "count" in data
    assert "items" in data


def test_clear_inbox(client):
    r = client.post("/api/v1/inbox/clear")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_websocket_endpoint(client):
    from app import events
    events._history.append(events._make_event("test_ws", "e1", "L1", {"ok": True}))

    with client.websocket_connect("/ws") as ws:
        data = ws.receive_text()
        parsed = json.loads(data)
        assert parsed["type"] == "history"
        assert len(parsed["events"]) >= 1


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "layers" in data


def test_check_retrain_completed():
    """Test _check_retrain when process completes successfully."""
    import asyncio
    from app.main import _check_retrain

    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    with patch("app.l2_classifier.service._model", None), \
         patch("app.l2_classifier.service._tokenizer", None), \
         patch("app.l2_classifier.service.load_model"), \
         patch("app.main.operator_store.clear_decisions"):
        _check_retrain(mock_proc)

    loop.close()


def test_check_retrain_failed():
    """Test _check_retrain when process fails."""
    import asyncio
    from app.main import _check_retrain

    mock_proc = MagicMock()
    mock_proc.poll.return_value = 1

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    _check_retrain(mock_proc)
    loop.close()


def test_check_retrain_still_running():
    """Test _check_retrain when process is still running."""
    import asyncio
    from app.main import _check_retrain

    mock_proc = MagicMock()
    mock_proc.poll.return_value = None

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        _check_retrain(mock_proc)
    except Exception:
        pass
    loop.close()
