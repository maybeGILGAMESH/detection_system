"""Tests for operator_store — CRUD operations and file persistence."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from app.schemas import (
    Label, OperatorDecision, ParsedEmail, L2Result, JudgeVerdict, Verdict,
)
from app import operator_store


@pytest.fixture(autouse=True)
def _reset_store(tmp_path):
    """Reset operator_store state and use a temp directory for each test."""
    operator_store._pending = {}
    operator_store._decisions = []
    operator_store._inbox = []
    operator_store._loaded = True  # skip lazy-load from real files

    operator_store._DATA_DIR = tmp_path
    operator_store._PENDING_FILE = tmp_path / "operator_pending.json"
    operator_store._DECISIONS_FILE = tmp_path / "operator_decisions.json"
    operator_store._INBOX_FILE = tmp_path / "user_inbox.json"

    yield


def _make_email(**kwargs) -> ParsedEmail:
    defaults = dict(
        sender="test@example.com",
        recipient="user@example.com",
        subject="Test",
        body="Test body",
    )
    defaults.update(kwargs)
    return ParsedEmail(**defaults)


class TestPending:
    def test_add_and_get_pending(self):
        email = _make_email()
        l2 = L2Result(confidence=0.55, label=Label.SAFE)
        operator_store.add_pending("e1", email, l2_result=l2)

        pending = operator_store.get_pending()
        assert len(pending) == 1
        assert pending[0].email_id == "e1"
        assert pending[0].l2_confidence == pytest.approx(0.55, abs=0.001)

    def test_pending_persisted_to_file(self, tmp_path):
        email = _make_email()
        operator_store.add_pending("e2", email)

        data = json.loads((tmp_path / "operator_pending.json").read_text())
        assert "e2" in data

    def test_resolve_pending(self):
        email = _make_email(subject="Suspicious")
        operator_store.add_pending("e3", email)

        decision = OperatorDecision(
            email_id="e3", operator_label=Label.PHISHING, comment="Obvious scam"
        )
        ok = operator_store.resolve_pending(decision)
        assert ok is True
        assert len(operator_store.get_pending()) == 0
        assert operator_store.get_decision_count() == 1

    def test_resolve_nonexistent_returns_false(self):
        decision = OperatorDecision(
            email_id="missing", operator_label=Label.SAFE
        )
        ok = operator_store.resolve_pending(decision)
        assert ok is False


class TestDecisions:
    def test_decisions_accumulate(self):
        email = _make_email()
        for i in range(3):
            eid = f"e{i}"
            operator_store.add_pending(eid, email)
            operator_store.resolve_pending(
                OperatorDecision(email_id=eid, operator_label=Label.PHISHING)
            )
        assert operator_store.get_decision_count() == 3

    def test_clear_decisions(self):
        email = _make_email()
        operator_store.add_pending("e1", email)
        operator_store.resolve_pending(
            OperatorDecision(email_id="e1", operator_label=Label.SAFE)
        )
        assert operator_store.get_decision_count() == 1

        operator_store.clear_decisions()
        assert operator_store.get_decision_count() == 0


class TestInbox:
    def test_add_to_inbox(self):
        email = _make_email()
        operator_store.add_to_inbox("e1", email, Verdict.DELIVER, "Summary", "Safe")

        items = operator_store.get_inbox()
        assert len(items) == 1
        assert items[0].email_id == "e1"
        assert items[0].summary == "Summary"

    def test_inbox_limit(self):
        email = _make_email()
        for i in range(250):
            operator_store.add_to_inbox(f"e{i}", email, Verdict.DELIVER)

        # Internal store capped at 200
        assert len(operator_store._inbox) == 200

    def test_clear_inbox(self):
        email = _make_email()
        operator_store.add_to_inbox("e1", email, Verdict.DELIVER)
        operator_store.clear_inbox()
        assert len(operator_store.get_inbox()) == 0
