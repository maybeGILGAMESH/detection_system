"""Operator review store — persists emails awaiting human review and decisions.

Also manages user inbox with delivered emails and AI summaries.
Stores in a simple JSON file for the diploma demo; swap for PostgreSQL later.
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

from app.schemas import (
    Label, OperatorDecision, OperatorPendingItem,
    InboxItem, Verdict, ParsedEmail, JudgeVerdict, L2Result,
)

logger = logging.getLogger(__name__)

_DATA_DIR = Path("./data")
_PENDING_FILE = _DATA_DIR / "operator_pending.json"
_DECISIONS_FILE = _DATA_DIR / "operator_decisions.json"
_INBOX_FILE = _DATA_DIR / "user_inbox.json"

# In-memory caches
_pending: dict[str, dict] = {}
_decisions: list[dict] = []
_inbox: list[dict] = []

_loaded = False


def _ensure_dir():
    _DATA_DIR.mkdir(parents=True, exist_ok=True)


def _load():
    global _pending, _decisions, _inbox, _loaded
    if _loaded:
        return
    _ensure_dir()

    if _PENDING_FILE.exists():
        try:
            _pending = json.loads(_PENDING_FILE.read_text(encoding="utf-8"))
        except Exception:
            _pending = {}

    if _DECISIONS_FILE.exists():
        try:
            _decisions = json.loads(_DECISIONS_FILE.read_text(encoding="utf-8"))
        except Exception:
            _decisions = []

    if _INBOX_FILE.exists():
        try:
            _inbox = json.loads(_INBOX_FILE.read_text(encoding="utf-8"))
        except Exception:
            _inbox = []

    _loaded = True


def _save_pending():
    _ensure_dir()
    _PENDING_FILE.write_text(json.dumps(_pending, ensure_ascii=False, indent=2), encoding="utf-8")


def _save_decisions():
    _ensure_dir()
    _DECISIONS_FILE.write_text(json.dumps(_decisions, ensure_ascii=False, indent=2), encoding="utf-8")


def _save_inbox():
    _ensure_dir()
    _INBOX_FILE.write_text(json.dumps(_inbox, ensure_ascii=False, indent=2), encoding="utf-8")


# -- Operator Pending --

def add_pending(
    email_id: str,
    email: ParsedEmail,
    l2_result: Optional[L2Result] = None,
    l3_verdict: Optional[JudgeVerdict] = None,
    evidence_summary: str = "",
):
    """Add an email to the operator review queue."""
    _load()
    item = {
        "email_id": email_id,
        "sender": email.sender,
        "recipient": email.recipient,
        "subject": email.subject,
        "body_preview": email.body[:500] if email.body else "",
        "full_body": email.body,
        "urls": email.urls[:10],
        "l2_confidence": round(l2_result.confidence, 4) if l2_result else 0.0,
        "l3_confidence": round(l3_verdict.confidence, 2) if l3_verdict else 0.0,
        "l3_reasoning": l3_verdict.reasoning if l3_verdict else "",
        "evidence_summary": evidence_summary,
        "timestamp": time.time(),
    }
    _pending[email_id] = item
    _save_pending()
    logger.info("Added email %s to operator review queue (total: %d)", email_id, len(_pending))


def get_pending() -> list[OperatorPendingItem]:
    """Get all emails pending operator review."""
    _load()
    return [OperatorPendingItem(**v) for v in _pending.values()]


def resolve_pending(decision: OperatorDecision) -> bool:
    """Operator resolves an email: mark as phishing or safe."""
    _load()
    if decision.email_id not in _pending:
        return False

    pending_item = _pending.pop(decision.email_id)
    _save_pending()

    # Store the decision for future retraining
    record = {
        "email_id": decision.email_id,
        "operator_label": decision.operator_label.value,
        "comment": decision.comment,
        "subject": pending_item.get("subject", ""),
        "body": pending_item.get("full_body", pending_item.get("body_preview", "")),
        "sender": pending_item.get("sender", ""),
        "timestamp": time.time(),
    }
    _decisions.append(record)
    _save_decisions()

    logger.info(
        "Operator resolved %s as %s (%d decisions total)",
        decision.email_id, decision.operator_label.value, len(_decisions),
    )
    return True


def get_decisions() -> list[dict]:
    """Get all operator decisions (for retraining)."""
    _load()
    return list(_decisions)


def get_decision_count() -> int:
    _load()
    return len(_decisions)


def clear_decisions():
    """Clear decisions after retraining."""
    global _decisions
    _decisions = []
    _save_decisions()


# -- User Inbox --

def add_to_inbox(
    email_id: str,
    email: ParsedEmail,
    action: Verdict,
    summary: str = "",
    safety_note: str = "",
):
    """Add an email to the user's inbox."""
    _load()
    item = {
        "email_id": email_id,
        "sender": email.sender,
        "subject": email.subject,
        "body_preview": email.body[:300] if email.body else "",
        "summary": summary,
        "safety_note": safety_note,
        "action": action.value,
        "timestamp": time.time(),
    }
    _inbox.append(item)
    # Keep last 200 emails
    if len(_inbox) > 200:
        _inbox[:] = _inbox[-200:]
    _save_inbox()


def get_inbox(limit: int = 50) -> list[InboxItem]:
    """Get recent inbox items."""
    _load()
    items = _inbox[-limit:]
    items.reverse()
    return [InboxItem(**i) for i in items]


def clear_inbox():
    global _inbox
    _inbox = []
    _save_inbox()

