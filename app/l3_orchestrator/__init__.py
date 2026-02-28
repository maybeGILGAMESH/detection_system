"""L3 Orchestrator — LangGraph-based investigation state machine.

Pipeline: extract_urls → gather_evidence → judge_verdict → make_decision

Components:
  - state : InvestigationState (Pydantic model passed through nodes)
  - graph : sequential pipeline (extract → evidence → judge → decide)

Entry point: graph.run_investigation(email) → InvestigationState
"""

from app.l3_orchestrator.state import InvestigationState
from app.l3_orchestrator.graph import run_investigation

__all__ = ["InvestigationState", "run_investigation"]

