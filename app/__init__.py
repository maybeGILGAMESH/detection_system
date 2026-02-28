"""Detect Email — AI-powered multi-layer phishing detection system.

Architecture (from UML):
  L1: Threat Intel   → URL/IP/domain reputation (VirusTotal, PhishTank, OpenPhish, AbuseIPDB)
  L2: Classifier     → DistilBERT text classification (phishing / safe)
  L3: Orchestrator   → LangGraph state machine (Evidence Agent + DeepSeek Judge)

Gateway:
  aiosmtpd SMTP server (port 1025) + FastAPI REST API (port 8000)
"""

__version__ = "1.0.0"
__author__ = "Detect Email Team"

