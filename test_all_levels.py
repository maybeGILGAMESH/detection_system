#!/usr/bin/env python3
"""
Comprehensive test script for Detect Email — all 3 AI layers.

Usage:
  python test_all_levels.py          # run all tests
  python test_all_levels.py l1       # test L1 only
  python test_all_levels.py l2       # test L2 only
  python test_all_levels.py l3       # test L3 only
  python test_all_levels.py cascade  # test full cascade

Requires the server to be running on http://localhost:8000
"""

import os
import sys
import json
import time

# Bypass VPN/proxy for localhost requests
os.environ["NO_PROXY"] = "localhost,127.0.0.1"

import httpx

BASE = "http://localhost:8000"
TIMEOUT = 120  # L3 with DeepSeek can be slow

# httpx client that ignores proxy for local connections
_client = httpx.Client(timeout=TIMEOUT, trust_env=False)


def header(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def result_line(label: str, value, ok: bool = True):
    icon = "✅" if ok else "❌"
    print(f"  {icon} {label}: {value}")


def pp_json(data: dict, indent: int = 4):
    """Pretty-print JSON with colors in terminal."""
    print(json.dumps(data, indent=indent, ensure_ascii=False))


# -----------------------------------------------------------------------
# Test 0: Health check
# -----------------------------------------------------------------------
def test_health():
    header("TEST 0: Health Check")
    try:
        r = _client.get(f"{BASE}/health")
        data = r.json()
        result_line("Status", data.get("status"), data.get("status") == "ok")
        result_line("L2 model loaded", data.get("l2_loaded"), True)
        result_line("L3 model loaded", data.get("l3_loaded"), True)
        return True
    except Exception as e:
        print(f"  ❌ Server not reachable: {e}")
        print("  ⚠️  Start the server first: python -m app.main")
        return False


# -----------------------------------------------------------------------
# Test 1: L1 Threat Intel
# -----------------------------------------------------------------------
def test_l1():
    header("TEST 1: L1 Threat Intel")

    # --- Test 1a: Clean URLs (should pass) ---
    print("\n  --- 1a: Clean URL (google.com) ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l1/check", json={
        "urls": ["https://www.google.com"],
        "ips": [],
        "domains": ["google.com"],
    })
    elapsed = time.time() - t0
    data = r.json()
    verdict = data.get("verdict")
    result_line("Verdict", verdict, verdict == "PROCEED")
    result_line("Time", f"{elapsed:.2f}s", True)
    checks = data.get("results", [])
    for c in checks:
        mal = c.get("is_malicious", False)
        result_line(f"  {c['source']}", c.get("detail", ""), not mal)

    # --- Test 1b: Suspicious domain ---
    print("\n  --- 1b: Suspicious domain (phishing-test.xyz) ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l1/check", json={
        "urls": ["http://phishing-test.xyz/login"],
        "ips": [],
        "domains": ["phishing-test.xyz"],
    })
    elapsed = time.time() - t0
    data = r.json()
    verdict = data.get("verdict")
    result_line("Verdict", verdict, True)  # Could be PROCEED or REJECT
    result_line("Time", f"{elapsed:.2f}s", True)
    checks = data.get("results", [])
    for c in checks:
        result_line(f"  {c['source']}", c.get("detail", ""), True)

    # --- Test 1c: Empty input (should pass trivially) ---
    print("\n  --- 1c: Empty input (no URLs/IPs/domains) ---")
    r = _client.post(f"{BASE}/api/v1/l1/check", json={
        "urls": [], "ips": [], "domains": [],
    })
    data = r.json()
    verdict = data.get("verdict")
    result_line("Verdict", verdict, verdict == "PROCEED")
    result_line("Results count", len(data.get("results", [])), True)

    pp_json(data)


def test_l2():
    header("TEST 2: L2 DistilBERT Classifier")

    # --- Test 2a: Obviously phishing ---
    print("\n  --- 2a: Obvious phishing email ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l2/classify", json={
        "subject": "URGENT: Your account has been compromised!",
        "body": (
            "Dear Customer, We have detected unauthorized access to your account. "
            "Your account will be suspended within 24 hours unless you verify your identity. "
            "Click here immediately to verify: http://secure-verify-account.xyz/login "
            "If you do not act now, all your data will be permanently deleted. "
            "Enter your password and credit card details to confirm your identity."
        ),
    })
    elapsed = time.time() - t0
    data = r.json()
    label = data.get("label")
    confidence = data.get("confidence", 0)
    result_line("Label", label, label == "phishing")
    result_line("Confidence (safe)", f"{confidence:.4f}", confidence < 0.4)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- Test 2b: Obviously safe ---
    print("\n  --- 2b: Clearly safe business email ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l2/classify", json={
        "subject": "Meeting notes from today's standup",
        "body": (
            "Hi team, Here are the notes from today's standup meeting. "
            "1. Backend API is on track for Friday deployment. "
            "2. Frontend team completed the dashboard redesign. "
            "3. QA will start regression testing tomorrow. "
            "4. Next sprint planning is scheduled for Monday at 10 AM. "
            "Let me know if I missed anything. Best regards, Alex"
        ),
    })
    elapsed = time.time() - t0
    data = r.json()
    label = data.get("label")
    confidence = data.get("confidence", 0)
    result_line("Label", label, label == "safe")
    result_line("Confidence (safe)", f"{confidence:.4f}", confidence > 0.5)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- Test 2c: Ambiguous / grey-zone ---
    print("\n  --- 2c: Ambiguous email (could trigger grey zone) ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l2/classify", json={
        "subject": "Your order has been shipped",
        "body": (
            "Hello, Your recent order #38291 has been shipped and is on its way. "
            "You can track your package using the following link: "
            "http://track-delivery-status.com/track?id=38291 "
            "Expected delivery: March 3, 2026. "
            "If you have any questions, please contact our support team. "
            "Thank you for your purchase!"
        ),
    })
    elapsed = time.time() - t0
    data = r.json()
    label = data.get("label")
    confidence = data.get("confidence", 0)
    result_line("Label", label, True)
    result_line("Confidence (safe)", f"{confidence:.4f}", True)
    zone = "SAFE ZONE (>0.9)" if confidence > 0.9 else \
           "PHISH ZONE (<0.4)" if confidence < 0.4 else \
           "GREY ZONE (0.4-0.9) → would trigger L3!"
    result_line("Zone", zone, True)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- Test 2d: Russian phishing ---
    print("\n  --- 2d: Russian phishing email ---")
    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/l2/classify", json={
        "subject": "Срочно: Подтвердите вашу учетную запись",
        "body": (
            "Уважаемый клиент! Мы обнаружили подозрительную активность на вашем счете. "
            "Пожалуйста, немедленно подтвердите свою личность, перейдя по ссылке: "
            "http://bank-verify-ru.xyz/confirm "
            "Если вы не подтвердите в течение 12 часов, ваш счет будет заблокирован. "
            "Введите логин, пароль и данные карты для верификации."
        ),
    })
    elapsed = time.time() - t0
    data = r.json()
    label = data.get("label")
    confidence = data.get("confidence", 0)
    result_line("Label", label, True)
    result_line("Confidence (safe)", f"{confidence:.4f}", True)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- Test 2e: Empty body ---
    print("\n  --- 2e: Empty body (edge case) ---")
    r = _client.post(f"{BASE}/api/v1/l2/classify", json={
        "subject": "",
        "body": "",
    })
    data = r.json()
    result_line("Label", data.get("label"), True)
    result_line("Confidence", data.get("confidence"), True)


def test_l3():
    header("TEST 3: L3 Deep Investigation (Evidence + Judge)")

    print("\n  --- 3a: Direct L3 investigation via /api/v1/l3/investigate ---")
    print("  ⏳ This may take a while (evidence gathering + DeepSeek inference)...\n")

    payload = {
        "email": {
            "sender": "security@acc0unt-verify.xyz",
            "recipient": "victim@company.com",
            "subject": "Action Required: Verify your credentials",
            "body": (
                "Dear user, We noticed unusual sign-in activity on your account. "
                "For security purposes, please verify your identity by clicking the link below: "
                "http://acc0unt-verify.xyz/secure-login "
                "This link will expire in 2 hours. Failure to verify may result in account suspension. "
                "Thank you, Security Team"
            ),
            "urls": ["http://acc0unt-verify.xyz/secure-login"],
            "domains": ["acc0unt-verify.xyz"],
            "ips": [],
            "html_body": "",
            "message_id": "test-l3-001",
            "raw": "",
        }
    }

    t0 = time.time()
    try:
        r = _client.post(
            f"{BASE}/api/v1/l3/investigate",
            json=payload,
        )
        elapsed = time.time() - t0
        data = r.json()

        result_line("HTTP Status", r.status_code, r.status_code == 200)
        result_line("Action", data.get("action"), True)
        result_line("Verdict", data.get("verdict_label"), True)
        result_line("Confidence", f"{data.get('confidence', 0):.2f}", True)
        result_line("Evidence bundles", data.get("evidence_count", 0), True)
        result_line("Time", f"{elapsed:.2f}s", True)

        if data.get("reasoning"):
            print(f"\n  📝 Judge Reasoning:\n  {data['reasoning'][:500]}")

        if data.get("error"):
            print(f"\n  ⚠️  Error: {data['error']}")

        print("\n  Full response:")
        pp_json(data)

    except httpx.ReadTimeout:
        elapsed = time.time() - t0
        print(f"  ⏱️  Timeout after {elapsed:.1f}s — L3 Judge (DeepSeek 14B) needs more time")
        print("  💡 Try increasing TIMEOUT or check GPU memory")
    except Exception as e:
        print(f"  ❌ Error: {e}")


def test_cascade():
    header("TEST 4: Full Cascade (L1 → L2 → L3)")

    # --- 4a: Should be caught at L2 (obvious phishing) ---
    print("\n  --- 4a: Obvious phishing → expect L2 REJECT ---")
    payload = {
        "sender": "admin@paypa1-security.com",
        "recipient": "user@company.com",
        "subject": "Your PayPal account has been limited",
        "body": (
            "We've noticed unusual activity in your PayPal account. "
            "Your account access has been limited until you confirm your identity. "
            "Click here to restore access: http://paypa1-security.com/restore "
            "You must verify within 24 hours or your account will be permanently closed. "
            "Enter your email, password, SSN, and credit card to verify."
        ),
        "urls": ["http://paypa1-security.com/restore"],
        "domains": ["paypa1-security.com"],
        "ips": [],
        "html_body": "",
        "message_id": "cascade-test-001",
        "raw": "",
    }

    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/process", json=payload)
    elapsed = time.time() - t0
    data = r.json()

    result_line("Final Action", data.get("action"), data.get("action") == "REJECT")
    result_line("Detail", data.get("detail"), True)
    result_line("L1 verdict", data.get("l1_result", {}).get("verdict"), True)
    l2 = data.get("l2_result")
    if l2:
        result_line("L2 label", l2.get("label"), True)
        result_line("L2 confidence", f"{l2.get('confidence', 0):.4f}", True)
    result_line("L3 triggered", data.get("l3_verdict") is not None, True)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- 4b: Safe business email → expect DELIVER ---
    print("\n  --- 4b: Safe email → expect DELIVER ---")
    payload = {
        "sender": "alex.johnson@company.com",
        "recipient": "team@company.com",
        "subject": "Q1 Report ready for review",
        "body": (
            "Hi everyone, The Q1 financial report is ready for review. "
            "Key highlights: Revenue up 15% YoY, new customer acquisitions increased by 22%. "
            "The full report is attached. Please review before Friday's board meeting. "
            "Let me know if you have any questions. Best, Alex"
        ),
        "urls": [],
        "domains": [],
        "ips": [],
        "html_body": "",
        "message_id": "cascade-test-002",
        "raw": "",
    }

    t0 = time.time()
    r = _client.post(f"{BASE}/api/v1/process", json=payload)
    elapsed = time.time() - t0
    data = r.json()

    result_line("Final Action", data.get("action"), data.get("action") == "DELIVER")
    result_line("Detail", data.get("detail"), True)
    l2 = data.get("l2_result")
    if l2:
        result_line("L2 label", l2.get("label"), True)
        result_line("L2 confidence", f"{l2.get('confidence', 0):.4f}", True)
    result_line("L3 triggered", data.get("l3_verdict") is not None, True)
    result_line("Time", f"{elapsed:.2f}s", True)

    # --- 4c: Grey-zone email → should trigger L3 ---
    print("\n  --- 4c: Ambiguous email → grey zone → L3 investigation ---")
    print("  ⏳ If grey zone is hit, this will take longer (DeepSeek inference)...\n")
    payload = {
        "sender": "notifications@dropbox-share.net",
        "recipient": "user@company.com",
        "subject": "Someone shared a document with you",
        "body": (
            "Hi, A document has been shared with you via our file sharing service. "
            "Document: 'Project_Proposal_2026.pdf' "
            "Shared by: colleague@partner-company.com "
            "Click to view: http://dropbox-share.net/view/doc/abc123 "
            "This link will expire in 7 days. "
            "If you were not expecting this, you can safely ignore this email."
        ),
        "urls": ["http://dropbox-share.net/view/doc/abc123"],
        "domains": ["dropbox-share.net"],
        "ips": [],
        "html_body": "",
        "message_id": "cascade-test-003",
        "raw": "",
    }

    t0 = time.time()
    try:
        r = _client.post(f"{BASE}/api/v1/process", json=payload)
        elapsed = time.time() - t0
        data = r.json()

        result_line("Final Action", data.get("action"), True)
        result_line("Detail", data.get("detail"), True)
        result_line("L1 verdict", data.get("l1_result", {}).get("verdict"), True)
        l2 = data.get("l2_result")
        if l2:
            conf = l2.get("confidence", 0)
            result_line("L2 label", l2.get("label"), True)
            result_line("L2 confidence", f"{conf:.4f}", True)
            zone = "SAFE" if conf > 0.9 else "PHISH" if conf < 0.4 else "GREY → L3"
            result_line("L2 Zone", zone, True)

        l3 = data.get("l3_verdict")
        result_line("L3 triggered", l3 is not None, True)
        if l3:
            result_line("L3 verdict", l3.get("verdict"), True)
            result_line("L3 confidence", f"{l3.get('confidence', 0):.2f}", True)
            if l3.get("reasoning"):
                print(f"\n  📝 Judge Reasoning:\n  {l3['reasoning'][:500]}")

        result_line("Time", f"{elapsed:.2f}s", True)

        print("\n  Full response:")
        pp_json(data)

    except httpx.ReadTimeout:
        elapsed = time.time() - t0
        print(f"  ⏱️  Timeout after {elapsed:.1f}s")


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------
if __name__ == "__main__":
    args = sys.argv[1:]
    target = args[0].lower() if args else "all"

    print("🛡  Detect Email — Comprehensive Test Suite")
    print(f"   Server: {BASE}")
    print(f"   Target: {target}")

    # Always check health first
    if not test_health():
        sys.exit(1)

    if target in ("all", "l1"):
        test_l1()
    if target in ("all", "l2"):
        test_l2()
    if target in ("all", "l3"):
        test_l3()
    if target in ("all", "cascade"):
        test_cascade()

    print(f"\n{'='*70}")
    print("  ✅ Test suite complete!")
    print(f"{'='*70}\n")

