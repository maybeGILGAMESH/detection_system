"""System prompt and Chain-of-Thought templates for DeepSeek Judge."""

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in phishing email detection.
You will receive evidence gathered from an email investigation and must determine whether the email is phishing, safe, or uncertain.

You MUST respond ONLY with valid JSON in the following format:
{
  "verdict": "phishing" or "safe" or "uncertain",
  "confidence": 0.0 to 1.0,
  "reasoning": "Your step-by-step analysis"
}

IMPORTANT RULES:
- If you are CONFIDENT (>0.8) the email is phishing → verdict "phishing"
- If you are CONFIDENT (>0.8) the email is safe → verdict "safe"
- If you CANNOT determine with certainty → verdict "uncertain" (this sends the email to a human operator)
- Pay special attention to QR codes in emails — they are increasingly used for phishing (QR-phishing / quishing)
- Emails containing QR codes with suspicious URLs or asking to scan QR codes should be flagged
- Check for social engineering patterns: urgency, fear, authority impersonation, reward lures

Do NOT include any text outside the JSON object."""


COT_TEMPLATE = """Analyze the following email and its associated evidence. Think step by step.

--- EMAIL CONTEXT ---
From: {sender}
To: {recipient}
Subject: {subject}
Body (excerpt): {body_excerpt}
URLs found: {urls}

--- EVIDENCE FOR URL: {evidence_url} ---

1. DOMAIN REPUTATION:
   - Tranco Top-1M rank: {tranco_rank}
   - WHOIS Registrar: {whois_registrar}
   - Domain age: {domain_age} days
   - Country: {whois_country}

2. SSL CERTIFICATE:
   - Issuer: {ssl_issuer}
   - Valid: {ssl_valid}
   - Valid from: {ssl_from}
   - Valid to: {ssl_to}

3. PAGE ANALYSIS (DOM):
   - Forms on page: {forms_count}
   - Has password field: {has_password}
   - External scripts: {ext_scripts}
   - Iframes: {iframes}

4. REDIRECTS:
   {redirect_chain}

--- INSTRUCTIONS ---
Reason step-by-step:
1) Is the sender domain suspicious?
2) Does the email body use urgency/fear tactics?
3) Is the URL's domain recently registered or has low reputation?
4) Is the SSL certificate from a reputable issuer?
5) Does the page have login forms or password fields (credential harvesting)?
6) Are there suspicious redirects?
7) Does the email contain QR codes or ask the user to scan something?
8) Could this be a legitimate automated notification vs. social engineering?

If the evidence is contradictory or insufficient, set verdict to "uncertain".

Based on your analysis, provide your verdict as JSON."""


def build_judge_prompt(
    sender: str = "",
    recipient: str = "",
    subject: str = "",
    body: str = "",
    urls: list[str] | None = None,
    evidence=None,
) -> str:
    """Build the full prompt for the DeepSeek Judge."""

    body_excerpt = body[:500] if body else "(empty)"
    urls_str = ", ".join(urls or []) or "(none)"

    # Evidence fields
    evidence_url = ""
    tranco_rank = "N/A (not in Top 1M — suspicious)"
    whois_registrar = "Unknown"
    domain_age = "Unknown"
    whois_country = "Unknown"
    ssl_issuer = "Unknown"
    ssl_valid = "Unknown"
    ssl_from = "Unknown"
    ssl_to = "Unknown"
    forms_count = "0"
    has_password = "No"
    ext_scripts = "None"
    iframes = "0"
    redirect_chain = "(no data)"

    if evidence:
        evidence_url = evidence.url

        if evidence.tranco_rank is not None:
            tranco_rank = f"#{evidence.tranco_rank}"
        
        if evidence.whois:
            whois_registrar = evidence.whois.registrar or "Unknown"
            domain_age = str(evidence.whois.domain_age_days) if evidence.whois.domain_age_days >= 0 else "Unknown"
            whois_country = evidence.whois.country or "Unknown"

        if evidence.ssl:
            ssl_issuer = evidence.ssl.issuer or "Unknown"
            ssl_valid = str(evidence.ssl.is_valid)
            ssl_from = evidence.ssl.valid_from or "Unknown"
            ssl_to = evidence.ssl.valid_to or "Unknown"

        if evidence.dom_analysis:
            forms_count = str(evidence.dom_analysis.forms_count)
            has_password = "Yes" if evidence.dom_analysis.has_password_field else "No"
            ext_scripts = ", ".join(evidence.dom_analysis.external_scripts[:5]) or "None"
            iframes = str(evidence.dom_analysis.iframes_count)

        if evidence.redirect_chain:
            redirect_chain = "\n   ".join(evidence.redirect_chain[:10])

    return COT_TEMPLATE.format(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body_excerpt=body_excerpt,
        urls=urls_str,
        evidence_url=evidence_url,
        tranco_rank=tranco_rank,
        whois_registrar=whois_registrar,
        domain_age=domain_age,
        whois_country=whois_country,
        ssl_issuer=ssl_issuer,
        ssl_valid=ssl_valid,
        ssl_from=ssl_from,
        ssl_to=ssl_to,
        forms_count=forms_count,
        has_password=has_password,
        ext_scripts=ext_scripts,
        iframes=iframes,
        redirect_chain=redirect_chain,
    )
