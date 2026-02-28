#!/usr/bin/env python3
"""SMTP Bombardier — sends diverse test emails to the phishing detection system.

Sends emails that trigger different processing levels:
  - L1 (Threat Intel reject): domains in local blacklist
  - L2 (Classifier reject): obvious phishing text patterns
  - L2 (Safe deliver): clearly legitimate business emails
  - Grey Zone → L3: ambiguous emails (moderate phishing + legitimate signals)
  - QR Phishing: social engineering with QR codes
  - Uncertain → Operator: maximally ambiguous cases

Usage:
    python smtp_bombardier.py --http                    # all emails via HTTP
    python smtp_bombardier.py --http --level l2_phish   # only L2 phishing
    python smtp_bombardier.py --http --level grey_safe  # only grey→safe
    python smtp_bombardier.py --http --delay 5          # 5s between emails
"""

import argparse
import smtplib
import time
import sys
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = "127.0.0.1"
SMTP_PORT = 1025

# Email Templates
#
# Email texts carefully tuned to hit specific L2 confidence zones.
# Model: DistilBERT trained on phishing/safe emails.
#  - Pure business language -> safe (>0.9)
#  - Keyword-heavy phishing (password, urgent, verify, suspended) -> phish (<0.4)
#  - Mix of both signals -> grey zone (0.4-0.9)

EMAILS = {
    # -- L1: Known blacklisted domains → Threat Intel reject -----------------
    "l1": [
        {
            "sender": "security@acc0unt-verify.xyz",
            "recipient": "victim@company.com",
            "subject": "Action Required: Verify your credentials",
            "body": (
                "Dear Customer,\n\n"
                "We detected unusual activity on your account. "
                "Please verify your credentials immediately:\n\n"
                "http://acc0unt-verify.xyz/login?ref=secure\n\n"
                "Failure to verify within 24 hours will result in account suspension.\n\n"
                "Security Team"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: acc0unt-verify.xyz)",
        },
        {
            "sender": "admin@secure-banking-login.tk",
            "recipient": "user@company.com",
            "subject": "URGENT: Bank Account Locked!",
            "body": (
                "Your bank account has been temporarily locked due to suspicious activity.\n\n"
                "Restore access now: http://secure-banking-login.tk/restore?id=8837\n\n"
                "If you don't act within 12 hours, your funds will be frozen.\n\n"
                "Bank Security Division"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: secure-banking-login.tk)",
        },
        {
            "sender": "support@phishing-login-secure.gq",
            "recipient": "admin@company.com",
            "subject": "Security Alert: Unauthorized access attempt",
            "body": (
                "We have detected an unauthorized sign-in attempt on your account.\n\n"
                "Location: Lagos, Nigeria\n"
                "Device: Unknown\n\n"
                "If this wasn't you, secure your account immediately:\n"
                "http://phishing-login-secure.gq/secure-account\n\n"
                "Account Security Team"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: phishing-login-secure.gq)",
        },
        {
            "sender": "service@paypa1-security.ml",
            "recipient": "customer@company.com",
            "subject": "Your PayPal account is limited",
            "body": (
                "Dear PayPal user,\n\n"
                "We noticed some suspicious transactions on your account. "
                "To restore full access, please confirm your identity:\n\n"
                "http://paypa1-security.ml/confirm-identity\n\n"
                "PayPal Customer Protection"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: paypa1-security.ml)",
        },
        {
            "sender": "admin@microsofit-365.cf",
            "recipient": "employee@company.com",
            "subject": "Microsoft 365: Password Expiration Notice",
            "body": (
                "Your Microsoft 365 password will expire in 24 hours.\n\n"
                "To keep your access, update your password now:\n"
                "http://microsofit-365.cf/password-update\n\n"
                "Microsoft 365 Admin Center"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: microsofit-365.cf)",
        },
        {
            "sender": "refunds@amazon-refund-claim.ga",
            "recipient": "buyer@company.com",
            "subject": "Amazon Refund: $247.99 pending your approval",
            "body": (
                "Dear Amazon Customer,\n\n"
                "A refund of $247.99 has been issued for your recent order #112-4839201.\n\n"
                "To claim your refund, please verify your payment method:\n"
                "http://amazon-refund-claim.ga/refund/verify\n\n"
                "Amazon Customer Service"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: amazon-refund-claim.ga)",
        },
        {
            "sender": "share@googl3-drive-share.work",
            "recipient": "team@company.com",
            "subject": "Document shared with you: Q1 Financial Report",
            "body": (
                "John Smith shared a document with you.\n\n"
                "Q1 Financial Report — Final Version.xlsx\n\n"
                "Open in Google Drive:\n"
                "http://googl3-drive-share.work/open?doc=q1-report\n\n"
                "Google Drive"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: googl3-drive-share.work)",
        },
        {
            "sender": "noreply@apple-id-locked.buzz",
            "recipient": "user@company.com",
            "subject": "Your Apple ID has been locked",
            "body": (
                "Dear Apple Customer,\n\n"
                "Your Apple ID was locked for security reasons. "
                "Someone tried to sign in from an unrecognized device.\n\n"
                "Unlock your Apple ID: http://apple-id-locked.buzz/unlock\n\n"
                "If you don't verify within 48 hours, your account will be permanently disabled.\n\n"
                "Apple Support"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: apple-id-locked.buzz)",
        },
        {
            "sender": "alert@chase-online-alert.click",
            "recipient": "client@company.com",
            "subject": "Chase Alert: Suspicious transaction detected",
            "body": (
                "Chase Bank Security Alert\n\n"
                "A transaction of $1,299.00 was attempted on your debit card ending in 4821.\n\n"
                "If you did NOT authorize this, report immediately:\n"
                "http://chase-online-alert.click/report-fraud\n\n"
                "Chase Fraud Protection"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: chase-online-alert.click)",
        },
        {
            "sender": "files@dropbox-verify-now.top",
            "recipient": "user@company.com",
            "subject": "Dropbox: Verify your email to keep your files",
            "body": (
                "Hi,\n\n"
                "We need to verify your email address to continue storing your files.\n\n"
                "If you don't verify within 7 days, your files may be permanently deleted.\n\n"
                "Verify now: http://dropbox-verify-now.top/verify-email\n\n"
                "Dropbox Team"
            ),
            "html": "",
            "expect": "L1 REJECT (local blacklist: dropbox-verify-now.top)",
        },
    ],

    # -- L2 PHISHING: Obvious phishing patterns -----------------------------
    "l2_phish": [
        {
            "sender": "helpdesk@randomdomain99.com",
            "recipient": "employee@company.com",
            "subject": "URGENT: Your password expires today!!!",
            "body": (
                "Dear User,\n\n"
                "Your corporate password expires TODAY. If you do not reset it immediately, "
                "you will lose access to all company systems including email, VPN, and internal tools.\n\n"
                "CLICK HERE NOW TO RESET YOUR PASSWORD.\n\n"
                "You must enter your current password and SSN for verification.\n\n"
                "This is an automated notification. Do not reply to this email.\n\n"
                "IT Support Team"
            ),
            "html": "",
            "expect": "L2 REJECT (password + urgency + SSN)",
        },
        {
            "sender": "prize@winner-notification.xyz",
            "recipient": "lucky@company.com",
            "subject": "Congratulations! You've Won $1,000,000!!!",
            "body": (
                "CONGRATULATIONS!!!\n\n"
                "You have been selected as the WINNER of our international lottery!\n"
                "Prize: $1,000,000 USD\n\n"
                "To claim your prize, reply with:\n"
                "- Full name\n- Bank account number\n- Credit card details\n"
                "- Social Security Number\n\n"
                "Offer expires in 24 hours!\n\n"
                "International Prize Committee"
            ),
            "html": "",
            "expect": "L2 REJECT (lottery scam)",
        },
        {
            "sender": "ceo@urgent-wire.biz",
            "recipient": "finance@company.com",
            "subject": "Wire Transfer - CONFIDENTIAL",
            "body": (
                "I need you to process an urgent wire transfer of $45,000 to the account below.\n"
                "This is strictly confidential — do not discuss with anyone.\n\n"
                "Bank: First National\nAccount: 3847291056\nRouting: 021000021\n\n"
                "Complete within 2 hours. I'm in a meeting and cannot take calls.\n\n"
                "CEO"
            ),
            "html": "",
            "expect": "L2 REJECT (BEC/wire fraud)",
        },
        {
            "sender": "support@paypal-security-check.com",
            "recipient": "user@company.com",
            "subject": "Your PayPal account has been limited",
            "body": (
                "Dear PayPal Customer,\n\n"
                "We've noticed suspicious activity and temporarily limited your access.\n\n"
                "Confirm your identity by providing:\n"
                "- Full name\n- Date of birth\n- Credit card number\n"
                "- Card expiration date and CVV\n- Your password\n\n"
                "If we don't receive verification within 24 hours, "
                "your account will be permanently suspended.\n\n"
                "PayPal Security"
            ),
            "html": "",
            "expect": "L2 REJECT (credential harvesting)",
        },
        {
            "sender": "admin@accounts-dept.com",
            "recipient": "staff@company.com",
            "subject": "Immediate action: Confirm your login credentials",
            "body": (
                "ATTENTION ALL EMPLOYEES\n\n"
                "Due to a recent security breach, all employees must re-confirm "
                "their login credentials within the next 4 hours.\n\n"
                "Please reply to this email with:\n"
                "1. Your username\n2. Your current password\n3. Your new password\n\n"
                "Failure to comply will result in immediate account deactivation.\n\n"
                "System Administrator"
            ),
            "html": "",
            "expect": "L2 REJECT (credential theft)",
        },
        {
            "sender": "no-reply@crypto-airdrop-bonus.com",
            "recipient": "investor@company.com",
            "subject": "CLAIM NOW: 5000 FREE tokens before they expire!",
            "body": (
                "🚀 EXCLUSIVE AIRDROP ALERT! 🚀\n\n"
                "You've been selected for a MASSIVE crypto airdrop!\n"
                "Claim 5000 FREE tokens worth $12,500 USD right now!\n\n"
                "To receive your tokens, connect your wallet and enter your seed phrase.\n\n"
                "ACT FAST — only 200 spots remaining!\n"
                "Offer expires in 3 hours!\n\n"
                "Crypto Rewards Network"
            ),
            "html": "",
            "expect": "L2 REJECT (crypto scam)",
        },
        {
            "sender": "hr@company-benefits-update.com",
            "recipient": "all-staff@company.com",
            "subject": "Mandatory: Update your direct deposit information NOW",
            "body": (
                "Dear Employee,\n\n"
                "Due to a payroll system migration, ALL employees must update "
                "their direct deposit information immediately.\n\n"
                "Failure to update within 24 hours will delay your next paycheck.\n\n"
                "Please provide:\n"
                "- Full name\n- Social Security Number\n- Bank routing number\n"
                "- Account number\n- Date of birth\n\n"
                "Reply to this email directly.\n\n"
                "Human Resources Department"
            ),
            "html": "",
            "expect": "L2 REJECT (HR impersonation / direct deposit scam)",
        },
        {
            "sender": "alert@windows-defender-warning.com",
            "recipient": "user@company.com",
            "subject": "CRITICAL: Your computer is infected with 14 viruses!",
            "body": (
                "⚠️ WINDOWS DEFENDER ALERT ⚠️\n\n"
                "Your computer has been compromised! We detected:\n"
                "- 14 active viruses\n- 3 trojans\n- Potential ransomware\n\n"
                "Your personal files, passwords, and banking information are AT RISK.\n\n"
                "Call our Microsoft Certified Technicians immediately: 1-888-555-0199\n"
                "Or download the emergency repair tool now.\n\n"
                "DO NOT TURN OFF YOUR COMPUTER!\n\n"
                "Windows Security Center"
            ),
            "html": "",
            "expect": "L2 REJECT (tech support scam)",
        },
        {
            "sender": "boss-executive@company-mail.net",
            "recipient": "assistant@company.com",
            "subject": "Need you to buy gift cards ASAP — don't tell anyone",
            "body": (
                "Hey,\n\n"
                "I need your help with something urgent and confidential. "
                "I'm stuck in a meeting and can't make calls.\n\n"
                "Please buy 5 Apple gift cards, $200 each ($1000 total). "
                "Scratch off the backs and send me photos of the codes.\n\n"
                "I'll reimburse you today. This is VERY urgent.\n\n"
                "Do NOT mention this to anyone — it's a surprise.\n\n"
                "Sent from my iPhone"
            ),
            "html": "",
            "expect": "L2 REJECT (gift card scam / BEC)",
        },
        {
            "sender": "voicemail@phone-system-notification.com",
            "recipient": "user@company.com",
            "subject": "You have 3 missed voicemails — click to listen",
            "body": (
                "MISSED VOICEMAIL NOTIFICATION\n\n"
                "You have 3 new voicemail messages.\n\n"
                "Message 1: From +1 (555) 0147 — Duration: 2:34\n"
                "Message 2: From Unknown — Duration: 0:45\n"
                "Message 3: From +1 (555) 0392 — Duration: 1:12\n\n"
                "Click below to listen to your messages:\n"
                "[PLAY VOICEMAIL]\n\n"
                "You must enter your email password to access the voicemail portal.\n\n"
                "Corporate Phone System"
            ),
            "html": "",
            "expect": "L2 REJECT (voicemail phishing)",
        },
    ],

    # -- L2 SAFE: Clearly legitimate business emails -------------------------
    "safe": [
        {
            "sender": "alex.johnson@company.com",
            "recipient": "team@company.com",
            "subject": "Meeting notes from today's standup",
            "body": (
                "Hi team,\n\n"
                "Here are the notes from today's standup meeting:\n\n"
                "1. Backend API development is on track for Friday deployment\n"
                "2. Frontend team completed the dashboard redesign\n"
                "3. QA starts regression testing tomorrow morning\n"
                "4. DevOps is preparing the staging environment\n\n"
                "Next sprint planning is Monday at 10 AM in Conference Room B.\n\n"
                "Best regards,\nAlex Johnson\nSenior Developer"
            ),
            "html": "",
            "expect": "L2 DELIVER (meeting notes)",
        },
        {
            "sender": "hr@company.com",
            "recipient": "all-staff@company.com",
            "subject": "Office closed on March 3rd — Public Holiday",
            "body": (
                "Dear Colleagues,\n\n"
                "This is a reminder that our office will be closed on Monday, March 3rd, "
                "in observance of the public holiday.\n\n"
                "Normal business hours resume on Tuesday, March 4th.\n"
                "If you have any urgent matters, please contact your department head.\n\n"
                "Enjoy the long weekend!\n\nHuman Resources Department"
            ),
            "html": "",
            "expect": "L2 DELIVER (HR announcement)",
        },
        {
            "sender": "maria.kovalenko@company.com",
            "recipient": "project-alpha@company.com",
            "subject": "Q1 Report draft — please review",
            "body": (
                "Hi everyone,\n\n"
                "I've attached the Q1 performance report draft. Key highlights:\n\n"
                "- Revenue: up 12% QoQ\n- Customer satisfaction: 4.7/5.0\n"
                "- New feature adoption: 68%\n- Support tickets reduced by 23%\n\n"
                "Please review and add your sections by Thursday.\n\n"
                "Regards,\nMaria Kovalenko\nProject Manager"
            ),
            "html": "",
            "expect": "L2 DELIVER (quarterly report)",
        },
        {
            "sender": "ci-bot@company.com",
            "recipient": "dev@company.com",
            "subject": "[CI] Build #4521 passed — all tests green",
            "body": (
                "Build #4521 completed successfully.\n\n"
                "Branch: fix/null-pointer-auth\n"
                "Changes: Added null check in AuthService.validateToken()\n"
                "Tests: 247 passed, 0 failed\n"
                "Coverage: 89.3%\n\n"
                "Reviewers: Anna S., Mark T.\nStatus: Ready to merge"
            ),
            "html": "",
            "expect": "L2 DELIVER (CI notification)",
        },
        {
            "sender": "elena@company.com",
            "recipient": "team@company.com",
            "subject": "Team lunch tomorrow at 12:30",
            "body": (
                "Hi everyone!\n\n"
                "Just a reminder — our team lunch is tomorrow at 12:30.\n"
                "Location: Café Milano, 2nd floor.\n\n"
                "8 people confirmed so far. Please RSVP by end of day.\n\n"
                "See you there!\nElena"
            ),
            "html": "",
            "expect": "L2 DELIVER (social/team)",
        },
    ],

    # -- Grey Zone → L3 → PHISHING ------------------------------------------
    # These use NEUTRAL language (no phishing keywords!) so L2 gives moderate
    # confidence. L3 investigates the URLs and finds suspicious domains.
    "grey": [
        {
            "sender": "shared@fileshare-service.net",
            "recipient": "team@company.com",
            "subject": "Shared file: Q2 project proposal",
            "body": (
                "Hi,\n\n"
                "A new document has been shared with you.\n\n"
                "Title: Q2 Project Proposal — Budget & Timeline\n"
                "Shared by: David Chen (external)\n\n"
                "Open the document:\n"
                "http://fileshare-service.net/shared/doc-q2-proposal\n\n"
                "This link is valid for 7 days.\n\n"
                "FileStar Platform"
            ),
            "html": "",
            "expect": "GREY → L3 → PHISHING (fake file sharing)",
        },
        {
            "sender": "reports@analytics-dash.net",
            "recipient": "manager@company.com",
            "subject": "Your February activity report is ready",
            "body": (
                "Hello,\n\n"
                "Your monthly activity report for February 2026 is available.\n\n"
                "Highlights:\n"
                "- Total sessions: 142\n"
                "- Team collaboration score: 87/100\n"
                "- New integrations: 3\n\n"
                "View the full report:\n"
                "http://analytics-dash.net/reports/feb-2026\n\n"
                "Analytics Dashboard Team"
            ),
            "html": "",
            "expect": "GREY → L3 → PHISHING (fake analytics service)",
        },
    ],

    # -- Grey Zone → L3 → SAFE (legitimate services, neutral text) ----------
    # These are from real services but written neutrally to land in grey zone.
    # L3 investigates and finds legit domains (Tranco top 1M, valid SSL, etc.)
    "grey_safe": [
        {
            "sender": "notifications@github.com",
            "recipient": "developer@company.com",
            "subject": "New sign-in from a new device",
            "body": (
                "Hi developer,\n\n"
                "A sign-in to your account was recorded from a new device.\n\n"
                "Device: Chrome on Linux\n"
                "Location: Moscow, Russia\n"
                "Time: February 28, 2026 at 14:30 UTC\n\n"
                "If this was you, no action is needed.\n"
                "Review your sessions: https://github.com/settings/security\n\n"
                "The GitHub Team"
            ),
            "html": "",
            "expect": "GREY → L3 → SAFE (legit GitHub notification)",
        },
        {
            "sender": "noreply@zoom.us",
            "recipient": "user@company.com",
            "subject": "Upcoming plan renewal on March 5",
            "body": (
                "Hi,\n\n"
                "Your Zoom Pro plan will automatically renew on March 5, 2026.\n\n"
                "Plan: Zoom Pro\n"
                "Amount: $13.99/month\n"
                "Payment: Visa ending in 4242\n\n"
                "Manage your subscription at https://zoom.us/account\n\n"
                "Zoom Billing Team"
            ),
            "html": "",
            "expect": "GREY → L3 → SAFE (legit Zoom renewal)",
        },
    ],

    # -- QR Phishing (quishing) ----------------------------------------------
    "qr_phish": [
        {
            "sender": "it-security@company-portal.xyz",
            "recipient": "employee@company.com",
            "subject": "Mandatory: Enable Two-Factor Authentication",
            "body": (
                "Dear Employee,\n\n"
                "As part of our ongoing security improvements, all staff must enable "
                "two-factor authentication before March 1, 2026.\n\n"
                "To set up 2FA, scan the QR code below with your phone:\n\n"
                "[QR CODE IMAGE: http://company-portal.xyz/qr/2fa-setup.png]\n\n"
                "After scanning, enter your corporate username and password "
                "to link your authenticator app.\n\n"
                "IMPORTANT: Accounts without 2FA will be temporarily suspended "
                "after the deadline.\n\n"
                "IT Security Department"
            ),
            "html": (
                "<p>Dear Employee,</p>"
                "<p>Scan the QR code to set up 2FA:</p>"
                "<img src='http://company-portal.xyz/qr/2fa-setup.png' alt='QR Code'>"
                "<p>Enter your credentials after scanning.</p>"
            ),
            "expect": "GREY → L3 → PHISHING (QR-phishing / quishing)",
        },
        {
            "sender": "parking@municipal-services.xyz",
            "recipient": "driver@company.com",
            "subject": "Parking Violation — Fine Payment Required",
            "body": (
                "MUNICIPAL PARKING SERVICES\n"
                "Parking Violation Notice\n\n"
                "Vehicle: license plate ***487\n"
                "Violation: Overtime parking in Zone B\n"
                "Fine: $75.00\n"
                "Due: March 5, 2026\n\n"
                "Pay your fine by scanning the QR code:\n"
                "[QR CODE: http://municipal-services.xyz/pay/fine?ref=PKG-2026-0487]\n\n"
                "Or pay online: http://municipal-services.xyz/pay/fine?ref=PKG-2026-0487\n\n"
                "Late payment penalties apply after the due date.\n\n"
                "Municipal Parking Authority"
            ),
            "html": "",
            "expect": "GREY → L3 → PHISHING (QR with fake fine)",
        },
    ],

    # -- Uncertain → Operator Review -----------------------------------------
    # These use NEUTRAL language so L2 gives moderate confidence (grey zone).
    # L3 Judge is genuinely uncertain because the content is ambiguous.
    "uncertain": [
        {
            "sender": "noreply@feedback-portal.io",
            "recipient": "user@company.com",
            "subject": "Invitation: annual customer feedback survey",
            "body": (
                "Hi,\n\n"
                "You have been selected to participate in our annual "
                "customer satisfaction survey for 2026.\n\n"
                "The survey takes approximately 5 minutes and covers "
                "your experience with our platform this year.\n\n"
                "Start the survey:\n"
                "http://feedback-portal.io/survey/2026-annual\n\n"
                "Your responses are anonymous and help us improve.\n\n"
                "Customer Experience Team"
            ),
            "html": "",
            "expect": "GREY → L3 → UNCERTAIN → OPERATOR",
        },
        {
            "sender": "updates@workspace-tools.io",
            "recipient": "manager@company.com",
            "subject": "New integration available for your workspace",
            "body": (
                "Hello,\n\n"
                "A new integration is available that connects your "
                "workspace with third-party project management tools.\n\n"
                "Features:\n"
                "- Automatic task synchronization\n"
                "- Shared calendar view\n"
                "- Cross-team reporting\n\n"
                "Learn more and activate:\n"
                "http://workspace-tools.io/integrations/new\n\n"
                "Workspace Tools Team"
            ),
            "html": "",
            "expect": "GREY → L3 → UNCERTAIN → OPERATOR",
        },
        {
            "sender": "no-reply@event-platform.io",
            "recipient": "admin@company.com",
            "subject": "You're invited: Tech Conference 2026",
            "body": (
                "Hello,\n\n"
                "You are invited to the Tech Conference 2026, "
                "taking place on April 15-17 in Berlin.\n\n"
                "Topics: AI/ML, Cloud Infrastructure, DevOps\n"
                "Early bird registration available.\n\n"
                "Register here:\n"
                "http://event-platform.io/techconf-2026/register\n\n"
                "We look forward to seeing you there.\n\n"
                "Event Platform Team"
            ),
            "html": "",
            "expect": "GREY → L3 → UNCERTAIN → OPERATOR",
        },
    ],
}

# -- Sender --

def send_email(email_data: dict, host: str, port: int) -> bool:
    """Send a single email via SMTP."""
    msg = MIMEMultipart("alternative")
    msg["From"] = email_data["sender"]
    msg["To"] = email_data["recipient"]
    msg["Subject"] = email_data["subject"]

    msg.attach(MIMEText(email_data["body"], "plain", "utf-8"))

    if email_data.get("html"):
        msg.attach(MIMEText(email_data["html"], "html", "utf-8"))

    try:
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            smtp.sendmail(email_data["sender"], [email_data["recipient"]], msg.as_string())
        return True
    except Exception as e:
        print(f"  ❌ SMTP Error: {e}")
        return False


def send_batch(levels: list[str], host: str, port: int, delay: float):
    """Send a batch of emails for given levels."""
    total = 0
    success = 0

    for level in levels:
        emails = EMAILS.get(level, [])
        if not emails:
            print(f"⚠️  Unknown level: {level}")
            continue

        level_names = {
            "l1":         "🔴 L1 — Threat Intel (blacklisted domains)",
            "l2_phish":   "🟠 L2 — Obvious Phishing Text",
            "safe":       "🟢 L2 — Safe / Legitimate Emails",
            "grey":       "🟡 Grey Zone → L3 → PHISHING",
            "grey_safe":  "🟢 Grey Zone → L3 → SAFE",
            "qr_phish":   "📱 QR-Phishing (quishing)",
            "uncertain":  "🟣 Uncertain → Operator Review",
        }

        print(f"\n{'-' * 60}")
        print(f"  {level_names.get(level, level)} ({len(emails)} emails)")
        print(f"{'-' * 60}")

        for i, email_data in enumerate(emails, 1):
            total += 1
            print(f"\n  [{i}/{len(emails)}] To: {email_data['recipient']}")
            print(f"           Subject: {email_data['subject']}")
            print(f"           Expected: {email_data['expect']}")
            print(f"           Sending...", end=" ", flush=True)

            if send_email(email_data, host, port):
                success += 1
                print("✅ Sent!")
            else:
                print("❌ Failed!")

            if delay > 0 and not (level == levels[-1] and i == len(emails)):
                print(f"           ⏳ Waiting {delay}s...")
                time.sleep(delay)

    print(f"\n{'-' * 60}")
    print(f"  📊 Summary: {success}/{total} emails sent successfully")
    print(f"{'-' * 60}\n")


# -------------------------------------------------------------------------------
#  HTTP Mode
# -------------------------------------------------------------------------------

def send_http(levels: list[str], delay: float, api_url: str):
    """Send emails via HTTP API (with long timeout for L3)."""
    import httpx

    # Long timeout because L3 can take 60-120s for LLM inference
    client = httpx.Client(base_url=api_url, trust_env=False, timeout=300)
    total = 0
    success = 0

    for level in levels:
        emails = EMAILS.get(level, [])
        if not emails:
            continue

        level_names = {
            "l1":         "🔴 L1 Reject (blacklist)",
            "l2_phish":   "🟠 L2 Phishing",
            "safe":       "🟢 L2 Safe",
            "grey":       "🟡 Grey → L3 → Phish",
            "grey_safe":  "🟢 Grey → L3 → Safe",
            "qr_phish":   "📱 QR-Phishing",
            "uncertain":  "🟣 Uncertain → Operator",
        }

        print(f"\n{'-' * 60}")
        print(f"  {level_names.get(level, level)} ({len(emails)} emails)")
        print(f"{'-' * 60}")

        for i, email_data in enumerate(emails, 1):
            total += 1
            print(f"\n  [{i}/{len(emails)}] {email_data['subject']}")
            print(f"           Expected: {email_data['expect']}")

            urls = re.findall(r'https?://[^\s<>"\']+', email_data["body"])
            if email_data.get("html"):
                urls += re.findall(r'https?://[^\s<>"\']+', email_data["html"])
            urls = list(set(urls))
            domains = list(set(
                url.split("//")[1].split("/")[0].split(":")[0] for url in urls
            ))

            payload = {
                "sender": email_data["sender"],
                "recipient": email_data["recipient"],
                "subject": email_data["subject"],
                "body": email_data["body"],
                "html_body": email_data.get("html", ""),
                "urls": urls,
                "domains": domains,
                "ips": [],
                "message_id": f"test-{level}-{i}@bombardier",
                "raw": "",
            }

            try:
                print(f"           Sending...", end=" ", flush=True)
                r = client.post("/api/v1/process", json=payload)
                result = r.json()
                action = result.get("action", "?")
                detail = result.get("detail", "")
                icons = {
                    "DELIVER": "✅", "RELEASE": "✅",
                    "REJECT": "🚫", "DELETE": "🗑️",
                    "OPERATOR_REVIEW": "👤",
                }
                icon = icons.get(action, "❓")
                print(f"{icon} {action} — {detail}")
                success += 1
            except Exception as e:
                print(f"❌ Error: {e}")

            if delay > 0:
                time.sleep(delay)

    client.close()

    print(f"\n{'-' * 60}")
    print(f"  📊 Results: {success}/{total} processed")
    print(f"{'-' * 60}\n")


# -------------------------------------------------------------------------------
#  CLI
# -------------------------------------------------------------------------------

ALL_LEVELS = ["l1", "l2_phish", "safe", "grey", "grey_safe", "uncertain"]

def main():
    parser = argparse.ArgumentParser(
        description="SMTP Bombardier — send test phishing & safe emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Levels:
  l1          Known blacklisted domains (Threat Intel reject)
  l2_phish    Obvious phishing text (DistilBERT reject)
  safe        Legitimate business emails (DistilBERT deliver)
  grey        Ambiguous → L3 investigation → phishing
  grey_safe   Ambiguous → L3 investigation → safe
  uncertain   AI can't decide → operator review
  qr_phish    QR-code phishing (optional, not in 'all')
  all         All of the above (except qr_phish)
        """,
    )
    parser.add_argument(
        "--level",
        choices=ALL_LEVELS + ["qr_phish", "all"],
        default="all",
        help="Which email level to send (default: all)",
    )
    parser.add_argument("--delay", type=float, default=3.0, help="Seconds between emails (default: 3)")
    parser.add_argument("--repeat", type=int, default=1, help="Repeat the batch N times")
    parser.add_argument("--host", default=SMTP_HOST, help=f"SMTP host (default: {SMTP_HOST})")
    parser.add_argument("--port", type=int, default=SMTP_PORT, help=f"SMTP port (default: {SMTP_PORT})")
    parser.add_argument("--http", action="store_true", help="Use HTTP API instead of SMTP")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000", help="API URL (for --http mode)")

    args = parser.parse_args()

    levels = ALL_LEVELS if args.level == "all" else [args.level]
    total_emails = sum(len(EMAILS.get(l, [])) for l in levels)

    print(f"""
SMTP Bombardier -- Phishing Email Test Suite
  Target:  {args.host}:{args.port}{'  (HTTP)' if args.http else ''}
  Levels:  {', '.join(levels)}
  Emails:  {total_emails} per batch x {args.repeat} = {total_emails * args.repeat}
  Delay:   {args.delay}s between emails
""")

    for batch in range(1, args.repeat + 1):
        if args.repeat > 1:
            print(f"\n🔄 Batch {batch}/{args.repeat}")

        if args.http:
            send_http(levels, args.delay, args.api_url)
        else:
            send_batch(levels, args.host, args.port, args.delay)

        if batch < args.repeat:
            time.sleep(5)

    print("🎉 Bombardier complete!")


if __name__ == "__main__":
    main()
