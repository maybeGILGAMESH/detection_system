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
import base64
import io
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


# ---------------------------------------------------------------------------
#  QR code image generator (base64 PNG) — used for artifact emails
# ---------------------------------------------------------------------------

def _make_qr_b64(url: str) -> str:
    """Generate a QR code PNG image as a base64 string."""
    try:
        import qrcode
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        return ""


def _qr_img_tag(url: str, alt: str = "QR Code") -> str:
    """Return an <img> tag with an inline base64 QR code, or a placeholder."""
    b64 = _make_qr_b64(url)
    if b64:
        return (
            f'<img src="data:image/png;base64,{b64}" '
            f'alt="{alt}" width="200" height="200">'
        )
    return f'<div style="border:1px solid #ccc;padding:40px;text-align:center">[QR: {url}]</div>'


# ---------------------------------------------------------------------------
#  Artifact: QR-phishing emails with real embedded QR code images
# ---------------------------------------------------------------------------

_ARTIFACT_QR_PHISH: list[dict] = [
    {
        "sender": "security@corp-2fa-portal.xyz",
        "recipient": "employee@company.com",
        "subject": "Mandatory: Enable Two-Factor Authentication",
        "body": (
            "Dear Employee,\n\n"
            "As part of our security policy, all staff must enable 2FA by scanning "
            "the QR code in the attached HTML version of this email.\n\n"
            "After scanning, enter your corporate credentials to link your "
            "authenticator app.\n\n"
            "Accounts without 2FA will be suspended after the deadline.\n\n"
            "IT Security Department"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">'
            '<h2 style="color:#1a73e8">Corporate 2FA Enrollment</h2>'
            "<p>Scan the QR code below with your phone to set up two-factor authentication:</p>"
            '<div style="text-align:center;padding:20px">'
            "{qr_2fa}"
            "</div>"
            "<p>After scanning, enter your username and password to complete enrollment.</p>"
            '<p style="color:#d93025;font-weight:bold">Deadline: 3 days. '
            "Non-compliant accounts will be locked.</p>"
            '<hr><p style="font-size:11px;color:#666">IT Security Department</p>'
            "</div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes phishing URL)",
    },
    {
        "sender": "parking@city-fines-portal.xyz",
        "recipient": "driver@company.com",
        "subject": "Parking Violation — Fine Payment Required",
        "body": (
            "CITY PARKING SERVICES\n"
            "Parking Violation Notice\n\n"
            "Vehicle: license plate ***487\n"
            "Violation: Overtime parking in Zone B\n"
            "Fine: $75.00\n"
            "Due: 7 days from receipt\n\n"
            "Pay your fine by scanning the QR code in the HTML version.\n\n"
            "Late payment penalties apply.\n\n"
            "Municipal Parking Authority"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;'
            'border:2px solid #c00;padding:20px">'
            '<h2 style="color:#c00">PARKING VIOLATION NOTICE</h2>'
            "<table>"
            "<tr><td><b>Vehicle:</b></td><td>License ***487</td></tr>"
            "<tr><td><b>Violation:</b></td><td>Overtime parking, Zone B</td></tr>"
            '<tr><td><b>Fine:</b></td><td style="color:#c00;font-weight:bold">$75.00</td></tr>'
            "</table>"
            '<p>Scan to pay immediately:</p><div style="text-align:center">'
            "{qr_fine}"
            "</div>"
            '<p style="font-size:11px;color:#888">Municipal Parking Authority</p>'
            "</div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes phishing payment URL)",
    },
    {
        "sender": "hr@benefits-enroll-now.xyz",
        "recipient": "staff@company.com",
        "subject": "Open Enrollment: Scan QR to Update Benefits",
        "body": (
            "Dear Team Member,\n\n"
            "Annual benefits enrollment is now open. To review and update your "
            "selections for 2026, scan the QR code in the HTML email.\n\n"
            "You will need to confirm your identity with your SSO credentials.\n\n"
            "Enrollment closes in 5 business days.\n\n"
            "Human Resources"
        ),
        "html": (
            '<div style="font-family:Segoe UI,sans-serif;max-width:600px;margin:auto">'
            '<div style="background:#0078d4;color:#fff;padding:15px 20px">'
            "<h2>Benefits Open Enrollment 2026</h2></div>"
            '<div style="padding:20px">'
            "<p>Review and update your benefits by scanning the QR code:</p>"
            '<div style="text-align:center;padding:15px;background:#f5f5f5;border-radius:8px">'
            "{qr_benefits}"
            "</div>"
            "<p>Log in with your corporate SSO credentials after scanning.</p>"
            '<p style="color:#d83b01"><b>Deadline: 5 business days</b></p></div>'
            "</div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes credential harvesting URL)",
    },
    # --- QR to fake bank / payment ---
    {
        "sender": "noreply@secure-pay-invoice.site",
        "recipient": "client@company.com",
        "subject": "Invoice #INV-20260315 — Payment Due",
        "body": (
            "Dear Client,\n\n"
            "Please find attached invoice #INV-20260315 for consulting services.\n\n"
            "Amount due: $2,340.00\n"
            "Due date: March 28, 2026\n\n"
            "Scan the QR code in the HTML version to pay via bank transfer.\n\n"
            "Finance Department"
        ),
        "html": (
            '<div style="font-family:Georgia,serif;max-width:600px;margin:auto;'
            'border:1px solid #ccc;padding:30px">'
            '<h1 style="font-size:20px;border-bottom:2px solid #333;padding-bottom:10px">'
            "INVOICE #INV-20260315</h1>"
            '<table style="width:100%;margin:15px 0;border-collapse:collapse">'
            '<tr><td style="padding:6px 0">Service:</td><td>IT Consulting — March 2026</td></tr>'
            '<tr><td style="padding:6px 0">Amount:</td>'
            '<td style="font-weight:bold;font-size:18px">$2,340.00</td></tr>'
            '<tr><td style="padding:6px 0">Due:</td><td>March 28, 2026</td></tr>'
            "</table>"
            "<p>Scan to pay instantly via secure bank transfer:</p>"
            '<div style="text-align:center;padding:20px;background:#f9f9f9;border-radius:8px">'
            "{qr_invoice}"
            "</div>"
            '<p style="font-size:11px;color:#888;margin-top:15px">'
            "If you have questions about this invoice, reply to this email.</p></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes fake payment portal)",
    },
    # --- QR to crypto wallet drain ---
    {
        "sender": "rewards@web3-airdrop-claim.site",
        "recipient": "user@company.com",
        "subject": "Claim Your 500 USDT Airdrop — Scan QR",
        "body": (
            "Congratulations!\n\n"
            "You have been selected for a USDT airdrop reward.\n"
            "Amount: 500 USDT\n\n"
            "To claim, scan the QR code in the HTML version with "
            "your wallet app.\n\n"
            "Offer expires in 48 hours.\n\n"
            "Web3 Rewards Team"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;'
            'background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;'
            'padding:30px;border-radius:12px">'
            '<h2 style="color:#00d4aa">500 USDT Airdrop</h2>'
            '<p style="font-size:16px">You have been selected!</p>'
            '<div style="background:rgba(255,255,255,0.1);padding:20px;border-radius:8px;'
            'text-align:center;margin:20px 0">'
            '<p style="font-size:36px;font-weight:bold;color:#00d4aa;margin:0">500 USDT</p>'
            '<p style="color:#aaa">Scan to claim</p>'
            "{qr_crypto}"
            "</div>"
            '<p style="color:#ff6b6b;font-weight:bold">Expires in 48 hours</p>'
            '<p style="font-size:10px;color:#666">Web3 Rewards Program</p>'
            "</div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes crypto scam / wallet drain)",
    },
    # --- QR to fake tax refund ---
    {
        "sender": "refunds@tax-refund-portal.site",
        "recipient": "taxpayer@company.com",
        "subject": "Tax Refund: $1,847.00 — Verify to Receive",
        "body": (
            "Internal Revenue Service\n"
            "Tax Refund Notification\n\n"
            "Our records indicate you are eligible for a tax refund of $1,847.00 "
            "for the fiscal year 2025.\n\n"
            "To process your refund, scan the QR code in the HTML version "
            "and verify your banking information.\n\n"
            "Sincerely,\n"
            "IRS Refund Processing Center"
        ),
        "html": (
            '<div style="font-family:Times New Roman,serif;max-width:600px;margin:auto;'
            'border:3px solid #003366;padding:25px">'
            '<div style="text-align:center;border-bottom:2px solid #003366;padding-bottom:15px">'
            '<h2 style="color:#003366;margin:0">Internal Revenue Service</h2>'
            '<p style="color:#666;margin:5px 0">Tax Refund Notification</p></div>'
            '<div style="padding:20px 0">'
            "<p>Dear Taxpayer,</p>"
            '<p>You are eligible for a refund of <b style="font-size:18px;color:#006600">'
            "$1,847.00</b> for fiscal year 2025.</p>"
            "<p>Scan the QR code to verify your identity and banking details:</p>"
            '<div style="text-align:center;padding:15px;background:#f5f5f5;margin:15px 0">'
            "{qr_tax}"
            "</div>"
            '<p style="color:#c00;font-size:12px">Processing deadline: 10 business days. '
            "Unclaimed refunds will be forfeited.</p></div>"
            '<div style="border-top:1px solid #ccc;padding-top:10px;font-size:10px;color:#888">'
            "IRS Refund Processing Center | This is an automated notification</div></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (QR encodes fake IRS refund portal)",
    },
]


# ---------------------------------------------------------------------------
#  Artifact: HTML phishing with forms, iframes, obfuscated redirects
# ---------------------------------------------------------------------------

_ARTIFACT_HTML: list[dict] = [
    {
        "sender": "noreply@signin-microsoftonline.xyz",
        "recipient": "user@company.com",
        "subject": "Action Required: Verify Your Microsoft 365 Account",
        "body": (
            "Your Microsoft 365 session has expired.\n\n"
            "Please re-authenticate to continue accessing Outlook, Teams, "
            "and OneDrive.\n\n"
            "Open the HTML version of this email to sign in securely."
        ),
        "html": (
            '<div style="font-family:Segoe UI,sans-serif;max-width:500px;margin:40px auto;'
            'border:1px solid #ddd;border-radius:8px;overflow:hidden">'
            '<div style="background:#0078d4;padding:20px;text-align:center">'
            '<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/'
            'RE1Mu3b" alt="Microsoft" width="120" style="filter:brightness(0) invert(1)">'
            "</div>"
            '<div style="padding:30px">'
            "<h3>Sign in to your account</h3>"
            '<form action="http://signin-microsoftonline.xyz/auth/login" method="POST">'
            '<input type="email" name="email" placeholder="Email address" '
            'style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px"><br>'
            '<input type="password" name="password" placeholder="Password" '
            'style="width:100%;padding:10px;margin:8px 0;border:1px solid #ccc;border-radius:4px"><br>'
            '<button type="submit" style="width:100%;padding:12px;background:#0078d4;color:#fff;'
            'border:none;border-radius:4px;font-size:16px;cursor:pointer">Sign in</button>'
            "</form>"
            '<p style="font-size:11px;color:#666;margin-top:15px">'
            "Can't access your account? | Sign in with a security key</p>"
            "</div></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (HTML form with password field, fake Microsoft)",
    },
    {
        "sender": "noreply@drive-share-docs.xyz",
        "recipient": "team@company.com",
        "subject": "Document shared: Q3 Budget Review.xlsx",
        "body": (
            "A document has been shared with you.\n\n"
            "Title: Q3 Budget Review.xlsx\n"
            "Shared by: CFO Office\n\n"
            "Open the HTML version to view the document."
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:40px auto;'
            'border:1px solid #ddd;border-radius:8px;overflow:hidden">'
            '<div style="background:#4285f4;padding:15px 20px;color:#fff">'
            "<b>Google Drive</b> — Document shared with you</div>"
            '<div style="padding:25px">'
            '<p style="font-size:18px">Q3 Budget Review.xlsx</p>'
            '<p style="color:#666">CFO Office shared a spreadsheet with you</p>'
            '<div style="background:#f0f0f0;padding:15px;border-radius:4px;margin:15px 0">'
            '<iframe src="http://drive-share-docs.xyz/embed/preview?doc=q3budget" '
            'width="100%" height="200" style="border:none" sandbox></iframe>'
            "</div>"
            '<a href="http://drive-share-docs.xyz/view/q3budget" '
            'style="display:block;text-align:center;background:#1a73e8;color:#fff;'
            'padding:12px;border-radius:4px;text-decoration:none;font-weight:bold">'
            "Open in Google Drive</a>"
            '<p style="font-size:11px;color:#999;margin-top:15px">'
            "You received this because CFO Office shared a file with you.</p>"
            "</div></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (hidden iframe, fake Google Drive)",
    },
    {
        "sender": "security@account-alerts-service.xyz",
        "recipient": "user@company.com",
        "subject": "Unusual sign-in activity on your account",
        "body": (
            "We detected an unusual sign-in attempt.\n\n"
            "Location: Unknown\n"
            "Time: Today\n\n"
            "If this wasn't you, please review your account immediately "
            "by opening the HTML version of this email."
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:40px auto">'
            '<h2 style="color:#d93025">Security Alert</h2>'
            "<p>We detected an unusual sign-in attempt on your account.</p>"
            '<table style="width:100%;border-collapse:collapse;margin:15px 0">'
            '<tr><td style="padding:8px;border-bottom:1px solid #eee"><b>Location:</b></td>'
            '<td style="padding:8px;border-bottom:1px solid #eee;color:#d93025">'
            "Unknown (Lagos, NG)</td></tr>"
            '<tr><td style="padding:8px;border-bottom:1px solid #eee"><b>Device:</b></td>'
            '<td style="padding:8px;border-bottom:1px solid #eee">Linux / Chrome</td></tr>'
            "</table>"
            "<p>If this wasn't you, secure your account now:</p>"
            '<a href="http://account-alerts-service.xyz/secure?token=abc123" '
            'style="display:inline-block;background:#d93025;color:#fff;padding:12px 30px;'
            'border-radius:4px;text-decoration:none;font-weight:bold">Review Activity</a>'
            '<script>setTimeout(function(){'
            'window.location="http://account-alerts-service.xyz/redirect";},15000);</script>'
            '<p style="font-size:11px;color:#999;margin-top:20px">'
            "This is an automated security notification.</p></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (JS auto-redirect, fake security alert)",
    },
    # --- Fake DHL / package delivery ---
    {
        "sender": "tracking@dhl-parcel-status.site",
        "recipient": "customer@company.com",
        "subject": "DHL: Your package is waiting — confirm delivery address",
        "body": (
            "DHL Express Notification\n\n"
            "Your package (tracking #DHL-7729401835) could not be delivered "
            "due to an incomplete address.\n\n"
            "Confirm your delivery details in the HTML version.\n\n"
            "DHL Customer Service"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:auto;'
            'border:1px solid #ddd;border-radius:8px;overflow:hidden">'
            '<div style="background:#ffcc00;padding:15px 20px">'
            '<b style="font-size:20px;color:#c00">DHL</b>'
            '<span style="color:#333;margin-left:10px">Express</span></div>'
            '<div style="padding:25px">'
            '<h3 style="color:#333">Delivery Attempt Failed</h3>'
            '<div style="background:#fff3cd;border:1px solid #ffc107;padding:12px;'
            'border-radius:4px;margin:15px 0">'
            "<b>Tracking:</b> DHL-7729401835<br>"
            "<b>Status:</b> Address incomplete — action required</div>"
            '<form action="http://dhl-parcel-status.site/confirm" method="POST">'
            '<input type="text" name="fullname" placeholder="Full Name" '
            'style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px">'
            '<input type="text" name="address" placeholder="Street Address" '
            'style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px">'
            '<input type="text" name="city" placeholder="City, ZIP Code" '
            'style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px">'
            '<input type="text" name="phone" placeholder="Phone Number" '
            'style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px">'
            '<input type="text" name="card" placeholder="Card number (delivery fee $1.99)" '
            'style="width:100%;padding:10px;margin:5px 0;border:1px solid #ccc;border-radius:4px">'
            '<button type="submit" style="width:100%;padding:12px;background:#c00;color:#fff;'
            'border:none;border-radius:4px;font-size:15px;cursor:pointer;margin-top:8px">'
            "Confirm &amp; Pay $1.99</button>"
            "</form>"
            '<p style="font-size:10px;color:#999;margin-top:12px">'
            "DHL International GmbH</p></div></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (fake DHL, form harvests address + card)",
    },
    # --- "Vote for me" social engineering ---
    {
        "sender": "anna.k@creative-contest-vote.site",
        "recipient": "friend@company.com",
        "subject": "Please vote for my project! Just takes 10 seconds",
        "body": (
            "Hey!\n\n"
            "I'm in the finals of a creative design contest and really need "
            "your vote. It only takes 10 seconds!\n\n"
            "Just follow the link below, log in with your social account, "
            "and click the vote button:\n\n"
            "http://creative-contest-vote.site/entry/anna-k-2026?ref=email\n\n"
            "Thank you so much! Voting closes tomorrow.\n\n"
            "Anna"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:auto">'
            "<p>Hey!</p>"
            "<p>I'm in the finals of a creative design contest and really need your vote. "
            "It literally takes 10 seconds!</p>"
            '<div style="text-align:center;margin:20px 0">'
            '<a href="http://creative-contest-vote.site/entry/anna-k-2026?ref=email" '
            'style="display:inline-block;background:#e91e63;color:#fff;padding:15px 40px;'
            'border-radius:30px;text-decoration:none;font-size:18px;font-weight:bold">'
            "Vote for Anna</a></div>"
            '<p style="color:#666;font-size:13px">You will need to log in with your '
            "Google or Telegram account to verify your vote.</p>"
            '<p style="color:#999;font-size:11px">Voting closes March 24, 2026</p></div>'
        ),
        "expect": "GREY -> L3 -> PHISHING (social engineering, credential harvesting via vote)",
    },
    # --- Fake Telegram / social media ---
    {
        "sender": "noreply@tg-security-check.site",
        "recipient": "user@company.com",
        "subject": "Telegram: Someone is trying to delete your account",
        "body": (
            "Telegram Security\n\n"
            "We received a request to delete your Telegram account.\n\n"
            "If this was NOT you, cancel the deletion immediately by "
            "opening the link below:\n\n"
            "http://tg-security-check.site/cancel-deletion?uid=79281234567\n\n"
            "If you do not respond within 24 hours, your account "
            "and all messages will be permanently removed.\n\n"
            "Telegram Security Team"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:auto">'
            '<div style="background:#0088cc;padding:15px 20px;color:#fff;text-align:center">'
            '<b style="font-size:20px">Telegram</b></div>'
            '<div style="padding:25px">'
            '<h3 style="color:#d93025">Account Deletion Request</h3>'
            "<p>We received a request to <b>permanently delete</b> your Telegram account.</p>"
            '<div style="background:#fee;border:1px solid #fcc;padding:12px;border-radius:4px;'
            'margin:15px 0"><b>If this was NOT you</b>, cancel the deletion now:</div>'
            '<a href="http://tg-security-check.site/cancel-deletion?uid=79281234567" '
            'style="display:block;text-align:center;background:#0088cc;color:#fff;'
            'padding:14px;border-radius:4px;text-decoration:none;font-size:16px;'
            'font-weight:bold">Cancel Deletion</a>'
            '<p style="color:#c00;font-size:13px;margin-top:12px">'
            "You have 24 hours. After that, your account will be removed.</p>"
            '<p style="font-size:10px;color:#999">Telegram FZ LLC</p></div></div>'
        ),
        "expect": "GREY -> L3 -> PHISHING (fake Telegram, urgency + credential theft)",
    },
    # --- Fake WhatsApp backup restore ---
    {
        "sender": "backup@whatsapp-cloud-restore.site",
        "recipient": "user@company.com",
        "subject": "WhatsApp: Your chat backup could not be restored",
        "body": (
            "WhatsApp Cloud Backup\n\n"
            "We were unable to restore your chat backup from March 20, 2026.\n\n"
            "Backup size: 4.7 GB\n"
            "Messages: 23,491\n"
            "Media files: 2,847\n\n"
            "To restore your backup, verify your phone number:\n"
            "http://whatsapp-cloud-restore.site/restore?phone=verify\n\n"
            "If you do not verify within 7 days, the backup will be deleted.\n\n"
            "WhatsApp Support"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:500px;margin:auto">'
            '<div style="background:#25d366;padding:15px 20px;color:#fff;text-align:center">'
            '<b style="font-size:20px">WhatsApp</b></div>'
            '<div style="padding:25px">'
            '<h3>Chat Backup Restore Failed</h3>'
            '<div style="background:#f5f5f5;padding:15px;border-radius:8px;margin:10px 0">'
            "<p><b>Backup date:</b> March 20, 2026<br>"
            "<b>Size:</b> 4.7 GB<br>"
            "<b>Messages:</b> 23,491<br>"
            "<b>Media:</b> 2,847 files</p></div>"
            '<p>Verify your phone number to restore:</p>'
            '<a href="http://whatsapp-cloud-restore.site/restore?phone=verify" '
            'style="display:block;text-align:center;background:#25d366;color:#fff;'
            'padding:14px;border-radius:8px;text-decoration:none;font-weight:bold;'
            'font-size:16px">Restore Backup</a>'
            '<p style="color:#c00;font-size:12px;margin-top:12px">'
            "Backup will be deleted in 7 days if not verified.</p>"
            '<p style="font-size:10px;color:#999">WhatsApp LLC, a Meta company</p>'
            "</div></div>"
        ),
        "expect": "GREY -> L3 -> PHISHING (fake WhatsApp, phone/credential harvest)",
    },
]


# ---------------------------------------------------------------------------
#  Artifact: Safe QR codes — legitimate services
# ---------------------------------------------------------------------------

_ARTIFACT_SAFE_QR: list[dict] = [
    {
        "sender": "noreply@github.com",
        "recipient": "developer@company.com",
        "subject": "Enable 2FA on your GitHub account",
        "body": (
            "Hi developer,\n\n"
            "We recommend enabling two-factor authentication on your GitHub account.\n\n"
            "Scan the QR code in the HTML version to open your security settings.\n\n"
            "The GitHub Team"
        ),
        "html": (
            '<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:auto">'
            '<div style="background:#24292f;padding:20px;text-align:center">'
            '<span style="color:#fff;font-size:24px;font-weight:bold">GitHub</span></div>'
            '<div style="padding:25px">'
            "<h3>Set Up Two-Factor Authentication</h3>"
            "<p>Scan this QR code with your phone to open your GitHub security settings:</p>"
            '<div style="text-align:center;padding:20px">'
            "{qr_github}"
            "</div>"
            "<p>Or visit: <a href=\"https://github.com/settings/security\">"
            "github.com/settings/security</a></p>"
            '<hr><p style="font-size:11px;color:#666">GitHub, Inc.</p>'
            "</div></div>"
        ),
        "expect": "GREY -> L3 -> SAFE (QR encodes legitimate github.com URL)",
    },
    {
        "sender": "noreply@zoom.us",
        "recipient": "user@company.com",
        "subject": "Your Zoom meeting link — scan to join",
        "body": (
            "Hi,\n\n"
            "Your upcoming meeting is ready. Scan the QR code in the "
            "HTML version to join from your mobile device.\n\n"
            "Meeting: Weekly Team Standup\n"
            "Time: Monday 10:00 AM\n\n"
            "Zoom Team"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">'
            '<div style="background:#2d8cff;padding:15px 20px;color:#fff">'
            "<b>Zoom</b> — Meeting Invitation</div>"
            '<div style="padding:25px">'
            "<h3>Weekly Team Standup</h3>"
            "<p><b>Time:</b> Monday 10:00 AM<br>"
            "<b>Duration:</b> 30 minutes</p>"
            "<p>Scan to join from your mobile device:</p>"
            '<div style="text-align:center;padding:15px;background:#f5f8ff;border-radius:8px">'
            "{qr_zoom}"
            "</div>"
            '<p style="font-size:12px;color:#666;margin-top:15px">'
            'Or click: <a href="https://zoom.us/j/1234567890">Join Meeting</a></p>'
            "</div></div>"
        ),
        "expect": "GREY -> L3 -> SAFE (QR encodes legitimate zoom.us URL)",
    },
    {
        "sender": "noreply@linkedin.com",
        "recipient": "professional@company.com",
        "subject": "Your LinkedIn QR code for networking",
        "body": (
            "Hi,\n\n"
            "Here is your personal LinkedIn QR code for quick networking "
            "at upcoming events.\n\n"
            "Others can scan it to view your profile instantly.\n\n"
            "LinkedIn Team"
        ),
        "html": (
            '<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">'
            '<div style="background:#0a66c2;padding:15px 20px;color:#fff">'
            "<b>LinkedIn</b></div>"
            '<div style="padding:25px">'
            "<h3>Your Networking QR Code</h3>"
            "<p>Share this QR code at events for instant profile access:</p>"
            '<div style="text-align:center;padding:15px">'
            "{qr_linkedin}"
            "</div>"
            '<p style="font-size:12px;color:#666">'
            'Or share: <a href="https://linkedin.com/in/example-user">'
            "linkedin.com/in/example-user</a></p></div></div>"
        ),
        "expect": "GREY -> L3 -> SAFE (QR encodes legitimate linkedin.com URL)",
    },
]


def _build_artifact_emails() -> dict[str, list[dict]]:
    """Render QR code images into artifact email templates at import time."""

    # Map each QR placeholder in templates to the URL it should encode.
    _phish_qr_map = {
        "{qr_2fa}":      "http://corp-2fa-portal.xyz/enroll/2fa?token=a1b2c3",
        "{qr_fine}":     "http://city-fines-portal.xyz/pay/fine?ref=PKG-2026-0487",
        "{qr_benefits}": "http://benefits-enroll-now.xyz/sso/login?redirect=benefits",
        "{qr_invoice}":  "http://secure-pay-invoice.site/pay/INV-20260315?bank=verify",
        "{qr_crypto}":   "http://web3-airdrop-claim.site/claim?wallet=connect",
        "{qr_tax}":      "http://tax-refund-portal.site/verify?ssn=required",
    }

    _safe_qr_map = {
        "{qr_github}":   "https://github.com/settings/security",
        "{qr_zoom}":     "https://zoom.us/j/1234567890",
        "{qr_linkedin}": "https://linkedin.com/in/example-user",
    }

    def _render_qr_in_templates(templates, qr_map):
        result = []
        for tmpl in templates:
            entry = dict(tmpl)
            html = entry.get("html", "")
            for placeholder, url in qr_map.items():
                if placeholder in html:
                    html = html.replace(placeholder, _qr_img_tag(url))
            entry["html"] = html
            result.append(entry)
        return result

    return {
        "artifact_qr":      _render_qr_in_templates(_ARTIFACT_QR_PHISH, _phish_qr_map),
        "artifact_html":    list(_ARTIFACT_HTML),
        "artifact_safe_qr": _render_qr_in_templates(_ARTIFACT_SAFE_QR, _safe_qr_map),
    }


# Build artifact emails (QR images rendered once at import time)
_artifact_emails = _build_artifact_emails()
EMAILS.update(_artifact_emails)

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
            "l1":               "🔴 L1 — Threat Intel (blacklisted domains)",
            "l2_phish":         "🟠 L2 — Obvious Phishing Text",
            "safe":             "🟢 L2 — Safe / Legitimate Emails",
            "grey":             "🟡 Grey Zone → L3 → PHISHING",
            "grey_safe":        "🟢 Grey Zone → L3 → SAFE",
            "qr_phish":         "📱 QR-Phishing (quishing, text only)",
            "uncertain":        "🟣 Uncertain → Operator Review",
            "artifact_qr":      "📱 Artifact: QR Code Phishing (real images)",
            "artifact_html":    "🎨 Artifact: HTML Phishing (forms/iframes/JS)",
            "artifact_safe_qr": "✅ Artifact: Safe QR Codes (legitimate)",
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
            "l1":               "🔴 L1 Reject (blacklist)",
            "l2_phish":         "🟠 L2 Phishing",
            "safe":             "🟢 L2 Safe",
            "grey":             "🟡 Grey → L3 → Phish",
            "grey_safe":        "🟢 Grey → L3 → Safe",
            "qr_phish":         "📱 QR-Phishing (text)",
            "uncertain":        "🟣 Uncertain → Operator",
            "artifact_qr":      "📱 Artifact: QR Phish",
            "artifact_html":    "🎨 Artifact: HTML Phish",
            "artifact_safe_qr": "✅ Artifact: Safe QR",
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

ALL_LEVELS = [
    "l1", "l2_phish", "safe", "grey", "grey_safe", "uncertain",
    "artifact_qr", "artifact_html", "artifact_safe_qr",
]

def main():
    parser = argparse.ArgumentParser(
        description="SMTP Bombardier — send test phishing & safe emails",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Levels:
  l1                Known blacklisted domains (Threat Intel reject)
  l2_phish          Obvious phishing text (DistilBERT reject)
  safe              Legitimate business emails (DistilBERT deliver)
  grey              Ambiguous → L3 investigation → phishing
  grey_safe         Ambiguous → L3 investigation → safe
  uncertain         AI can't decide → operator review
  qr_phish          QR-code phishing text only (legacy, not in 'all')
  artifact_qr       HTML emails with real embedded QR code images (phishing)
  artifact_html     HTML emails with forms, iframes, JS redirects (phishing)
  artifact_safe_qr  HTML emails with legitimate QR codes (safe)
  all               All of the above (except qr_phish)
        """,
    )
    parser.add_argument(
        "--level",
        choices=ALL_LEVELS + ["qr_phish", "all", "artifacts"],
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

    if args.level == "all":
        levels = ALL_LEVELS
    elif args.level == "artifacts":
        levels = ["artifact_qr", "artifact_html", "artifact_safe_qr"]
    else:
        levels = [args.level]
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
