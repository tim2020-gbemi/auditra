# notifications.py
# Handles all email notifications for Auditra using Resend.
# Two categories:
#   1. Account notifications: new registration, account activated, password reset
#   2. Alert notifications: Non-Compliant control, Critical vulnerability, Critical risk

import os
import resend
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

resend.api_key = os.environ.get("RESEND_API_KEY")

# Test sender address provided by Resend. No domain verification needed.
# Replace with a verified domain address later, e.g. notifications@auditra.ng
SENDER_ADDRESS = "Auditra <onboarding@resend.dev>"


def send_email(to, subject, html_body):
    """
    Core send function. Everything else in this file calls this.
    Fails silently (logs to console) rather than crashing the app
    if the email doesn't send, since a notification failure should
    never break the actual feature that triggered it.
    """
    if not resend.api_key:
        print("RESEND_API_KEY not set. Skipping email send.")
        return False

    if not to:
        print("No recipient email provided. Skipping email send.")
        return False

    try:
        resend.Emails.send({
            "from": SENDER_ADDRESS,
            "to": to if isinstance(to, list) else [to],
            "subject": subject,
            "html": html_body,
        })
        return True
    except Exception as e:
        print(f"Email send failed: {e}")
        return False


def _email_wrapper(title, body_html):
    """
    Shared HTML shell for every Auditra email.
    Keeps a consistent dark, professional look matching the product.
    """
    return f"""
    <div style="background:#0d0d1a;padding:32px;font-family:Arial,sans-serif;">
        <div style="max-width:520px;margin:0 auto;background:#13131f;border:1px solid #1e1e35;border-radius:8px;overflow:hidden;">
            <div style="background:#0d0d1a;border-bottom:2px solid #4f8ef7;padding:20px 28px;">
                <span style="font-family:'Courier New',monospace;font-size:20px;font-weight:bold;color:#ffffff;letter-spacing:1px;">AUDITRA</span>
            </div>
            <div style="padding:28px;color:#d0d0e8;">
                <h2 style="color:#ffffff;font-size:16px;margin:0 0 16px 0;">{title}</h2>
                {body_html}
            </div>
            <div style="background:#0d0d1a;padding:16px 28px;border-top:1px solid #1e1e35;">
                <span style="font-family:'Courier New',monospace;font-size:10px;color:#5a5a7a;">
                    Auditra Compliance Platform | This is an automated notification
                </span>
            </div>
        </div>
    </div>
    """


# ─────────────────────────────────────────────────────────────────────────────
# ACCOUNT NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────

def notify_admins_new_registration(admin_emails, new_username):
    """Sent to all admins when someone self-registers and needs approval."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            A new user has registered on Auditra and is awaiting approval.
        </p>
        <p style="font-size:14px;background:#0d0d1a;padding:12px 16px;border-radius:6px;border-left:3px solid #4f8ef7;">
            <strong>Username:</strong> {new_username}
        </p>
        <p style="font-size:13px;color:#9999bb;">
            Log in as admin and visit the Users page to activate this account.
        </p>
    """
    return send_email(admin_emails, "New Registration Pending Approval", _email_wrapper("New Registration", body))


def notify_user_account_activated(user_email, username):
    """Sent to a user when their account is approved by an admin."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            Hi {username}, your Auditra account has been activated. You can now log in.
        </p>
    """
    return send_email(user_email, "Your Auditra Account Is Now Active", _email_wrapper("Account Activated", body))


def notify_user_password_reset(user_email, username):
    """Sent to a user when an admin resets their password."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            Hi {username}, your Auditra password was just reset by an administrator.
            If you did not expect this, contact your admin immediately.
        </p>
    """
    return send_email(user_email, "Your Auditra Password Was Reset", _email_wrapper("Password Reset", body))


# ─────────────────────────────────────────────────────────────────────────────
# ALERT NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────

def notify_admins_control_noncompliant(admin_emails, control_id, description):
    """Sent to all admins when a compliance control is marked Non-Compliant."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            A control has been marked <strong style="color:#f76f6f;">Non-Compliant</strong>.
        </p>
        <p style="font-size:14px;background:#0d0d1a;padding:12px 16px;border-radius:6px;border-left:3px solid #f76f6f;">
            <strong>{control_id}</strong><br>
            <span style="color:#9999bb;">{description}</span>
        </p>
        <p style="font-size:13px;color:#9999bb;">
            Review this control on the Compliance Dashboard and plan remediation.
        </p>
    """
    return send_email(admin_emails, f"Control Non-Compliant: {control_id}", _email_wrapper("Compliance Alert", body))


def notify_admins_critical_vulnerability(admin_emails, cve_id, asset_name, cvss_score):
    """Sent to all admins when a Critical vulnerability (CVSS 9.0+) is logged."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            A <strong style="color:#f76f6f;">Critical</strong> vulnerability has been logged.
        </p>
        <p style="font-size:14px;background:#0d0d1a;padding:12px 16px;border-radius:6px;border-left:3px solid #f76f6f;">
            <strong>{cve_id or 'No CVE ID'}</strong><br>
            <span style="color:#9999bb;">Asset: {asset_name} &nbsp;|&nbsp; CVSS Score: {cvss_score}</span>
        </p>
        <p style="font-size:13px;color:#9999bb;">
            Review this on the Vulnerability Tracker and prioritize remediation.
        </p>
    """
    return send_email(admin_emails, f"Critical Vulnerability Logged: {cve_id or 'Unidentified'}", _email_wrapper("Vulnerability Alert", body))


def notify_admins_critical_risk(admin_emails, risk_title, risk_score):
    """Sent to all admins when a risk enters the Critical band (score 15-25)."""
    body = f"""
        <p style="font-size:14px;line-height:1.6;">
            A risk has entered the <strong style="color:#f76f6f;">Critical</strong> band on the Risk Register.
        </p>
        <p style="font-size:14px;background:#0d0d1a;padding:12px 16px;border-radius:6px;border-left:3px solid #f76f6f;">
            <strong>{risk_title}</strong><br>
            <span style="color:#9999bb;">Risk Score: {risk_score} / 25</span>
        </p>
        <p style="font-size:13px;color:#9999bb;">
            Review this on the Risk Register and assign an owner if unassigned.
        </p>
    """
    return send_email(admin_emails, f"Critical Risk: {risk_title}", _email_wrapper("Risk Alert", body))
