# Copyright (c) 2026 ad25343 — https://github.com/ad25343/InformaticaConversion
# Licensed under CC BY-NC 4.0. Commercial use requires written permission.
"""
Email notifications (v2.17.2).

Sends async SMTP emails at key pipeline events:

  gate_waiting  — pipeline paused at Gate 1, 2, or 3; a human decision is required
  job_failed    — pipeline reached a terminal FAILED or BLOCKED state
  job_complete  — Gate 3 approved; generated code is ready

No dedicated mail server required.  Configure any SMTP relay via .env:
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
  SMTP_TLS (default true)  or  SMTP_SSL (port-465 direct SSL)
  NOTIFY_GATE_EMAILS  — comma-separated list of recipients

All send failures are logged as warnings and never block the pipeline.
"""
from __future__ import annotations

import email.mime.multipart
import email.mime.text
import logging
from datetime import datetime, timezone
from typing import Optional

from .config import settings

_log = logging.getLogger("conversion.notify")

_TOOL = "Informatica Conversion Tool"

# Gate labels used in email subjects / bodies
_GATE_LABELS = {
    "gate1": "Gate 1 — Technical Review",
    "gate2": "Gate 2 — Security Review",
    "gate3": "Gate 3 — Code Review",
}


def _recipients() -> list[str]:
    """Parse NOTIFY_GATE_EMAILS into a clean list.  Returns [] if unset."""
    raw = settings.notify_gate_emails.strip()
    if not raw:
        return []
    return [addr.strip() for addr in raw.split(",") if addr.strip()]


def _from_addr() -> str:
    return settings.smtp_from.strip() or settings.smtp_user.strip()


def _is_configured() -> bool:
    return bool(settings.smtp_host.strip()) and bool(_recipients())


def _build_message(
    subject: str,
    body_html: str,
    body_text: str,
) -> email.mime.multipart.MIMEMultipart:
    """Assemble a multipart/alternative MIME message."""
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = _from_addr()
    msg["To"]      = ", ".join(_recipients())

    msg.attach(email.mime.text.MIMEText(body_text, "plain"))
    msg.attach(email.mime.text.MIMEText(body_html, "html"))
    return msg


async def _send(msg: email.mime.multipart.MIMEMultipart) -> None:
    """Low-level async SMTP send.  Raises on failure (caller catches)."""
    import aiosmtplib  # lazy import — only needed when email is configured

    kwargs: dict = dict(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user or None,
        password=settings.smtp_password or None,
    )

    if settings.smtp_ssl:
        kwargs["use_tls"] = True          # Direct SSL (port 465)
    elif settings.smtp_tls:
        kwargs["start_tls"] = True        # STARTTLS (port 587)

    await aiosmtplib.send(msg, **kwargs)


# ── Public entry point ────────────────────────────────────────────────────────

async def fire_email(
    event: str,
    job_id: str,
    filename: str,
    step: int,
    status: str,
    message: str,
    gate: Optional[str] = None,
) -> None:
    """
    Send a non-blocking, non-fatal email notification.

    Signature mirrors ``webhook.fire_webhook`` so both can be called from
    the same orchestrator call sites.

    Args:
        event:    "gate_waiting" | "job_complete" | "job_failed"
        job_id:   UUID of the job
        filename: Original mapping filename
        step:     Current pipeline step number (0–12)
        status:   Job status string
        message:  Human-readable description of the event
        gate:     Internal gate key, e.g. "gate1" (None for non-gate events)
    """
    if not _is_configured():
        return   # Email not configured — silent no-op

    try:
        subject, body_html, body_text = _build_content(
            event, job_id, filename, step, status, message, gate
        )
        msg = _build_message(subject, body_html, body_text)
        await _send(msg)
        _log.info(
            "Email sent — event=%s job=%s to=%s",
            event, job_id, settings.notify_gate_emails,
        )
    except Exception as exc:
        _log.warning(
            "Email failed (non-fatal) — event=%s job=%s error=%s",
            event, job_id, exc,
        )


def _build_content(
    event: str,
    job_id: str,
    filename: str,
    step: int,
    status: str,
    message: str,
    gate: Optional[str],
) -> tuple[str, str, str]:
    """Return (subject, html_body, plain_body) for the given event."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    gate_label = _GATE_LABELS.get(gate or "", gate or "")

    if event == "gate_waiting":
        subject = f"[ICT] Action required — {gate_label}: {filename}"
        plain = (
            f"A mapping is waiting for your review.\n\n"
            f"File     : {filename}\n"
            f"Gate     : {gate_label}\n"
            f"Job ID   : {job_id}\n"
            f"Step     : {step}\n"
            f"Message  : {message}\n"
            f"Time     : {now}\n\n"
            f"Open the Informatica Conversion Tool to review and sign off."
        )
        html = f"""
<html><body style="font-family:sans-serif;color:#1a1a2e;max-width:600px">
  <div style="background:#2563eb;color:#fff;padding:16px 20px;border-radius:8px 8px 0 0">
    <strong>⚡ Informatica Conversion Tool</strong>
  </div>
  <div style="border:1px solid #e2e8f0;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <h2 style="margin:0 0 12px;color:#2563eb">Action required — {gate_label}</h2>
    <p>A mapping is waiting for your review.</p>
    <table style="border-collapse:collapse;width:100%;font-size:14px">
      <tr><td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap">File</td>
          <td style="padding:6px 0"><strong>{filename}</strong></td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Gate</td>
          <td style="padding:6px 0"><strong>{gate_label}</strong></td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Job ID</td>
          <td style="padding:6px 0;font-family:monospace;font-size:12px">{job_id}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Message</td>
          <td style="padding:6px 0">{message}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Time</td>
          <td style="padding:6px 0">{now}</td></tr>
    </table>
    <p style="margin-top:16px;color:#475569">
      Open the <strong>Informatica Conversion Tool</strong> and go to the
      <strong>Review Queue</strong> tab to sign off.
    </p>
  </div>
</body></html>"""

    elif event == "job_failed":
        subject = f"[ICT] Job failed — {filename}"
        plain = (
            f"A job has reached a terminal failure state.\n\n"
            f"File     : {filename}\n"
            f"Status   : {status}\n"
            f"Job ID   : {job_id}\n"
            f"Step     : {step}\n"
            f"Message  : {message}\n"
            f"Time     : {now}\n"
        )
        html = f"""
<html><body style="font-family:sans-serif;color:#1a1a2e;max-width:600px">
  <div style="background:#dc2626;color:#fff;padding:16px 20px;border-radius:8px 8px 0 0">
    <strong>⚡ Informatica Conversion Tool — Job Failed</strong>
  </div>
  <div style="border:1px solid #e2e8f0;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <h2 style="margin:0 0 12px;color:#dc2626">Job reached a terminal failure state</h2>
    <table style="border-collapse:collapse;width:100%;font-size:14px">
      <tr><td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap">File</td>
          <td style="padding:6px 0"><strong>{filename}</strong></td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Status</td>
          <td style="padding:6px 0"><strong style="color:#dc2626">{status}</strong></td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Job ID</td>
          <td style="padding:6px 0;font-family:monospace;font-size:12px">{job_id}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Message</td>
          <td style="padding:6px 0">{message}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Time</td>
          <td style="padding:6px 0">{now}</td></tr>
    </table>
  </div>
</body></html>"""

    else:  # job_complete or unknown
        subject = f"[ICT] Job complete — {filename}"
        plain = (
            f"A mapping conversion has completed successfully.\n\n"
            f"File     : {filename}\n"
            f"Job ID   : {job_id}\n"
            f"Step     : {step}\n"
            f"Message  : {message}\n"
            f"Time     : {now}\n"
        )
        html = f"""
<html><body style="font-family:sans-serif;color:#1a1a2e;max-width:600px">
  <div style="background:#16a34a;color:#fff;padding:16px 20px;border-radius:8px 8px 0 0">
    <strong>⚡ Informatica Conversion Tool — Conversion Complete</strong>
  </div>
  <div style="border:1px solid #e2e8f0;border-top:none;padding:20px;border-radius:0 0 8px 8px">
    <h2 style="margin:0 0 12px;color:#16a34a">Mapping conversion complete</h2>
    <table style="border-collapse:collapse;width:100%;font-size:14px">
      <tr><td style="padding:6px 12px 6px 0;color:#64748b;white-space:nowrap">File</td>
          <td style="padding:6px 0"><strong>{filename}</strong></td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Job ID</td>
          <td style="padding:6px 0;font-family:monospace;font-size:12px">{job_id}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Message</td>
          <td style="padding:6px 0">{message}</td></tr>
      <tr><td style="padding:6px 12px 6px 0;color:#64748b">Time</td>
          <td style="padding:6px 0">{now}</td></tr>
    </table>
  </div>
</body></html>"""

    return subject, html, plain
