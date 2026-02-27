from __future__ import annotations

import logging
from datetime import datetime, timezone
from html import escape
from uuid import UUID

from ..settings import get_settings
from .mailer import MailPayload, send_email

logger = logging.getLogger(__name__)


def _get_admin_recipients() -> list[str]:
    raw = (get_settings().admin_notify_emails or "").strip()
    if not raw:
        return []

    recipients: list[str] = []
    seen: set[str] = set()
    for piece in raw.split(","):
        email = piece.strip().lower()
        if not email or email in seen:
            continue
        seen.add(email)
        recipients.append(email)
    return recipients


def _format_time_utc(ts: datetime | None = None) -> str:
    value = ts or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _send_admin_notification(subject: str, text_body: str, html_body: str) -> None:
    recipients = _get_admin_recipients()
    if not recipients:
        return

    for to_email in recipients:
        try:
            send_email(
                MailPayload(
                    to_email=to_email,
                    subject=subject,
                    text_body=text_body,
                    html_body=html_body,
                )
            )
        except Exception:
            logger.exception(
                "admin_notification_failed",
                extra={"event": "admin_notification_failed", "to": to_email, "subject": subject},
            )


def notify_new_user_created(
    *,
    local_user_id: UUID,
    supabase_user_id: UUID,
    email: str,
    full_name: str | None,
) -> None:
    full_name_value = full_name or "N/A"
    now_str = _format_time_utc()
    subject = "New User Registered | AI DevOps Monitor"
    text_body = (
        "A new user was registered.\n\n"
        f"Email: {email}\n"
        f"Full name: {full_name_value}\n"
        f"Local user id: {local_user_id}\n"
        f"Supabase user id: {supabase_user_id}\n"
        f"Time: {now_str}\n"
    )
    html_body = f"""
<html>
  <body style="margin:0;padding:16px;background:#f5f5f5;color:#111;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
      <tr>
        <td align="center">
          <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="background:#fff;border:1px solid #e5e5e5;border-radius:8px;">
            <tr>
              <td style="padding:20px 24px;border-bottom:1px solid #efefef;">
                <h2 style="margin:0;font-size:20px;">New User Registered</h2>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 24px;font-size:14px;line-height:1.6;">
                <p style="margin:0 0 12px;">A new user was added to AI DevOps Monitor.</p>
                <p style="margin:0;"><strong>Email:</strong> {escape(email)}</p>
                <p style="margin:8px 0 0;"><strong>Full name:</strong> {escape(full_name_value)}</p>
                <p style="margin:8px 0 0;"><strong>Local user id:</strong> {escape(str(local_user_id))}</p>
                <p style="margin:8px 0 0;"><strong>Supabase user id:</strong> {escape(str(supabase_user_id))}</p>
                <p style="margin:8px 0 0;"><strong>Time:</strong> {escape(now_str)}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
""".strip()
    _send_admin_notification(subject, text_body, html_body)


def notify_server_created(
    *,
    actor_email: str,
    actor_full_name: str | None,
    server_id: UUID,
    server_name: str,
) -> None:
    actor_name_value = actor_full_name or "N/A"
    now_str = _format_time_utc()
    subject = "New Server Added | AI DevOps Monitor"
    text_body = (
        "A new server was added.\n\n"
        f"User email: {actor_email}\n"
        f"User full name: {actor_name_value}\n"
        f"Server name: {server_name}\n"
        f"Server id: {server_id}\n"
        f"Time: {now_str}\n"
    )
    html_body = f"""
<html>
  <body style="margin:0;padding:16px;background:#f5f5f5;color:#111;font-family:Arial,Helvetica,sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
      <tr>
        <td align="center">
          <table role="presentation" width="640" cellspacing="0" cellpadding="0" style="background:#fff;border:1px solid #e5e5e5;border-radius:8px;">
            <tr>
              <td style="padding:20px 24px;border-bottom:1px solid #efefef;">
                <h2 style="margin:0;font-size:20px;">New Server Added</h2>
              </td>
            </tr>
            <tr>
              <td style="padding:20px 24px;font-size:14px;line-height:1.6;">
                <p style="margin:0 0 12px;">A user added a new server.</p>
                <p style="margin:0;"><strong>User email:</strong> {escape(actor_email)}</p>
                <p style="margin:8px 0 0;"><strong>User full name:</strong> {escape(actor_name_value)}</p>
                <p style="margin:8px 0 0;"><strong>Server name:</strong> {escape(server_name)}</p>
                <p style="margin:8px 0 0;"><strong>Server id:</strong> {escape(str(server_id))}</p>
                <p style="margin:8px 0 0;"><strong>Time:</strong> {escape(now_str)}</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
""".strip()
    _send_admin_notification(subject, text_body, html_body)
