from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from ..errors import APIError
from ..settings import get_settings

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class MailPayload:
    to_email: str
    subject: str
    text_body: str
    html_body: str | None = None


class SMTPMailer:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str | None,
        password: str | None,
        from_email: str,
        use_tls: bool,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.use_tls = use_tls

    def send(self, payload: MailPayload) -> None:
        message = EmailMessage()
        message["From"] = self.from_email
        message["To"] = payload.to_email
        message["Subject"] = payload.subject
        message.set_content(payload.text_body)
        if payload.html_body:
            message.add_alternative(payload.html_body, subtype="html")

        with smtplib.SMTP(self.host, self.port, timeout=20) as smtp:
            smtp.ehlo()
            if self.use_tls:
                smtp.starttls()
                smtp.ehlo()
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(message)


def get_mailer() -> SMTPMailer:
    settings = get_settings()
    if not settings.smtp_host or not settings.smtp_from:
        raise APIError(
            code="bad_request",
            message="SMTP is not configured",
            status_code=400,
            details={"required": ["SMTP_HOST", "SMTP_FROM"]},
        )
    return SMTPMailer(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user,
        password=settings.smtp_pass,
        from_email=settings.smtp_from,
        use_tls=settings.smtp_tls,
    )


def send_email(payload: MailPayload) -> None:
    mailer = get_mailer()
    mailer.send(payload)
    logger.info(
        "email_sent",
        extra={"event": "email_sent", "to": payload.to_email, "subject": payload.subject},
    )
