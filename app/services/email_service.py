"""Outbound email. Running a mail server is out of scope: production uses any
SMTP relay (SES, SendGrid, Mailgun); local prints to the console; tests capture
messages in memory."""

from __future__ import annotations

import smtplib
import sys
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

import anyio

from app.core.config import Settings


@dataclass(frozen=True)
class Email:
    to: str
    subject: str
    body: str


class EmailSender(Protocol):
    async def send(self, email: Email) -> None: ...


class ConsoleEmailSender:
    """Local development only: prints to stdout, outside the structured log stream."""

    async def send(self, email: Email) -> None:
        sys.stdout.write(
            f"\n----- EMAIL to {email.to}: {email.subject} -----\n{email.body}\n-----\n"
        )
        sys.stdout.flush()


@dataclass
class MemoryEmailSender:
    outbox: list[Email] = field(default_factory=list)

    async def send(self, email: Email) -> None:
        self.outbox.append(email)


class SmtpEmailSender:
    def __init__(self, settings: Settings) -> None:
        self._s = settings

    def _send_sync(self, email: Email) -> None:
        msg = EmailMessage()
        msg["From"] = self._s.email_from
        msg["To"] = email.to
        msg["Subject"] = email.subject
        msg.set_content(email.body)
        with smtplib.SMTP(self._s.smtp_host, self._s.smtp_port, timeout=10) as smtp:
            if self._s.smtp_starttls:
                smtp.starttls()
            if self._s.smtp_username and self._s.smtp_password:
                smtp.login(self._s.smtp_username, self._s.smtp_password.get_secret_value())
            smtp.send_message(msg)

    async def send(self, email: Email) -> None:
        await anyio.to_thread.run_sync(self._send_sync, email)


def build_email_sender(settings: Settings) -> EmailSender:
    if settings.email_backend == "smtp":
        return SmtpEmailSender(settings)
    if settings.email_backend == "memory":
        return MemoryEmailSender()
    return ConsoleEmailSender()


# ---------------------------------------------------------------- templates
def verification_email(to: str, link: str, hours: int) -> Email:
    return Email(
        to,
        "Verify your email address",
        f"Welcome! Confirm your address within {hours} hours:\n\n{link}\n\n"
        "If you did not create an account, ignore this message.",
    )


def duplicate_signup_email(to: str, reset_link_hint: str) -> Email:
    return Email(
        to,
        "Someone tried to sign up with your email",
        "Someone tried to create an account with this address, which already has one.\n"
        f"If it was you, sign in or reset your password: {reset_link_hint}\n"
        "If it was not you, you can ignore this message.",
    )


def reset_email(to: str, link: str, minutes: int) -> Email:
    return Email(
        to,
        "Reset your password",
        f"Use this link within {minutes} minutes to choose a new password:\n\n{link}\n\n"
        "Resetting signs you out everywhere. If you did not ask for this, ignore this message.",
    )
