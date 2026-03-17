"""Email sending service using aiosmtplib."""
from email.message import EmailMessage
import aiosmtplib
from app.config import settings


async def send_email(to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    await aiosmtplib.send(
        msg,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_user or None,
        password=settings.smtp_password or None,
        use_tls=settings.smtp_use_tls,
    )


async def send_otp_email(to: str, code: str) -> None:
    subject = f"Tatu — Your login code: {code}"
    body = (
        f"Your one-time login code is: {code}\n\n"
        f"This code expires in 5 minutes.\n\n"
        f"If you did not request this code, ignore this email."
    )
    await send_email(to, subject, body)


async def send_invite_email(to: str, invite_url: str, inviter_name: str) -> None:
    subject = "Tatu — You've been invited"
    body = (
        f"You've been invited to join the Tatu DevSecOps platform by {inviter_name}.\n\n"
        f"Click here to accept your invitation:\n{invite_url}\n\n"
        f"This link expires in 24 hours."
    )
    await send_email(to, subject, body)
