import pytest
from unittest.mock import patch, AsyncMock

import app.services.email_service  # ensure module is imported before patching
from app.services.email_service import send_otp_email, send_invite_email


@pytest.mark.asyncio
async def test_send_otp_email():
    with patch("app.services.email_service.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        await send_otp_email("test@tatu.local", "123456")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "123456" in msg.get_content()
        assert msg["To"] == "test@tatu.local"


@pytest.mark.asyncio
async def test_send_invite_email():
    with patch("app.services.email_service.aiosmtplib.send", new_callable=AsyncMock) as mock_send:
        await send_invite_email("new@tatu.local", "https://tatu.local/accept?token=abc", "Admin")
        mock_send.assert_called_once()
        msg = mock_send.call_args[0][0]
        assert "accept?token=abc" in msg.get_content()
        assert "Admin" in msg.get_content()
