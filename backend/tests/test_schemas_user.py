import pytest
from pydantic import ValidationError

from app.schemas.user import UserInvite, UserUpdate, UserResponse
from app.schemas.auth import LoginRequest, OtpVerifyRequest


def test_user_invite_valid():
    invite = UserInvite(email="user@example.com", name="Test User", role="admin")
    assert invite.email == "user@example.com"
    assert invite.name == "Test User"
    assert invite.role == "admin"


def test_user_invite_default_role():
    invite = UserInvite(email="user@example.com", name="Test User")
    assert invite.role == "viewer"


def test_user_invite_invalid_role():
    with pytest.raises(ValidationError):
        UserInvite(email="user@example.com", name="Test User", role="superadmin")


def test_login_request():
    req = LoginRequest(email="user@example.com")
    assert req.email == "user@example.com"


def test_otp_verify_request():
    req = OtpVerifyRequest(email="user@example.com", code="123456")
    assert req.email == "user@example.com"
    assert req.code == "123456"
