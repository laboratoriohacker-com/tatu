import pytest
from app.auth import (
    hash_api_key, verify_api_key,
    create_signed_cookie, decode_signed_cookie,
    create_invite_token, decode_invite_token,
)


def test_hash_and_verify_api_key():
    raw_key = "tatu_abc123def456"
    hashed = hash_api_key(raw_key)
    assert hashed != raw_key
    assert verify_api_key(raw_key, hashed) is True
    assert verify_api_key("wrong_key", hashed) is False


def test_create_and_decode_signed_cookie():
    cookie_value = create_signed_cookie("user-123", "admin", "test@tatu.local")
    data = decode_signed_cookie(cookie_value)
    assert data is not None
    assert data["user_id"] == "user-123"
    assert data["role"] == "admin"
    assert data["email"] == "test@tatu.local"


def test_decode_signed_cookie_tampered():
    assert decode_signed_cookie("tampered_value") is None


def test_create_and_decode_invite_token():
    token = create_invite_token("user-456")
    data = decode_invite_token(token)
    assert data is not None
    assert data["user_id"] == "user-456"
    assert data["purpose"] == "invite"


def test_decode_invite_token_tampered():
    assert decode_invite_token("bad_token") is None


def test_session_cookie_not_valid_as_invite():
    cookie = create_signed_cookie("user-123", "admin", "test@tatu.local")
    assert decode_invite_token(cookie) is None
