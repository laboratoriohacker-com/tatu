import pytest
from pydantic import ValidationError
from app.schemas.event import EventCreate, EventResponse
from app.schemas.auth import LoginRequest, ApiKeyCreate, ApiKeyResponse
from app.schemas.stats import OverviewStats, TimelineBucket, PaginatedResponse


def test_event_create_valid():
    event = EventCreate(
        hook_name="Secrets Leak Prevention",
        hook_event="PreToolUse",
        severity="critical",
        status="blocked",
        message="AWS key detected",
        developer="carlos.m",
        repository="payments-api",
        session_id="sess-123",
        tool_name="Write",
    )
    assert event.hook_name == "Secrets Leak Prevention"


def test_event_create_invalid_severity():
    with pytest.raises(ValidationError):
        EventCreate(
            hook_name="Test",
            hook_event="PreToolUse",
            severity="invalid",
            status="blocked",
            message="test",
            developer="dev",
            repository="repo",
            session_id="sess",
        )


def test_event_create_nullable_tool_name():
    event = EventCreate(
        hook_name="Env Hardening",
        hook_event="SessionStart",
        severity="info",
        status="allowed",
        message="Env check passed",
        developer="dev",
        repository="repo",
        session_id="sess",
        tool_name=None,
    )
    assert event.tool_name is None


def test_login_request():
    req = LoginRequest(email="user@tatu.local")
    assert req.email == "user@tatu.local"


def test_api_key_create():
    key = ApiKeyCreate(label="production-hooks")
    assert key.label == "production-hooks"


def test_overview_stats():
    stats = OverviewStats(
        total_events=1000,
        total_blocks=50,
        active_sessions=5,
        secrets_caught=12,
        block_rate=5.0,
    )
    assert stats.total_events == 1000


def test_paginated_response():
    resp = PaginatedResponse(
        items=[],
        total=100,
        page=1,
        per_page=50,
        pages=2,
    )
    assert resp.pages == 2
