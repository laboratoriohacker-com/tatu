import os
import pytest


def test_settings_loads_defaults():
    os.environ.setdefault("TATU_SECRET_KEY", "testsecret")
    from app.config import Settings
    s = Settings()
    assert s.cors_origins == ["http://localhost:5173"]
    assert s.host == "0.0.0.0"
    assert s.port == 8000
    assert s.log_level == "info"
    assert s.smtp_host == "localhost"
    assert s.smtp_port == 1025
    assert s.smtp_use_tls is False
    assert s.smtp_from == "noreply@tatu.local"
    assert s.admin_email == "test@tatu.local"
