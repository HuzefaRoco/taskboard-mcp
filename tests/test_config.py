import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://tasks.example.com/")
    monkeypatch.setenv("SESSION_SECRET", "s3cret")
    s = Settings()
    assert s.database_url.endswith("/db")
    assert s.public_base_url == "https://tasks.example.com"
    assert s.access_token_ttl_seconds == 3600
    assert s.refresh_token_ttl_seconds == 2592000


def test_settings_require_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
