import pytest

from app.config import get_settings


@pytest.fixture
def metadata_client(client, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://tasks.example.com/")
    get_settings.cache_clear()
    try:
        yield client
    finally:
        get_settings.cache_clear()


def test_protected_resource_metadata(metadata_client):
    response = metadata_client.get("/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "resource": "https://tasks.example.com",
        "authorization_servers": ["https://tasks.example.com"],
        "scopes_supported": ["tasks:read", "tasks:write"],
    }


def test_authorization_server_metadata(metadata_client):
    response = metadata_client.get("/.well-known/oauth-authorization-server")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {
        "issuer": "https://tasks.example.com",
        "authorization_endpoint": "https://tasks.example.com/authorize",
        "token_endpoint": "https://tasks.example.com/token",
        "registration_endpoint": "https://tasks.example.com/register",
        "response_types_supported": ["code"],
        "scopes_supported": ["tasks:read", "tasks:write"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }


def test_metadata_uses_configured_base_url(metadata_client, monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://other.example.com/taskboard/")
    get_settings.cache_clear()
    resource = metadata_client.get("/.well-known/oauth-protected-resource").json()
    server = metadata_client.get("/.well-known/oauth-authorization-server").json()
    assert resource["resource"] == "https://other.example.com/taskboard"
    assert resource["authorization_servers"] == ["https://other.example.com/taskboard"]
    assert server["issuer"] == "https://other.example.com/taskboard"
    assert server["authorization_endpoint"] == "https://other.example.com/taskboard/authorize"
    assert server["token_endpoint"] == "https://other.example.com/taskboard/token"
    assert server["registration_endpoint"] == "https://other.example.com/taskboard/register"


def test_required_scopes():
    from app.oauth import required_scopes

    assert required_scopes() == ["tasks:read", "tasks:write"]
