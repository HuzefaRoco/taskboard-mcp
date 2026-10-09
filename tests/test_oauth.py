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


@pytest.mark.parametrize("redirect_uris", [
    ["https://chatgpt.com/connector_platform_oauth_redirect"],
    ["http://localhost:8080/callback", "https://example.com/callback?x=1"],
])
def test_register_creates_a_public_client(client, db_session, redirect_uris):
    from uuid import UUID

    from app.models import OAuthClient

    response = client.post("/register", json={
        "client_name": "ChatGPT", "redirect_uris": redirect_uris,
    })
    assert response.status_code == 201
    body = response.json()
    assert UUID(body["client_id"]).version == 4
    assert len(body["client_id"]) == 32
    assert body == {
        "client_id": body["client_id"], "client_name": "ChatGPT",
        "redirect_uris": redirect_uris, "token_endpoint_auth_method": "none",
    }
    stored = db_session.get(OAuthClient, body["client_id"])
    assert stored.client_name == "ChatGPT"
    assert stored.redirect_uris == redirect_uris


@pytest.mark.parametrize("metadata", [
    {"client_name": "x"}, {}, None, [],
    *[{"redirect_uris": value} for value in [
        [], None, "https://example.com", [None], [123], ["/callback"],
        ["http://example.com/callback"], ["http://localhost.evil.com"],
        ["https:///callback"], ["https://"], ["https://[broken"],
        ["https://example.com:bad/callback"], ["https://example.com/#fragment"],
        ["https://user:password@example.com/callback"],
        ["https://example.com/\ncallback"], ["https://example.com/ callback"],
        ["https://example.com/\\callback"],
    ]],
    {"redirect_uris": ["https://example.com"], "client_name": None},
    {"redirect_uris": ["https://example.com"], "client_name": 123},
    {"redirect_uris": ["https://example.com"], "client_name": "bad\x00name"},
])
def test_register_rejects_invalid_metadata(client, db_session, metadata):
    from app.models import OAuthClient

    before = db_session.query(OAuthClient).count()
    response = client.post("/register", json=metadata)
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_client_metadata"}
    assert db_session.query(OAuthClient).count() == before


def test_register_rejects_malformed_json(client):
    response = client.post("/register", content="{", headers={"Content-Type": "application/json"})
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_client_metadata"}


def test_oauth_client_fixture(oauth_client, db_session):
    from app.models import OAuthClient

    stored = db_session.get(OAuthClient, oauth_client)
    assert stored.client_name == "ChatGPT"
    assert stored.redirect_uris == ["https://chatgpt.com/connector_platform_oauth_redirect"]


def test_register_defaults_client_name_and_generates_unique_ids(client):
    metadata = {"redirect_uris": ["https://example.com/callback"]}
    first = client.post("/register", json=metadata)
    second = client.post("/register", json=metadata)
    assert first.status_code == second.status_code == 201
    assert first.json()["client_name"] == ""
    assert first.json()["client_id"] != second.json()["client_id"]


def test_register_rolls_back_database_failure(client, db_session, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    from app.models import OAuthClient

    def fail_commit():
        raise SQLAlchemyError("private database details")

    with monkeypatch.context() as patch:
        patch.setattr(db_session, "commit", fail_commit)
        response = client.post("/register", json={"redirect_uris": ["https://example.com"]})
    assert response.status_code == 500
    assert response.json() == {"error": "server_error"}
    assert db_session.query(OAuthClient).count() == 0
    assert client.post("/register", json={"redirect_uris": ["https://example.com"]}).status_code == 201
