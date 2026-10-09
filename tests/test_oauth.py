import hashlib
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from app.config import get_settings
from app.models import AuthorizationCode, OAuthClient


AUTH = {
    "response_type": "code",
    "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
    "scope": "tasks:read tasks:write",
    "state": "xyz",
    "resource": "https://tasks.example.com",
}


class HiddenFields(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input" and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")


def test_authorize_redirects_to_login_when_signed_out(client, oauth_client, make_user):
    params = {**AUTH, "client_id": oauth_client, "state": "a+&=\"<tag>"}
    response = client.get("/authorize", params=params, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login?next=")
    next_url = parse_qs(urlsplit(response.headers["location"]).query)["next"][0]
    assert next_url == "/authorize?" + response.request.url.query.decode()
    login = client.get(response.headers["location"])
    assert HiddenFields(login.text).fields["next"] == next_url
    make_user("a@example.com", "pw")
    logged_in = client.post("/login", data={
        "email": "a@example.com", "password": "pw", "next": next_url,
    }, follow_redirects=False)
    assert logged_in.headers["location"] == next_url
    consent = client.get(next_url)
    assert consent.status_code == 200
    assert HiddenFields(consent.text).fields == params


def test_authorize_renders_consent_then_issues_a_code(
    client, oauth_client, make_user, sign_in, db_session,
):
    user = make_user("a@example.com", "pw")
    make_user("b@example.com", "pw")
    sign_in(user.email, "pw")
    params = {**AUTH, "client_id": oauth_client}
    consent = client.get("/authorize", params=params)
    assert consent.status_code == 200
    assert "ChatGPT" in consent.text and "tasks:read" in consent.text
    assert "tasks:write" in consent.text
    fields = HiddenFields(consent.text).fields
    assert fields == params
    assert 'name="decision" value="approve"' in consent.text
    assert 'name="decision" value="deny"' in consent.text
    before = datetime.now(timezone.utc)
    response = client.post("/authorize", data={**fields, "decision": "approve"},
                           follow_redirects=False)
    after = datetime.now(timezone.utc)
    assert response.status_code == 303
    assert response.headers["location"].startswith(AUTH["redirect_uri"] + "?")
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["state"] == ["xyz"]
    code = query["code"][0]
    stored = db_session.get(AuthorizationCode, hashlib.sha256(code.encode()).hexdigest())
    assert stored is not None and stored.code_hash != code
    assert db_session.get(AuthorizationCode, code) is None
    assert stored.user_id == user.id and stored.client_id == oauth_client
    for field in ("redirect_uri", "scope", "code_challenge", "code_challenge_method", "resource"):
        assert getattr(stored, field) == AUTH[field]
    assert 600 <= (stored.expires_at - before).total_seconds() <= 600 + (after - before).total_seconds()


@pytest.mark.parametrize("method", ["get", "post"])
@pytest.mark.parametrize("changes", [
    {"client_id": "unknown"}, {"response_type": "token"},
    {"redirect_uri": "https://evil.example/cb"},
    {"redirect_uri": AUTH["redirect_uri"] + "/"},
    {"code_challenge_method": "plain"}, {"code_challenge": ""},
    {"code_challenge": "invalid"}, {"scope": "tasks:read offline_access"},
    {"scope": "admin"}, {"scope": ""}, {"resource": ""},
])
def test_authorize_rejects_invalid_parameters(
    client, oauth_client, make_user, sign_in, db_session, method, changes,
):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    params = {**AUTH, "client_id": oauth_client, **changes}
    response = (client.get("/authorize", params=params, follow_redirects=False) if method == "get"
                else client.post("/authorize", data={**params, "decision": "approve"},
                                 follow_redirects=False))
    assert response.status_code == 400 and "location" not in response.headers
    assert db_session.query(AuthorizationCode).count() == 0


def test_deny_returns_access_denied(client, oauth_client, make_user, sign_in, db_session):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    response = client.post("/authorize", data={**AUTH, "client_id": oauth_client, "decision": "deny"},
                           follow_redirects=False)
    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query) == {
        "error": ["access_denied"], "state": ["xyz"],
    }
    assert db_session.query(AuthorizationCode).count() == 0


def test_signed_out_post_does_not_issue_a_code(client, oauth_client, db_session):
    response = client.post("/authorize", data={**AUTH, "client_id": oauth_client, "decision": "approve"},
                           follow_redirects=False)
    assert response.status_code == 303
    next_url = parse_qs(urlsplit(response.headers["location"]).query)["next"][0]
    assert parse_qs(urlsplit(next_url).query) == {k: [v] for k, v in {**AUTH, "client_id": oauth_client}.items()}
    assert db_session.query(AuthorizationCode).count() == 0


@pytest.mark.parametrize("decision", ["", "allow", "APPROVE"])
def test_authorize_requires_an_explicit_decision(client, oauth_client, make_user, sign_in, decision):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    response = client.post("/authorize", data={**AUTH, "client_id": oauth_client, "decision": decision},
                           follow_redirects=False)
    assert response.status_code == 400


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_authorize_preserves_callback_query_and_encodes_state(
    client, oauth_client, make_user, sign_in, db_session, decision,
):
    callback = "https://example.com/callback?existing=a%2Bb"
    db_session.get(OAuthClient, oauth_client).redirect_uris = [callback]
    db_session.flush()
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    state = "a+&=\"<tag>"
    response = client.post("/authorize", data={
        **AUTH, "client_id": oauth_client, "redirect_uri": callback, "state": state, "decision": decision,
    }, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].startswith(callback + "&")
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["existing"] == ["a+b"] and query["state"] == [state]
    assert ("code" if decision == "approve" else "error") in query


def test_authorize_escapes_client_name(client, oauth_client, make_user, sign_in, db_session):
    db_session.get(OAuthClient, oauth_client).client_name = "<script>alert(1)</script>"
    db_session.flush()
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    response = client.get("/authorize", params={**AUTH, "client_id": oauth_client})
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>" not in response.text


@pytest.mark.parametrize("body", [b"client_id=%ZZ", b"client_id=\xff", b"client_id=a&client_id=b"])
def test_authorize_rejects_malformed_forms(client, body):
    response = client.post("/authorize", content=body,
                           headers={"content-type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400


def test_authorize_rejects_duplicate_query_parameters(client, oauth_client):
    response = client.get("/authorize?" + urlencode({**AUTH, "client_id": oauth_client})
                          + "&client_id=other", follow_redirects=False)
    assert response.status_code == 400


def test_authorize_rejects_oversized_forms(client):
    response = client.post("/authorize", content=b"state=" + b"x" * 65536,
                           headers={"content-type": "application/x-www-form-urlencoded"})
    assert response.status_code == 413


def test_authorize_rejects_non_form_bodies(client):
    assert client.post("/authorize", json=AUTH).status_code == 415


def test_authorize_rolls_back_database_failure(client, oauth_client, make_user, sign_in, db_session, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")

    def fail_commit():
        raise SQLAlchemyError("private database details")

    with monkeypatch.context() as patch:
        patch.setattr(db_session, "commit", fail_commit)
        response = client.post("/authorize", data={**AUTH, "client_id": oauth_client, "decision": "approve"})
    assert response.status_code == 500
    assert response.json() == {"error": "server_error"}
    assert db_session.query(AuthorizationCode).count() == 0


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
    ["https://example.com/call%20back?next=%2Ftasks&x=a:b@c/?d=1",
     "http://localhost:8080/call%2Fback?x=%25", "https://[::1]:8443/callback"],
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
        ["https://exa<mple.com/callback"], ["https://example.com/%ZZ"],
        ["https://exa>mple.com/callback"], ["https://exa|mple.com/callback"],
        ["https://exa{mple.com/callback"], ["https://exa\"mple.com/callback"],
        ["https://example.com/%"], ["https://example.com/%2"],
        ["https://example.com/callback?next=%GG"], ["https://exa%ZZmple.com/callback"],
        ["https://example.com/call<back"], ["https://example.com/callback?x={bad}"],
        ["https://example.com/callback", "https://example.com/%ZZ"],
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
