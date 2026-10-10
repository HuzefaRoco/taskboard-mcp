import hashlib
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

from app.config import get_settings
from app.models import AuthorizationCode, OAuthClient, Token


AUTH = {
    "response_type": "code",
    "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
    "scope": "tasks:read tasks:write",
    "state": "xyz",
    "resource": "https://tasks.example.com",
}

TOKEN = {
    "grant_type": "authorization_code",
    "redirect_uri": AUTH["redirect_uri"],
    "resource": "https://tasks.example.com",
}


def test_token_exchanges_a_code_for_tokens(metadata_client, oauth_client, sign_in, authorize_code,
                                          db_session):
    sign_in("a@example.com", "pw")
    code, verifier = authorize_code(oauth_client)
    stored_code = db_session.get(AuthorizationCode, hashlib.sha256(code.encode()).hexdigest())
    user_id = stored_code.user_id
    before = datetime.now(timezone.utc)
    response = metadata_client.post("/token", data={
        **TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier,
    })
    after = datetime.now(timezone.utc)
    body = response.json()
    assert response.status_code == 200 and body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600 and type(body["expires_in"]) is int
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert db_session.get(AuthorizationCode, hashlib.sha256(code.encode()).hexdigest()) is None
    for kind, ttl in [("access", 3600), ("refresh", 2592000)]:
        raw = body[kind + "_token"]
        stored = db_session.get(Token, hashlib.sha256(raw.encode()).hexdigest())
        assert stored is not None and db_session.get(Token, raw) is None
        assert stored.kind == kind and stored.user_id == user_id
        assert stored.client_id == oauth_client and stored.scope == AUTH["scope"]
        assert stored.resource == TOKEN["resource"]
        assert before + timedelta(seconds=ttl) <= stored.expires_at <= after + timedelta(seconds=ttl)


@pytest.mark.parametrize("changes", [
    {"code_verifier": "wrong"}, {"code_verifier": ""}, {"code": "unknown"}, {"code": ""},
    {"client_id": "other"}, {"client_id": ""},
    {"redirect_uri": AUTH["redirect_uri"] + "/"}, {"redirect_uri": ""},
    {"resource": "https://evil.example.com"}, {"resource": ""},
])
def test_token_rejects_invalid_grants(metadata_client, oauth_client, authorize_code, db_session,
                                     changes):
    code, verifier = authorize_code(oauth_client)
    data = {**TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier}
    response = metadata_client.post("/token", data={**data, **changes})
    assert response.status_code == 400 and response.json() == {"error": "invalid_grant"}
    assert db_session.query(Token).count() == 0
    assert metadata_client.post("/token", data=data).status_code == 200


def test_token_rejects_a_replayed_code(metadata_client, oauth_client, sign_in, authorize_code):
    sign_in("a@example.com", "pw")
    code, verifier = authorize_code(oauth_client)
    data = {**TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier}
    assert metadata_client.post("/token", data=data).status_code == 200
    response = metadata_client.post("/token", data=data)
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


@pytest.mark.parametrize("stored_suffix", ["", "/mcp"])
@pytest.mark.parametrize("requested_suffix", ["", "/mcp"])
def test_token_accepts_the_mcp_url_as_resource(metadata_client, oauth_client, authorize_code,
                                             stored_suffix, requested_suffix):
    code, verifier = authorize_code(oauth_client, resource=TOKEN["resource"] + stored_suffix)
    response = metadata_client.post("/token", data={
        **TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier,
        "resource": TOKEN["resource"] + requested_suffix,
    })
    assert response.status_code == 200


@pytest.mark.parametrize("changes", ["expired", "wrong-resource", "plain"])
def test_token_rejects_invalid_stored_codes(metadata_client, oauth_client, authorize_code,
                                          db_session, changes):
    code, verifier = authorize_code(oauth_client)
    stored = db_session.get(AuthorizationCode, hashlib.sha256(code.encode()).hexdigest())
    if changes == "expired":
        stored.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif changes == "wrong-resource":
        stored.resource = "https://evil.example.com"
    else:
        stored.code_challenge_method = "plain"
    db_session.commit()
    response = metadata_client.post("/token", data={
        **TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier,
    })
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"
    assert db_session.query(Token).count() == 0


@pytest.mark.parametrize("data", [{}, {"grant_type": "refresh_token"}, {"grant_type": "unknown"}])
def test_token_rejects_unsupported_grant_type(client, data):
    response = client.post("/token", data=data)
    assert response.status_code == 400 and response.json()["error"] == "unsupported_grant_type"


@pytest.mark.parametrize("body", [b"code=%ZZ", b"code=\xff", b"code=a&code=b", b"code=%00"])
def test_token_rejects_malformed_forms(client, body):
    response = client.post("/token", content=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_request"


def test_token_rolls_back_database_failure(metadata_client, oauth_client, authorize_code,
                                         db_session, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    code, verifier = authorize_code(oauth_client)
    data = {**TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier}

    def fail_commit():
        raise SQLAlchemyError("private database details")

    with monkeypatch.context() as patch:
        patch.setattr(db_session, "commit", fail_commit)
        response = metadata_client.post("/token", data=data)
    assert response.status_code == 500 and response.json() == {"error": "server_error"}
    assert db_session.query(Token).count() == 0
    assert metadata_client.post("/token", data=data).status_code == 200


def test_token_uses_configured_lifetimes(metadata_client, oauth_client, authorize_code,
                                       db_session, monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", "120")
    monkeypatch.setenv("REFRESH_TOKEN_TTL_SECONDS", "600")
    get_settings.cache_clear()
    code, verifier = authorize_code(oauth_client)
    before = datetime.now(timezone.utc)
    response = metadata_client.post("/token", data={
        **TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier,
    })
    after = datetime.now(timezone.utc)
    assert response.status_code == 200 and response.json()["expires_in"] == 120
    for kind, ttl in [("access", 120), ("refresh", 600)]:
        raw = response.json()[kind + "_token"]
        stored = db_session.get(Token, hashlib.sha256(raw.encode()).hexdigest())
        assert before + timedelta(seconds=ttl) <= stored.expires_at <= after + timedelta(seconds=ttl)


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
    fields = HiddenFields(consent.text).fields
    assert fields.pop("consent_token")
    assert fields == params


def test_authorize_renders_consent_then_issues_a_code(
    client, oauth_client, make_user, sign_in, db_session,
):
    user = make_user("a@example.com", "pw")
    make_user("b@example.com", "pw")
    sign_in(user.email, "pw")
    params = {**AUTH, "client_id": oauth_client}
    consent = client.get("/authorize", params=params)
    assert consent.status_code == 200
    assert consent.headers["cache-control"] == "no-store"
    assert "ChatGPT" in consent.text and "tasks:read" in consent.text
    assert "tasks:write" in consent.text
    fields = HiddenFields(consent.text).fields
    assert fields.get("consent_token")
    assert {k: v for k, v in fields.items() if k != "consent_token"} == params
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
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    response = client.post("/authorize", data={**fields, "decision": "deny"},
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
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    response = client.post("/authorize", data={**fields, "decision": decision},
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
    fields = HiddenFields(client.get("/authorize", params={
        **AUTH, "client_id": oauth_client, "redirect_uri": callback, "state": state,
    }).text).fields
    response = client.post("/authorize", data={**fields, "decision": decision}, follow_redirects=False)
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
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields

    def fail_commit():
        raise SQLAlchemyError("private database details")

    with monkeypatch.context() as patch:
        patch.setattr(db_session, "commit", fail_commit)
        response = client.post("/authorize", data={**fields, "decision": "approve"})
    assert response.status_code == 500
    assert response.json() == {"error": "server_error"}
    assert db_session.query(AuthorizationCode).count() == 0


@pytest.mark.parametrize("display_consent", [False, True])
def test_same_site_forged_approval_cannot_write_a_code(
    client, make_user, sign_in, db_session, display_consent,
):
    client.base_url = "https://tasks.example.com"
    callback = "https://evil.example.com/callback"
    registered = client.post("/register", json={"client_name": "Attacker", "redirect_uris": [callback]})
    assert registered.status_code == 201
    make_user("victim@example.com", "pw")
    sign_in("victim@example.com", "pw")
    params = {**AUTH, "client_id": registered.json()["client_id"], "redirect_uri": callback}
    if display_consent:
        assert client.get("/authorize", params=params).status_code == 200
    response = client.post("/authorize", data={**params, "decision": "approve"},
                           headers={"Origin": "https://evil.example.com"}, follow_redirects=False)
    assert response.status_code == 403 and "location" not in response.headers
    assert db_session.query(AuthorizationCode).count() == 0


@pytest.mark.parametrize("token", ["wrong", "", "\u00e9"])
def test_wrong_consent_token_cannot_write_a_code(client, oauth_client, make_user, sign_in, db_session, token):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    response = client.post("/authorize", data={**fields, "consent_token": token, "decision": "approve"},
                           follow_redirects=False)
    assert response.status_code == 403 and "location" not in response.headers
    assert db_session.query(AuthorizationCode).count() == 0


def test_stale_consent_token_cannot_write_a_code(client, oauth_client, make_user, sign_in, db_session):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    params = {**AUTH, "client_id": oauth_client}
    stale = HiddenFields(client.get("/authorize", params=params).text).fields
    fresh = HiddenFields(client.get("/authorize", params=params).text).fields
    response = client.post("/authorize", data={**stale, "decision": "approve"}, follow_redirects=False)
    assert response.status_code == 403
    assert db_session.query(AuthorizationCode).count() == 0
    assert stale["consent_token"] != fresh["consent_token"]
    assert client.post("/authorize", data={**fresh, "decision": "approve"}, follow_redirects=False).status_code == 303


def test_expired_consent_token_cannot_write_a_code(
    client, oauth_client, make_user, sign_in, db_session, monkeypatch,
):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    expired_time = datetime.now(timezone.utc).timestamp() + 601
    monkeypatch.setattr("app.oauth.time", lambda: expired_time, raising=False)
    response = client.post("/authorize", data={**fields, "decision": "approve"}, follow_redirects=False)
    assert response.status_code == 403
    assert db_session.query(AuthorizationCode).count() == 0


@pytest.mark.parametrize("changes", [
    {"scope": "tasks:read"}, {"state": "attacker"},
    {"code_challenge": "A" * 43}, {"resource": "https://other.example.com"},
])
def test_consent_token_is_bound_to_displayed_parameters(
    client, oauth_client, make_user, sign_in, db_session, changes,
):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    response = client.post("/authorize", data={**fields, **changes, "decision": "approve"},
                           follow_redirects=False)
    assert response.status_code == 403
    assert db_session.query(AuthorizationCode).count() == 0


def test_consent_token_cannot_transfer_to_another_signed_in_session(
    client, oauth_client, make_user, sign_in, db_session,
):
    make_user("a@example.com", "pw")
    make_user("b@example.com", "pw")
    sign_in("a@example.com", "pw")
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    sign_in("b@example.com", "pw")
    response = client.post("/authorize", data={**fields, "decision": "approve"}, follow_redirects=False)
    assert response.status_code == 403
    assert db_session.query(AuthorizationCode).count() == 0


@pytest.mark.parametrize("decision", ["approve", "deny"])
def test_completed_consent_cannot_be_resubmitted(
    client, oauth_client, make_user, sign_in, db_session, decision,
):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    fields = HiddenFields(client.get("/authorize", params={**AUTH, "client_id": oauth_client}).text).fields
    assert client.post("/authorize", data={**fields, "decision": decision}, follow_redirects=False).status_code == 303
    before = db_session.query(AuthorizationCode).count()
    response = client.post("/authorize", data={**fields, "decision": "approve"}, follow_redirects=False)
    assert response.status_code == 403
    assert db_session.query(AuthorizationCode).count() == before


@pytest.mark.parametrize("reserved", ["decision", "consent_token"])
def test_authorize_rejects_reserved_get_parameters(client, oauth_client, make_user, sign_in, reserved):
    make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    response = client.get("/authorize", params={**AUTH, "client_id": oauth_client, reserved: "deny"},
                          follow_redirects=False)
    assert response.status_code == 400


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
