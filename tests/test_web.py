import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from starlette.requests import Request


@pytest.fixture
def protected_client(client, monkeypatch):
    from fastapi import Depends

    from app.main import app
    from app.models import User
    from app.web import require_user

    monkeypatch.setattr(app.router, "routes", list(app.router.routes))

    @app.get("/_test/user")
    def protected_route(user: User = Depends(require_user)):
        return {"id": str(user.id)}

    return client


def test_login_rejects_a_wrong_password(client, make_user):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": "a@example.com", "password": "wrong"})
    assert r.status_code == 401
    assert "session" not in client.cookies
    assert "wrong" not in r.text


def test_login_is_case_and_space_insensitive_and_preserves_next(client, make_user):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": " A@Example.COM ", "password": "right",
                                    "next": "/connect"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/connect"


def test_logout_clears_the_session(protected_client, make_user, sign_in):
    user = make_user("a@example.com", "right")
    sign_in("a@example.com", "right")
    assert protected_client.get("/_test/user").json() == {"id": str(user.id)}
    r = protected_client.post("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert "session" not in protected_client.cookies
    r = protected_client.get("/_test/user", follow_redirects=False)
    assert r.headers["location"] == "/login?next=%2F_test%2Fuser"


def test_login_form_preserves_next_and_escapes_html(client):
    r = client.get("/login", params={"next": '/connect?state="<tag>'})
    assert r.status_code == 200
    assert 'name="email"' in r.text and 'type="password"' in r.text
    assert 'name="next"' in r.text
    assert "/connect?state=&#34;&lt;tag&gt;" in r.text
    assert 'href="/connect"' in r.text


def test_login_rejects_an_unknown_user(client):
    r = client.post("/login", data={"email": "unknown@example.com", "password": "pw"})
    assert r.status_code == 401
    assert "session" not in client.cookies


def test_login_defaults_to_root_and_sets_cookie(protected_client, make_user):
    user = make_user("a@example.com", "right")
    r = protected_client.post("/login", data={"email": user.email, "password": "right"},
                              follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    assert "httponly" in r.headers["set-cookie"].lower()
    assert "samesite=lax" in r.headers["set-cookie"].lower()
    assert protected_client.get("/_test/user").json() == {"id": str(user.id)}


@pytest.mark.parametrize("next_path", ["https://evil.example", "//evil.example", "/\\evil.example",
                                      "/connect\r\nX-Injected: yes"])
def test_login_does_not_redirect_outside_the_website(client, make_user, next_path):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": "a@example.com", "password": "right",
                                   "next": next_path}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"


def test_failed_login_keeps_next_without_echoing_password(client, make_user):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": "a@example.com", "password": "secret-wrong",
                                   "next": "/connect?state=abc"})
    assert r.status_code == 401
    assert 'value="/connect?state=abc"' in r.text
    assert "secret-wrong" not in r.text


@pytest.mark.parametrize("user_id", [None, "not-a-uuid", 123, {}, str(uuid4())])
def test_current_user_returns_none_for_missing_invalid_or_deleted_users(db_session, user_id):
    from app.web import current_user

    request = Request({"type": "http", "session": {"user_id": user_id}})
    assert current_user(request, db_session) is None


def test_invalid_cookie_cannot_authenticate(protected_client, make_user):
    make_user("a@example.com", "right")
    protected_client.cookies.set("session", "tampered")
    r = protected_client.get("/_test/user", follow_redirects=False)
    assert r.status_code == 303


@pytest.mark.parametrize("content_type", [None, "application/json", "text/plain",
                                         "multipart/form-data; boundary=test"])
def test_login_rejects_unsupported_content_types(client, content_type):
    headers = {"content-type": content_type} if content_type else {}
    r = client.post("/login", content=b"email=a%40example.com&password=right", headers=headers)
    assert r.status_code == 415
    assert "session" not in client.cookies


@pytest.mark.parametrize("body", [b"email=a%40example.com&password=%ZZ",
                                 b"email=a%40example.com&password=%FF",
                                 b"email=a%40example.com&password=\xff",
                                 b"email=a%40example.com&password",
                                 b"email=a%40example.com&password=one&password=two",
                                 b"email=a%00%40example.com&password=right",
                                 b"email=a&password=b&next=/&extra=value"])
def test_login_rejects_malformed_urlencoded_bodies(client, body):
    r = client.post("/login", content=body,
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 400
    assert "session" not in client.cookies


@pytest.mark.parametrize("body", [b"", b"email=a%40example.com", b"password=right",
                                 b"email=&password=right", b"email=a&password=",
                                 b"email=+++&password=right"])
def test_login_rejects_missing_or_empty_credentials(client, body):
    r = client.post("/login", content=body,
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 422
    assert "session" not in client.cookies


def test_login_accepts_utf8_urlencoded_credentials_and_content_type_parameters(client, make_user):
    make_user("a@example.com", "p+&=\u00e9")
    r = client.post("/login", content=b"email=a%40example.com&password=p%2B%26%3D%C3%A9&next=%2Fconnect",
                    headers={"content-type": "Application/X-WWW-Form-Urlencoded; charset=UTF-8"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/connect"


def test_login_rejects_oversized_forms(client):
    r = client.post("/login", content=b"email=a&password=" + b"x" * 65536,
                    headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert "session" not in client.cookies


def test_app_starts_without_multipart_support():
    result = subprocess.run(
        [sys.executable, "-c", """
import sys
sys.modules["multipart"] = None
sys.modules["python_multipart"] = None
from app.main import app
from fastapi.testclient import TestClient
with TestClient(app) as client:
    assert client.get("/login").status_code == 200
"""],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
