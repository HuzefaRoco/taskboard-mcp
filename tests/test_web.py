import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from starlette.requests import Request


def test_task_list_shows_only_the_signed_in_users_tasks(client, make_user, make_task):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    make_task(a, "mine", "open")
    make_task(b, "theirs", "open")
    client.post("/login", data={"email": "a@example.com", "password": "pw"})
    body = client.get("/").text
    assert "mine" in body and "theirs" not in body


def test_task_list_filters_by_status(client, make_user, make_task):
    a = make_user("a@example.com", "pw")
    make_task(a, "still open", "open")
    make_task(a, "all done", "completed")
    client.post("/login", data={"email": "a@example.com", "password": "pw"})
    body = client.get("/", params={"status": "completed"}).text
    assert "all done" in body and "still open" not in body


def test_task_list_requires_a_session(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login")


@pytest.mark.parametrize("status", [None, "", "complete", "invalid"])
def test_task_list_ignores_invalid_status(client, make_user, make_task, sign_in, status):
    user = make_user("a@example.com", "pw")
    make_task(user, "still open", "open")
    make_task(user, "all done", "completed")
    sign_in(user.email, "pw")
    response = client.get("/", params={} if status is None else {"status": status})
    assert response.status_code == 200
    assert "still open" in response.text and "all done" in response.text


def test_task_list_open_filter_and_html_escaping(client, make_user, make_task, sign_in):
    user = make_user("a@example.com", "pw")
    make_task(user, "<script>alert(1)</script>", "open")
    make_task(user, "all done", "completed")
    sign_in(user.email, "pw")
    response = client.get("/", params={"status": "open"})
    assert response.status_code == 200
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in response.text
    assert "<script>alert(1)</script>" not in response.text
    assert "all done" not in response.text


def test_task_filters_select_only_the_table_and_offer_no_mutation_controls(
    client, make_user, sign_in,
):
    user = make_user("a@example.com", "pw")
    sign_in(user.email, "pw")
    body = client.get("/").text
    assert 'hx-get="/"' in body and 'hx-get="/?status=completed"' in body
    assert body.count('hx-target="#task-table"') == 2
    assert body.count('hx-select="#task-table"') == 2
    assert body.count('hx-swap="outerHTML"') == 2
    assert 'id="task-table"' in body
    assert "htmx.min.js" in body
    assert "<form" not in body and "<button" not in body


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_root_rejects_task_mutations(client, make_user, make_task, sign_in, method):
    user = make_user("a@example.com", "pw")
    make_task(user, "unchanged", "open")
    sign_in(user.email, "pw")
    response = client.request(method, "/", json={"title": "changed", "status": "completed"})
    assert response.status_code == 405
    assert "unchanged" in client.get("/").text
    assert ">changed</td>" not in client.get("/").text


def test_task_helpers_add_and_list_in_creation_order(db_session, make_user, make_task):
    from app import tasks

    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    newer = make_task(a, "newer", "completed")
    older = tasks.add_task(db_session, a.id, "older")
    older.created_at = datetime.now(timezone.utc) - timedelta(days=1)
    make_task(b, "theirs", "open")
    db_session.flush()
    assert older.id is not None and older.status == "open" and older.user_id == a.id
    assert tasks.list_tasks(db_session, a.id) == [older, newer]
    assert tasks.list_tasks(db_session, a.id, "open") == [older]
    assert tasks.list_tasks(db_session, a.id, "completed") == [newer]


def test_task_helpers_complete_persists_and_is_idempotent(db_session, make_user):
    from app import tasks

    user = make_user("a@example.com", "pw")
    task = tasks.add_task(db_session, user.id, "mine")
    task_id = task.id
    assert tasks.complete_task(db_session, user.id, task_id).status == "completed"
    db_session.expire_all()
    assert tasks.list_tasks(db_session, user.id, "completed")[0].id == task_id
    assert tasks.complete_task(db_session, user.id, task_id).status == "completed"


def test_task_helpers_hide_other_users_tasks_and_missing_ids(db_session, make_user, make_task):
    from app import tasks

    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    task_id = make_task(b, "theirs", "open").id
    for missing_id in (task_id, uuid4()):
        with pytest.raises(tasks.TaskNotFound):
            tasks.complete_task(db_session, a.id, missing_id)
    assert tasks.list_tasks(db_session, a.id) == []
    assert tasks.list_tasks(db_session, b.id)[0].status == "open"


@pytest.mark.parametrize("operation", ["add", "list", "complete"])
@pytest.mark.parametrize("pending_change", ["update", "insert", "delete"])
def test_task_helpers_do_not_flush_unrelated_tasks(
    db_session, make_user, make_task, operation, pending_change,
):
    from sqlalchemy import select

    from app import tasks
    from app.models import Task

    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    mine = make_task(a, "mine", "open")
    make_task(b, "theirs", "open")
    unrelated = tasks.list_tasks(db_session, b.id)[0]
    if pending_change == "update":
        unrelated.title = "unauthorized change"
    elif pending_change == "insert":
        unrelated = Task(user_id=b.id, title="pending insert", status="open")
        db_session.add(unrelated)
    else:
        db_session.delete(unrelated)

    if operation == "add":
        added = tasks.add_task(db_session, a.id, "added")
        assert added.id is not None and added.user_id == a.id and added.status == "open"
    elif operation == "list":
        assert tasks.list_tasks(db_session, a.id) == [mine]
    else:
        assert tasks.complete_task(db_session, a.id, mine.id).status == "completed"

    # Read stored values directly, bypassing autoflush and the ORM identity map.
    connection = db_session.connection()
    assert connection.execute(
        select(Task.title, Task.status).where(Task.user_id == b.id)
    ).all() == [("theirs", "open")]
    assert unrelated in getattr(db_session, {"update": "dirty", "insert": "new",
                                            "delete": "deleted"}[pending_change])
    own_rows = connection.execute(
        select(Task.title, Task.status).where(Task.user_id == a.id).order_by(Task.title)
    ).all()
    expected = [("mine", "completed" if operation == "complete" else "open")]
    if operation == "add":
        expected.insert(0, ("added", "open"))
    assert own_rows == expected


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
