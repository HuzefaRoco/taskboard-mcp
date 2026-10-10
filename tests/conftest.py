import base64
import hashlib
import os
import secrets
from collections.abc import Callable, Generator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

    from app.models import Task, User

# Models import app.db during collection, so select the test database first.
if os.environ.get("TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def database() -> Generator[Engine, None, None]:
    test_url = os.environ.get("TEST_DATABASE_URL")
    if not test_url:
        pytest.fail("Set TEST_DATABASE_URL to a dedicated Postgres test database")
    if make_url(test_url).get_backend_name() != "postgresql":
        pytest.fail("TEST_DATABASE_URL must use Postgres, never SQLite")

    from app.db import engine

    if engine.url != make_url(test_url):
        pytest.fail("app.db was initialized before the test database was selected")
    try:
        command.upgrade(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")), "head")
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def db_session(database: Engine) -> Generator[Session, None, None]:
    from app.db import SessionLocal

    with database.connect() as connection:
        transaction = connection.begin()
        session = SessionLocal(bind=connection, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            try:
                session.rollback()
            finally:
                session.close()
                transaction.rollback()


@pytest.fixture
def client(db_session: Session, monkeypatch: pytest.MonkeyPatch) -> Generator["TestClient", None, None]:
    from fastapi.testclient import TestClient

    from app import mcp_server
    from app.db import get_session
    from app.main import app

    monkeypatch.setitem(app.dependency_overrides, get_session, lambda: db_session)
    monkeypatch.setattr(mcp_server, "SessionLocal", sessionmaker(
        bind=db_session.bind, join_transaction_mode="create_savepoint",
    ))
    with TestClient(app, base_url=get_settings().public_base_url) as test_client:
        yield test_client


@pytest.fixture
def make_user(db_session: Session) -> Callable[[str, str], "User"]:
    from app.models import User
    from app.security import hash_password

    def create_user(email: str, password: str) -> User:
        user = User(email=email, password_hash=hash_password(password))
        db_session.add(user)
        db_session.flush()
        return user

    return create_user


@pytest.fixture
def make_task(db_session: Session) -> Callable[["User", str, str], "Task"]:
    from app.models import Task

    def create_task(user: "User", title: str, status: str) -> Task:
        task = Task(user_id=user.id, title=title, status=status)
        db_session.add(task)
        db_session.flush()
        return task

    return create_task


@pytest.fixture
def sign_in(client: "TestClient") -> Callable[[str, str], None]:
    def login(email: str, password: str) -> None:
        response = client.post("/login", data={"email": email, "password": password},
                               follow_redirects=False)
        assert response.status_code == 303

    return login


@pytest.fixture
def oauth_client(client: "TestClient") -> str:
    response = client.post("/register", json={
        "client_name": "ChatGPT",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
    })
    assert response.status_code == 201
    return response.json()["client_id"]


@pytest.fixture
def authorize_code(client: "TestClient", make_user, sign_in) -> Callable[..., tuple[str, str]]:
    from tests.test_oauth import AUTH, HiddenFields

    make_user("a@example.com", "pw")

    def approve(client_id: str, resource: str = "https://tasks.example.com") -> tuple[str, str]:
        sign_in("a@example.com", "pw")
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
        consent = client.get("/authorize", params={
            **AUTH, "client_id": client_id, "resource": resource,
            "code_challenge": challenge.decode("ascii"),
        })
        assert consent.status_code == 200
        response = client.post("/authorize", data={
            **HiddenFields(consent.text).fields, "decision": "approve",
        }, follow_redirects=False)
        assert response.status_code == 303
        return parse_qs(urlsplit(response.headers["location"]).query)["code"][0], verifier

    return approve


@pytest.fixture
def tokens(client: "TestClient", authorize_code) -> Callable[[str], dict[str, str | int]]:
    from tests.test_oauth import TOKEN

    def exchange(client_id: str) -> dict[str, str | int]:
        code, verifier = authorize_code(client_id)
        response = client.post("/token", data={
            **TOKEN, "code": code, "client_id": client_id, "code_verifier": verifier,
        })
        assert response.status_code == 200
        return response.json()

    return exchange


@pytest.fixture
def mcp_url() -> str:
    return "/mcp"


@pytest.fixture
def bearer(db_session: Session, make_user, oauth_client: str) -> str:
    from app.security import issue_tokens

    user = make_user("mcp@example.com", "pw")
    issued = issue_tokens(
        db_session, user_id=user.id, client_id=oauth_client,
        scope="tasks:read tasks:write", resource=get_settings().public_base_url,
    )
    db_session.commit()
    return issued["access_token"]


@pytest.fixture
def revoke(db_session: Session) -> Callable[[str], None]:
    from app.models import Token
    from app.security import token_hash

    def revoke_token(raw_token: str) -> None:
        token = db_session.get(Token, token_hash(raw_token))
        assert token is not None
        token.revoked_at = datetime.now(timezone.utc)
        db_session.commit()

    return revoke_token


@pytest.fixture
def expire(db_session: Session) -> Callable[[str], None]:
    from app.models import Token
    from app.security import token_hash

    def expire_token(raw_token: str) -> None:
        token = db_session.get(Token, token_hash(raw_token))
        assert token is not None
        token.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db_session.commit()

    return expire_token
