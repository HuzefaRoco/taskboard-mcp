from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models import OAuthClient, Task, Token, User


def test_schema_exists(db_session):
    tables = set(db_session.execute(text(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
    )).scalars())
    assert {"users", "tasks", "oauth_clients",
            "oauth_authorization_codes", "oauth_tokens"} <= tables


def test_task_status_rejects_the_old_value(db_session):
    user = User(email="a@example.com", password_hash="x")
    db_session.add(user)
    db_session.flush()
    db_session.add(Task(user_id=user.id, title="t", status="complete"))
    with pytest.raises(IntegrityError) as caught:
        db_session.flush()
    assert caught.value.orig.sqlstate == "23514"


def test_user_email_is_normalized(db_session):
    user = User(email=" A@Example.COM ", password_hash="hashed")
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    assert user.email == "a@example.com"


@pytest.mark.parametrize("status", ["open", "completed"])
def test_task_accepts_current_statuses(db_session, status):
    user = User(email="status@example.com", password_hash="hashed")
    db_session.add(user)
    db_session.flush()
    task = Task(user_id=user.id, title="t", status=status)
    db_session.add(task)
    db_session.flush()
    db_session.refresh(task)
    assert task.status == status


def test_task_defaults_and_user_delete_cascade(db_session):
    user = User(email="cascade@example.com", password_hash="hashed")
    db_session.add(user)
    db_session.flush()
    task = Task(user_id=user.id, title="t")
    db_session.add(task)
    db_session.flush()
    assert isinstance(user.id, UUID)
    assert isinstance(task.id, UUID)
    assert task.status == "open"
    assert task.created_at.tzinfo is not None
    db_session.delete(user)
    db_session.flush()
    assert db_session.execute(
        text("SELECT id FROM tasks WHERE user_id = :user_id"), {"user_id": user.id}
    ).first() is None


def test_normalized_email_is_unique(db_session):
    db_session.add(User(email="unique@example.com", password_hash="hashed"))
    db_session.flush()
    db_session.add(User(email=" UNIQUE@Example.COM ", password_hash="hashed"))
    with pytest.raises(IntegrityError) as caught:
        db_session.flush()
    assert caught.value.orig.sqlstate == "23505"


@pytest.mark.parametrize("kind", ["access", "refresh", "invalid"])
def test_token_kind_constraint(db_session, kind):
    user = User(email="token@example.com", password_hash="hashed")
    client = OAuthClient(client_name="test", redirect_uris=["https://example.com/callback"])
    db_session.add_all([user, client])
    db_session.flush()
    assert len(client.client_id) == 32
    token = Token(
        token_hash="hashed-token", client_id=client.client_id, user_id=user.id,
        scope="tasks:read", resource="https://example.com", kind=kind,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db_session.add(token)
    if kind == "invalid":
        with pytest.raises(IntegrityError) as caught:
            db_session.flush()
        assert caught.value.orig.sqlstate == "23514"
    else:
        db_session.flush()
        db_session.refresh(token)
        assert token.kind == kind
        assert token.revoked_at is None


@pytest.mark.parametrize("attempt", [1, 2])
def test_session_commit_is_rolled_back_by_fixture(db_session, attempt):
    assert db_session.query(User).filter_by(email="rollback@example.com").first() is None
    db_session.add(User(email="rollback@example.com", password_hash="hashed"))
    db_session.commit()
