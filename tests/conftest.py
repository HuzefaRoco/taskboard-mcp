import os
from collections.abc import Generator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session

from app.config import get_settings

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
