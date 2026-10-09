from datetime import datetime, timedelta, timezone
from hashlib import sha256

import pytest
from sqlalchemy.orm import sessionmaker

from app import seed
from app.config import get_settings
from app.models import OAuthClient, Token, User
from app.security import (
    SCOPE_READ, SCOPE_WRITE, hash_password, issue_tokens, new_token,
    normalize_email, resolve_access_token, token_hash, verify_password, verify_pkce,
)


def test_seed_is_idempotent_and_hashes_passwords(db_session):
    pairs = [("Alice@Example.com ", "pw-a"), ("bob@example.com", "pw-b")]
    assert seed.seed(db_session, pairs) == 2
    assert seed.seed(db_session, pairs) == 0
    users = db_session.query(User).all()
    assert {u.email for u in users} == {"alice@example.com", "bob@example.com"}
    alice = db_session.query(User).filter_by(email="alice@example.com").one()
    assert alice.password_hash != "pw-a"
    assert verify_password("pw-a", alice.password_hash)
    assert not verify_password("wrong", alice.password_hash)


def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  A@B.COM ") == "a@b.com"


def test_seed_duplicates_do_not_replace_password(db_session):
    assert seed.seed(db_session, [("a@b.com", "first"), (" A@B.COM ", "second")]) == 1
    user = db_session.query(User).one()
    assert verify_password("first", user.password_hash)
    assert not verify_password("second", user.password_hash)


def test_seed_main_commits_pairs(db_session, monkeypatch):
    monkeypatch.setattr(seed, "SessionLocal", sessionmaker(
        bind=db_session.bind, join_transaction_mode="create_savepoint",
    ))
    seed.main(["CLI@Example.com", "cli-password", "other@example.com", "other-password"])
    user = db_session.query(User).filter_by(email="cli@example.com").one()
    assert verify_password("cli-password", user.password_hash)
    assert db_session.query(User).count() == 2


@pytest.mark.parametrize("argv", [[], ["a@b.com"], ["a@b.com", "pw", "unpaired"]])
def test_seed_main_rejects_incomplete_pairs(argv):
    with pytest.raises(SystemExit) as caught:
        seed.main(argv)
    assert caught.value.code == 2


@pytest.mark.parametrize("bad_pair", [("   ", "pw"), ("a@b.com", "")])
def test_seed_main_rolls_back_invalid_batch(db_session, monkeypatch, bad_pair):
    monkeypatch.setattr(seed, "SessionLocal", sessionmaker(
        bind=db_session.bind, join_transaction_mode="create_savepoint",
    ))
    with pytest.raises(SystemExit) as caught:
        seed.main(["valid@example.com", "pw", *bad_pair])
    assert caught.value.code == 2
    assert db_session.query(User).count() == 0


def test_seed_main_handles_database_failure(db_session, monkeypatch, capsys):
    monkeypatch.setattr(seed, "SessionLocal", sessionmaker(
        bind=db_session.bind, join_transaction_mode="create_savepoint",
    ))
    real_hash = seed.hash_password
    monkeypatch.setattr(seed, "hash_password", lambda password: (
        None if password == "failing-password" else real_hash(password)
    ))
    with pytest.raises(SystemExit) as caught:
        seed.main(["valid@example.com", "pw", "failure@example.com", "failing-password"])
    assert caught.value.code == 1
    assert db_session.query(User).count() == 0
    error = capsys.readouterr().err
    assert "database operation failed" in error
    assert "failing-password" not in error
    assert "INSERT" not in error


def test_password_hashes_are_salted_and_invalid_hashes_fail_closed():
    first = hash_password("password")
    assert first.startswith("$argon2id$")
    assert first != hash_password("password")
    assert verify_password("password", first)
    assert not verify_password("password", "not-a-hash")


def test_token_randomness_and_sha256():
    first, second = new_token(), new_token()
    assert first != second
    assert len(first) == 43
    assert token_hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_pkce_s256_rfc7636_vector():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert verify_pkce(verifier, challenge)
    assert not verify_pkce("wrong", challenge)
    assert not verify_pkce(verifier, challenge + "=")
    assert not verify_pkce(verifier, "non-ascii-\u00e9")


@pytest.fixture
def token_pair(db_session):
    user = User(email="tokens@example.com", password_hash=hash_password("pw"))
    client = OAuthClient(client_name="test", redirect_uris=["https://example.com/callback"])
    db_session.add_all([user, client])
    db_session.flush()
    return user, client


def test_issue_tokens_stores_hashes_and_settings_expiry(db_session, token_pair, monkeypatch):
    monkeypatch.setenv("ACCESS_TOKEN_TTL_SECONDS", "73")
    monkeypatch.setenv("REFRESH_TOKEN_TTL_SECONDS", "149")
    get_settings.cache_clear()
    try:
        user, client = token_pair
        resource = get_settings().public_base_url
        before = datetime.now(timezone.utc)
        result = issue_tokens(db_session, user_id=user.id, client_id=client.client_id,
                              scope=f"{SCOPE_READ} {SCOPE_WRITE}", resource=resource)
        db_session.flush()
        after = datetime.now(timezone.utc)
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == "73"
        assert result["access_token"] != result["refresh_token"]
        rows = db_session.query(Token).all()
        assert len(rows) == 2
        for kind, ttl in [("access", 73), ("refresh", 149)]:
            raw = result[f"{kind}_token"]
            row = next(row for row in rows if row.kind == kind)
            assert row.token_hash == sha256(raw.encode()).hexdigest()
            assert row.token_hash != raw
            assert row.scope == "tasks:read tasks:write"
            assert row.resource == resource
            assert row.user_id == user.id
            assert row.client_id == client.client_id
            assert row.revoked_at is None
            assert before + timedelta(seconds=ttl) <= row.expires_at <= after + timedelta(seconds=ttl)
    finally:
        get_settings.cache_clear()


@pytest.mark.parametrize("stored_suffix", ["", "/mcp"])
@pytest.mark.parametrize("requested_suffix", ["", "/mcp"])
def test_resolve_accepts_both_resource_forms(db_session, token_pair, stored_suffix, requested_suffix):
    user, client = token_pair
    base = get_settings().public_base_url
    result = issue_tokens(db_session, user_id=user.id, client_id=client.client_id,
                          scope=SCOPE_READ, resource=base + stored_suffix)
    token = resolve_access_token(db_session, result["access_token"], base + requested_suffix)
    assert token is not None
    assert token.kind == "access"
    assert resolve_access_token(db_session, result["access_token"], "https://other.example.com") is None
    assert resolve_access_token(db_session, result["access_token"], base + "/mcp/extra") is None
    assert resolve_access_token(db_session, result["refresh_token"], base) is None
    assert resolve_access_token(db_session, "unknown", base) is None


@pytest.mark.parametrize("invalid_state", ["expired", "revoked", "wrong-resource"])
def test_resolve_rejects_invalid_access_tokens(db_session, token_pair, invalid_state):
    user, client = token_pair
    base = get_settings().public_base_url
    result = issue_tokens(db_session, user_id=user.id, client_id=client.client_id,
                          scope=SCOPE_READ, resource=base)
    db_session.flush()
    row = db_session.get(Token, token_hash(result["access_token"]))
    if invalid_state == "expired":
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    elif invalid_state == "revoked":
        row.revoked_at = datetime.now(timezone.utc)
    else:
        row.resource = "https://other.example.com"
    db_session.flush()
    assert resolve_access_token(db_session, result["access_token"], row.resource) is None
