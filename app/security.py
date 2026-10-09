import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Token

SCOPE_READ = "tasks:read"
SCOPE_WRITE = "tasks:write"

_password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _password_hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_pkce(verifier: str, challenge: str) -> bool:
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=")
    return secrets.compare_digest(expected, challenge.encode("utf-8"))


def normalize_email(email: str) -> str:
    return email.strip().lower()


def issue_tokens(
    session: Session, *, user_id: UUID, client_id: str, scope: str, resource: str,
) -> dict[str, str]:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    access_token, refresh_token = new_token(), new_token()
    session.add_all([
        Token(
            token_hash=token_hash(raw), user_id=user_id, client_id=client_id,
            scope=scope, resource=resource, kind=kind,
            expires_at=now + timedelta(seconds=ttl),
        )
        for raw, kind, ttl in [
            (access_token, "access", settings.access_token_ttl_seconds),
            (refresh_token, "refresh", settings.refresh_token_ttl_seconds),
        ]
    ])
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": str(settings.access_token_ttl_seconds),
    }


def resolve_access_token(session: Session, raw_token: str, resource: str) -> Token | None:
    base = get_settings().public_base_url
    resources = (base, base + "/mcp")
    if resource not in resources:
        return None
    return session.scalar(select(Token).where(
        Token.token_hash == token_hash(raw_token),
        Token.kind == "access",
        Token.revoked_at.is_(None),
        Token.expires_at > datetime.now(timezone.utc),
        Token.resource.in_(resources),
    ))
