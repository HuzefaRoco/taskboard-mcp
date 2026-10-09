from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db import Base

STATUS_OPEN = "open"
STATUS_COMPLETED = "completed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    @validates("email")
    def normalize_email(self, key: str, value: str) -> str:
        return value.strip().lower()


class Task(Base):
    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint("status IN ('open','completed')", name="ck_tasks_status"),
        Index("ix_tasks_user_id_created_at", "user_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default=STATUS_OPEN, server_default=STATUS_OPEN)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    client_id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: uuid4().hex)
    client_name: Mapped[str] = mapped_column(Text)
    redirect_uris: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthorizationCode(Base):
    __tablename__ = "oauth_authorization_codes"

    code_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id", ondelete="CASCADE"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    redirect_uri: Mapped[str] = mapped_column(Text)
    scope: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[str] = mapped_column(Text)
    code_challenge_method: Mapped[str] = mapped_column(Text)
    resource: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Token(Base):
    __tablename__ = "oauth_tokens"
    __table_args__ = (CheckConstraint("kind IN ('access','refresh')", name="ck_oauth_tokens_kind"),)

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("oauth_clients.client_id", ondelete="CASCADE"))
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    scope: Mapped[str] = mapped_column(Text)
    resource: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
