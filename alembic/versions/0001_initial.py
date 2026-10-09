"""Create the taskboard and OAuth tables."""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("email", sa.Text(), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "tasks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('open','completed')", name="ck_tasks_status"),
    )
    op.create_index("ix_tasks_user_id_created_at", "tasks", ["user_id", "created_at"])
    op.create_table(
        "oauth_clients",
        sa.Column("client_id", sa.String(32), primary_key=True),
        sa.Column("client_name", sa.Text(), nullable=False),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "oauth_authorization_codes",
        sa.Column("code_hash", sa.Text(), primary_key=True),
        sa.Column("client_id", sa.String(32), sa.ForeignKey("oauth_clients.client_id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("code_challenge", sa.Text(), nullable=False),
        sa.Column("code_challenge_method", sa.Text(), nullable=False),
        sa.Column("resource", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "oauth_tokens",
        sa.Column("token_hash", sa.Text(), primary_key=True),
        sa.Column("client_id", sa.String(32), sa.ForeignKey("oauth_clients.client_id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope", sa.Text(), nullable=False),
        sa.Column("resource", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("kind IN ('access','refresh')", name="ck_oauth_tokens_kind"),
    )


def downgrade() -> None:
    op.drop_table("oauth_tokens")
    op.drop_table("oauth_authorization_codes")
    op.drop_table("oauth_clients")
    op.drop_index("ix_tasks_user_id_created_at", table_name="tasks")
    op.drop_table("tasks")
    op.drop_table("users")
