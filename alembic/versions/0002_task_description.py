"""Add task descriptions."""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tasks", sa.Column("description", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("tasks", "description")
