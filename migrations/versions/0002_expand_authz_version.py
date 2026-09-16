"""Expand users with a backward-compatible authorization version."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_expand_authz_version"
down_revision: str | None = "0001_auth_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("authz_version", sa.Integer(), server_default="1", nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "authz_version")
