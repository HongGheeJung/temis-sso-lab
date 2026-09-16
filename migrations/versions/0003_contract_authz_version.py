"""Contract after every application version reads authorization versions."""

from collections.abc import Sequence

from alembic import op

revision: str = "0003_contract_authz_version"
down_revision: str | None = "0002_expand_authz_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("users", "authz_version", nullable=False, server_default="1")


def downgrade() -> None:
    op.alter_column("users", "authz_version", nullable=True, server_default="1")
