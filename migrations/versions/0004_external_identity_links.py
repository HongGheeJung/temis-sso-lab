"""Add provider-owned identity links to the authentication database."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_external_identity_links"
down_revision: str | None = "0003_contract_authz_version"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "external_identity_links",
        sa.Column("provider", sa.String(32), primary_key=True),
        sa.Column("subject", sa.String(255), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_external_identity_links_user_id", "external_identity_links", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_external_identity_links_user_id", table_name="external_identity_links")
    op.drop_table("external_identity_links")
