from datetime import UTC, datetime
from typing import cast

from sqlalchemy import DateTime, ForeignKey, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column

from temis_sso.external_idp.models import ExternalIdentity
from temis_sso.persistence import Base


class ExternalIdentityLink(Base):
    __tablename__ = "external_identity_links"
    provider: Mapped[str] = mapped_column(String(32), primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class ExternalIdentityLinkRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _insert(self, provider: str, subject: str, user_id: str) -> None:
        self.session.add(ExternalIdentityLink(provider=provider, subject=subject, user_id=user_id))
        await self.session.flush()

    async def resolve(self, provider: str, subject: str) -> str | None:
        statement = select(ExternalIdentityLink.user_id).where(
            ExternalIdentityLink.provider == provider,
            ExternalIdentityLink.subject == subject,
        )
        return cast(str | None, await self.session.scalar(statement))


class ConfirmedAccountLinkService:
    def __init__(self, repository: ExternalIdentityLinkRepository) -> None:
        self.repository = repository

    async def link(
        self,
        authenticated_user_id: str,
        identity: ExternalIdentity,
        *,
        confirmed: bool,
    ) -> None:
        if not authenticated_user_id:
            raise ValueError("authenticated user is required")
        if not confirmed:
            raise ValueError("account linking requires explicit confirmation")
        await self.repository._insert(identity.provider, identity.subject, authenticated_user_id)
