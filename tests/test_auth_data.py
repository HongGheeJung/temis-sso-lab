import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from temis_sso.persistence import UserRepository, session_scope


@pytest.mark.asyncio
async def test_user_repository_normalizes_email() -> None:
    email = f"{uuid.uuid4().hex}@mail.test"
    async with session_scope() as session:
        user = await UserRepository(session).create(email.upper())
        assert user.email == email
        assert user.status == "pending"


@pytest.mark.asyncio
async def test_user_email_is_unique() -> None:
    email = f"{uuid.uuid4().hex}@mail.test"
    async with session_scope() as session:
        await UserRepository(session).create(email)
    with pytest.raises(IntegrityError):
        async with session_scope() as session:
            await UserRepository(session).create(email)


@pytest.mark.asyncio
async def test_alembic_migration_is_applied() -> None:
    async with session_scope() as session:
        revision = await session.scalar(text("select version_num from alembic_version"))
        assert revision == "0004_external_identity_links"
