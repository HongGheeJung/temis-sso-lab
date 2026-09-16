import asyncio
import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


async def verify() -> None:
    url = os.environ["RESTORE_ASYNC_DATABASE_URL"]
    expected = os.environ["EXPECTED_RESTORE_DATABASE"]
    engine = create_async_engine(url)
    try:
        async with engine.connect() as connection:
            row = (
                await connection.execute(
                    text(
                        "select current_database(), "
                        "to_regclass('public.temis_restore_target') is not null"
                    )
                )
            ).one()
    finally:
        await engine.dispose()
    if tuple(row) != (expected, True):
        raise SystemExit("refusing to restore: async target identity or marker mismatch")


asyncio.run(verify())
