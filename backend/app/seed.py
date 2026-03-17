"""Seed the database with sample events to populate the Tatu dashboard."""
import asyncio
from app.database import engine, async_session
from app.models import Base
from app.generate_events import generate_events


async def seed():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    await generate_events(count=200, hours=24)


if __name__ == "__main__":
    asyncio.run(seed())
