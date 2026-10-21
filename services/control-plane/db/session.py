"""
Bayora Shield - Async Database Session & Engine Configuration
Supports PostgreSQL via asyncpg in staging/production, and SQLite via aiosqlite for tests and local dev.
"""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
    AsyncEngine,
)
from services.control_plane.config import settings
from services.control_plane.db.models import Base

# Build engine with pool pre-ping
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Creates database tables if they do not already exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
