"""Test configuration and fixtures."""

import asyncio
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.database import Base
from app.config import settings

# Create test database engine with NullPool to avoid connection reuse
test_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,
    future=True,
    poolclass=NullPool  # Prevent connection pooling
)

# Create test session factory
test_async_session = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False  # Disable autoflush to prevent implicit operations
)

@pytest_asyncio.fixture(scope="session")
async def setup_database():
    """Set up test database."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def db_session(setup_database) -> AsyncSession:
    """Create a fresh database session for a test."""
    async with test_async_session() as session:
        try:
            yield session
            await session.rollback()  # Rollback any pending changes
        finally:
            await session.close()  # Ensure session is closed

@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Override the get_db dependency in FastAPI."""
    async def _override_get_db():
        try:
            yield db_session
        finally:
            await db_session.close()
    return _override_get_db 