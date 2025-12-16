"""Database connection and initialization."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from packages.storage.models import Base

logger = logging.getLogger(__name__)


class Database:
    """
    Database connection manager.

    Handles SQLite for MVP, designed to be easily replaced with PostgreSQL.
    """

    def __init__(self, database_url: str | None = None, echo: bool = False):
        """
        Initialize database connection.

        Args:
            database_url: Database URL. Defaults to SQLite in current directory.
            echo: Whether to echo SQL statements (for debugging)
        """
        if database_url is None:
            database_url = "sqlite+aiosqlite:///secscan.db"

        # Handle SQLite-specific settings
        connect_args = {}
        poolclass = None

        if database_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
            # Use StaticPool for SQLite to handle async properly
            if ":memory:" in database_url:
                poolclass = StaticPool

        self.engine = create_async_engine(
            database_url,
            echo=echo,
            connect_args=connect_args,
            poolclass=poolclass,
        )

        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the database schema."""
        if self._initialized:
            return

        async with self.engine.begin() as conn:
            # Enable foreign keys for SQLite
            if "sqlite" in str(self.engine.url):
                await conn.execute(text("PRAGMA foreign_keys=ON"))

            await conn.run_sync(Base.metadata.create_all)

        self._initialized = True
        logger.info("Database initialized")

    async def close(self) -> None:
        """Close database connection."""
        await self.engine.dispose()
        logger.info("Database connection closed")

    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a database session."""
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    def session(self) -> AsyncSession:
        """Create a new session (for use with async with)."""
        return self.async_session()


# Global database instance
_database: Database | None = None


def get_database(database_url: str | None = None) -> Database:
    """Get or create the global database instance."""
    global _database
    if _database is None:
        _database = Database(database_url)
    return _database


def reset_database() -> None:
    """Reset the global database instance (for testing)."""
    global _database
    _database = None


async def init_database(database_url: str | None = None) -> Database:
    """Initialize and return the database."""
    db = get_database(database_url)
    await db.initialize()
    return db
