"""Database connection factory with retry logic.

This module handles database connections for SQL Server (both local and Azure SQL)
with support for ADO.NET style connection strings and connection pooling.
"""

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from tenacity import retry, stop_after_attempt, wait_exponential

from .models import Base

# Default connection settings
DEFAULT_POOL_SIZE = 5
DEFAULT_MAX_OVERFLOW = 10
DEFAULT_POOL_TIMEOUT = 30
DEFAULT_POOL_RECYCLE = 1800  # 30 minutes


def get_database_url() -> str:
    """Get database URL from environment.

    Supports multiple environment variable formats:
    1. DATABASE_URL - Standard SQLAlchemy-style URL
    2. ConnectionStrings__ytsummarizer - .NET Aspire-injected connection string
    3. ConnectionStrings__sql - Alternative Aspire format
    """
    # Try standard DATABASE_URL first
    url = os.environ.get("DATABASE_URL")

    # Try Aspire-injected connection strings
    if not url:
        url = os.environ.get("ConnectionStrings__ytsummarizer")
    if not url:
        url = os.environ.get("ConnectionStrings__sql")

    if not url:
        raise ValueError(
            "Database connection string not found. Set one of: "
            "DATABASE_URL, ConnectionStrings__ytsummarizer, or ConnectionStrings__sql"
        )

    # Handle ADO.NET style connection strings from Aspire
    # Example: "Server=localhost,1433;Database=ytsummarizer;User Id=sa;Password=...;TrustServerCertificate=True"
    if "Server=" in url and ";" in url:
        url = convert_ado_connection_string(url)
    # Convert to async driver if needed
    elif url.startswith("mssql+pyodbc://"):
        url = url.replace("mssql+pyodbc://", "mssql+aioodbc://")
    elif not url.startswith("mssql+aioodbc://"):
        # Assume it's a connection string without driver prefix
        url = (
            f"mssql+aioodbc://{url}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )

    return url


def convert_ado_connection_string(ado_string: str) -> str:
    """Convert ADO.NET style connection string to SQLAlchemy URL.

    Converts strings like:
        Server=localhost,1433;Database=ytsummarizer;User Id=sa;Password=xxx;TrustServerCertificate=True
        Server=tcp:sql-server.database.windows.net,1433;Initial Catalog=db;...
    To:
        mssql+aioodbc://sa:xxx@localhost,1433/ytsummarizer?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
    """
    parts = {}
    for part in ado_string.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            parts[key.strip().lower()] = value.strip()

    # Extract components
    server = parts.get("server", parts.get("data source", "localhost"))
    database = parts.get("database", parts.get("initial catalog", ""))
    user = parts.get("user id", parts.get("uid", "sa"))
    password = parts.get("password", parts.get("pwd", ""))

    # Strip "tcp:" prefix if present (Azure SQL uses this format)
    if server.lower().startswith("tcp:"):
        server = server[4:]

    # Handle port in server (e.g., "localhost,1433" or "localhost:1433")
    if "," in server:
        host, port = server.split(",", 1)
    elif ":" in server:
        host, port = server.split(":", 1)
    else:
        host, port = server, "1433"

    # URL-encode the password in case it contains special characters
    from urllib.parse import quote_plus

    encoded_password = quote_plus(password)

    # Build SQLAlchemy URL
    # For SQL Server, the port goes in the query string, not in the host
    # Format: mssql+aioodbc://user:pass@host/database?driver=...&port=1433
    url = f"mssql+aioodbc://{user}:{encoded_password}@{host}/{database}"
    url += f"?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes&port={port}"

    return url


def create_engine(
    url: str | None = None,
    pool_size: int = DEFAULT_POOL_SIZE,
    max_overflow: int = DEFAULT_MAX_OVERFLOW,
    pool_timeout: int = DEFAULT_POOL_TIMEOUT,
    pool_recycle: int = DEFAULT_POOL_RECYCLE,
    echo: bool = False,
    **kwargs: Any,
) -> AsyncEngine:
    """Create an async SQLAlchemy engine with connection pooling.

    Args:
        url: Database URL. If None, reads from DATABASE_URL env var.
        pool_size: Number of connections to keep in the pool.
        max_overflow: Max connections beyond pool_size.
        pool_timeout: Seconds to wait for a connection from pool.
        pool_recycle: Seconds before recycling a connection.
        echo: If True, log all SQL statements.
        **kwargs: Additional engine arguments.

    Returns:
        Configured AsyncEngine instance.
    """
    if url is None:
        url = get_database_url()

    engine = create_async_engine(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        pool_recycle=pool_recycle,
        echo=echo,
        **kwargs,
    )

    return engine


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create an async session factory for the given engine.

    Args:
        engine: The async engine to use for sessions.

    Returns:
        Configured async_sessionmaker instance.
    """
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


class DatabaseConnection:
    """Database connection manager with retry logic."""

    def __init__(
        self,
        url: str | None = None,
        pool_size: int = DEFAULT_POOL_SIZE,
        max_overflow: int = DEFAULT_MAX_OVERFLOW,
        echo: bool = False,
    ):
        """Initialize the database connection manager.

        Args:
            url: Database URL. If None, reads from DATABASE_URL env var.
            pool_size: Number of connections to keep in the pool.
            max_overflow: Max connections beyond pool_size.
            echo: If True, log all SQL statements.
        """
        self._url = url
        self._pool_size = pool_size
        self._max_overflow = max_overflow
        self._echo = echo
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    @property
    def engine(self) -> AsyncEngine:
        """Get or create the database engine."""
        if self._engine is None:
            self._engine = create_engine(
                url=self._url,
                pool_size=self._pool_size,
                max_overflow=self._max_overflow,
                echo=self._echo,
            )
        return self._engine

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Get or create the session factory."""
        if self._session_factory is None:
            self._session_factory = create_session_factory(self.engine)
        return self._session_factory

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Create a new session context.

        Usage:
            async with db.session() as session:
                result = await session.execute(query)
        """
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    async def connect(self) -> None:
        """Test the database connection with retry logic."""
        async with self.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def close(self) -> None:
        """Close the database engine and all connections."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    async def create_tables(self) -> None:
        """Create all tables defined in the models."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_tables(self) -> None:
        """Drop all tables defined in the models."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)


# Global database connection instance
_db: DatabaseConnection | None = None


def get_db() -> DatabaseConnection:
    """Get the global database connection instance."""
    global _db
    if _db is None:
        _db = DatabaseConnection()
    return _db


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency for getting a database session.

    Usage in FastAPI:
        @app.get("/items")
        async def get_items(session: AsyncSession = Depends(get_session)):
            ...
    """
    db = get_db()
    async with db.session() as session:
        yield session
