"""Alembic environment configuration for YT Summarizer."""

import os
import sys
from logging.config import fileConfig

# Add the shared directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), "shared"))

from db.models import Base
from sqlalchemy import create_engine, pool

from alembic import context

# Alembic Config object
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Model metadata for autogenerate
target_metadata = Base.metadata


def convert_ado_connection_string(ado_string: str) -> str:
    """Convert ADO.NET style connection string to SQLAlchemy URL.

    Converts strings like:
        Server=localhost,1433;Database=ytsummarizer;User Id=sa;Password=xxx;TrustServerCertificate=True
    To:
        mssql+pyodbc://sa:xxx@localhost,1433/ytsummarizer?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
    """
    from urllib.parse import quote_plus

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

    # Handle port in server (e.g., "localhost,1433" or "localhost:1433")
    if "," in server:
        host, port = server.split(",", 1)
    elif ":" in server:
        host, port = server.split(":", 1)
    else:
        host, port = server, "1433"

    # URL-encode the password
    encoded_password = quote_plus(password)

    # Build SQLAlchemy URL (SQL Server ODBC uses comma for port)
    url = f"mssql+pyodbc://{user}:{encoded_password}@{host},{port}/{database}"
    url += "?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"

    return url


def get_url() -> str:
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
    if "Server=" in url and ";" in url:
        url = convert_ado_connection_string(url)
    # Handle pyodbc connection string format
    elif "://" not in url:
        url = (
            f"mssql+pyodbc://{url}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )
    # Convert async driver to sync for Alembic
    elif "mssql+aioodbc://" in url:
        url = url.replace("mssql+aioodbc://", "mssql+pyodbc://")

    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine,
    though an Engine is acceptable here as well. By skipping the Engine
    creation we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine and associate a
    connection with the context.
    """
    connectable = create_engine(
        get_url(),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
