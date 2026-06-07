"""Run Alembic migrations with a guarded baseline for existing production schemas."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus

from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection

from alembic import command

BASELINE_REVISION = "014"
ALEMBIC_VERSION_TABLE = "alembic_version"

BASELINE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "Channels": ("channel_id", "youtube_channel_id"),
    "Videos": ("video_id", "processing_status"),
    "Batches": ("batch_id",),
    "BatchItems": ("batch_item_id",),
    "Jobs": (
        "job_id",
        "correlation_id",
        "next_retry_at",
        "estimated_wait_seconds",
        "quota_status",
        "user_id",
    ),
    "Artifacts": ("artifact_id",),
    "Segments": ("segment_id", "Embedding"),
    "Relationships": ("relationship_id",),
    "Facets": ("facet_id",),
    "VideoFacets": ("video_facet_id",),
    "ChatThreads": ("thread_id", "last_run_id", "scope_json", "ai_settings_json"),
    "JobHistory": (
        "history_id",
        "queued_at",
        "wait_seconds",
        "enforced_delay_seconds",
        "estimated_wait_seconds",
    ),
    "proxy_request_logs": ("id", "job_id", "created_at"),
    "Users": ("user_id", "auth0_id"),
    "UsageRecords": ("usage_id",),
    "ExpediteRequests": ("request_id",),
}


def _convert_ado_connection_string(ado_string: str) -> str:
    parts = {}
    for part in ado_string.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            parts[key.strip().lower()] = value.strip()

    server = parts.get("server", parts.get("data source", "localhost"))
    database = parts.get("database", parts.get("initial catalog", ""))
    user = parts.get("user id", parts.get("uid", "sa"))
    password = quote_plus(parts.get("password", parts.get("pwd", "")))

    if server.lower().startswith("tcp:"):
        server = server[4:]

    if "," in server:
        host, port = server.split(",", 1)
    elif ":" in server:
        host, port = server.split(":", 1)
    else:
        host, port = server, "1433"

    return (
        f"mssql+pyodbc://{user}:{password}@{host},{port}/{database}"
        "?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
    )


def _database_url() -> str:
    url = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("ConnectionStrings__ytsummarizer")
        or os.environ.get("ConnectionStrings__sql")
    )
    if not url:
        raise RuntimeError(
            "Database connection string not found. Set DATABASE_URL, "
            "ConnectionStrings__ytsummarizer, or ConnectionStrings__sql."
        )

    if "Server=" in url and ";" in url:
        return _convert_ado_connection_string(url)
    if url.startswith("mssql+aioodbc://"):
        return url.replace("mssql+aioodbc://", "mssql+pyodbc://", 1)
    if "://" not in url:
        return (
            f"mssql+pyodbc://{url}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
        )
    return url


def _table_exists(conn: Connection, table_name: str) -> bool:
    result = conn.execute(
        text(
            """
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE' AND TABLE_NAME = :table_name
            """
        ),
        {"table_name": table_name},
    )
    return bool(result.scalar())


def _column_exists(conn: Connection, table_name: str, column_name: str) -> bool:
    result = conn.execute(
        text(
            """
            SELECT COUNT(*)
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = :table_name AND COLUMN_NAME = :column_name
            """
        ),
        {"table_name": table_name, "column_name": column_name},
    )
    return bool(result.scalar())


def _known_app_tables(conn: Connection) -> set[str]:
    result = conn.execute(
        text(
            """
            SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_TYPE = 'BASE TABLE'
            """
        )
    )
    existing = set(result.scalars())
    return existing.intersection(BASELINE_REQUIREMENTS.keys())


def _missing_baseline_objects(conn: Connection) -> list[str]:
    missing: list[str] = []
    for table_name, columns in BASELINE_REQUIREMENTS.items():
        if not _table_exists(conn, table_name):
            missing.append(f"{table_name}.*")
            continue
        for column_name in columns:
            if not _column_exists(conn, table_name, column_name):
                missing.append(f"{table_name}.{column_name}")
    return missing


def _alembic_config() -> Config:
    shared_root = Path(__file__).resolve().parents[1]
    config = Config(str(shared_root / "alembic.ini"))
    config.set_main_option("script_location", str(shared_root / "alembic"))
    return config


def main() -> None:
    engine = create_engine(_database_url(), pool_pre_ping=True)
    config = _alembic_config()
    stamp_revision: str | None = None

    try:
        with engine.begin() as conn:
            has_version_table = _table_exists(conn, ALEMBIC_VERSION_TABLE)
            known_tables = _known_app_tables(conn)
            if not has_version_table and known_tables:
                missing = _missing_baseline_objects(conn)
                if missing:
                    formatted = ", ".join(missing)
                    raise RuntimeError(
                        "Database is unversioned and does not match the expected "
                        f"{BASELINE_REVISION} baseline. Missing: {formatted}"
                    )

                print(
                    "Existing unversioned schema matches baseline "
                    f"{BASELINE_REVISION}; stamping Alembic."
                )
                stamp_revision = BASELINE_REVISION
            elif not has_version_table:
                print("No existing application schema detected; running migrations from scratch.")

        if stamp_revision:
            command.stamp(config, stamp_revision)

        command.upgrade(config, "head")
        print("Alembic migrations completed successfully.")
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
