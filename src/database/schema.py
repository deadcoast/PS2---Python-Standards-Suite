"""
Database Schema Module for PS2.

This module defines the database schema for PS2, including tables for metrics,
performance data, and historical analysis, and provides functions for schema
creation, modification, and migration.
"""

import logging
import sqlite3

# Current schema version
SCHEMA_VERSION = 1

# Logger
_logger = logging.getLogger("ps2.database.schema")


def create_tables(connection: sqlite3.Connection) -> None:
    """
    Create database tables if they don't exist.

    Args:
        connection: SQLite database connection.

    Raises:
        sqlite3.Error: If table creation fails.
    """
    cursor = connection.cursor()

    # Create schema_version table
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS schema_version (
        id INTEGER PRIMARY KEY,
        version INTEGER NOT NULL,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    )

    # Create metrics table
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        value REAL NOT NULL,
        unit TEXT NOT NULL DEFAULT '',
        tags TEXT NOT NULL DEFAULT '{}',
        timestamp REAL NOT NULL,
        datetime TEXT NOT NULL,
        context TEXT NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    )

    # Create metrics indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics (name)")
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp)"
    )

    # Create performance_data table
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS performance_data (
        id INTEGER PRIMARY KEY,
        project_name TEXT NOT NULL,
        source_file TEXT NOT NULL,
        function_name TEXT,
        execution_time REAL NOT NULL,
        memory_usage REAL,
        cpu_usage REAL,
        timestamp REAL NOT NULL,
        datetime TEXT NOT NULL,
        context TEXT NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    )

    # Create performance_data indexes
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_performance_data_project ON performance_data (project_name)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_performance_data_file ON performance_data (source_file)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_performance_data_timestamp ON performance_data (timestamp)"
    )

    # Create code_quality_history table
    cursor.execute(
        """
    CREATE TABLE IF NOT EXISTS code_quality_history (
        id INTEGER PRIMARY KEY,
        project_name TEXT NOT NULL,
        check_type TEXT NOT NULL,
        score REAL NOT NULL,
        issue_count INTEGER NOT NULL DEFAULT 0,
        fixed_count INTEGER NOT NULL DEFAULT 0,
        timestamp REAL NOT NULL,
        datetime TEXT NOT NULL,
        details TEXT NOT NULL DEFAULT '{}',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """
    )

    # Create code_quality_history indexes
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_quality_history_project ON code_quality_history (project_name)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_quality_history_type ON code_quality_history (check_type)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_quality_history_timestamp ON code_quality_history (timestamp)"
    )

    # Insert initial schema version if it doesn't exist
    cursor.execute("SELECT COUNT(*) FROM schema_version")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
        )

    # Commit the transaction
    connection.commit()

    _logger.info(f"Database schema created (version {SCHEMA_VERSION})")


def get_schema_version(connection: sqlite3.Connection) -> int:
    """
    Get the current schema version.

    Args:
        connection: SQLite database connection.

    Returns:
        Current schema version.

    Raises:
        sqlite3.Error: If the query fails.
    """
    cursor = connection.cursor()

    # Check if the schema_version table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name='schema_version'"
    )
    if not cursor.fetchone():
        return 0

    # Get the current schema version
    cursor.execute("SELECT MAX(version) FROM schema_version")
    version = cursor.fetchone()[0]

    return version or 0


def upgrade_schema(connection: sqlite3.Connection) -> bool:
    """
    Upgrade the database schema to the latest version.

    Args:
        connection: SQLite database connection.
        True if the schema was upgraded, False if already at the latest version.  # TODO: Line too long, needs manual fixing
    Returns:
        True if the schema was upgraded, False if already at the latest version.

    Raises:
        sqlite3.Error: If the upgrade fails.
    """
    current_version = get_schema_version(connection)

    if current_version == SCHEMA_VERSION:
        _logger.info(f"Database schema already at latest version ({SCHEMA_VERSION})")
        return False

    _logger.info(
        f"Upgrading database schema from version {current_version} to {SCHEMA_VERSION}"
    )

    # Use a transaction for the upgrade
    connection.execute("BEGIN TRANSACTION")

    try:
        # Apply upgrades based on current version
        if current_version < 1:
            _upgrade_to_version_1(connection)

        # Add more upgrade steps as needed for future versions
        # if current_version < 2:
        #     _upgrade_to_version_2(connection)

        # Update the schema version
        connection.execute(
            "INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,)
        )

        # Commit the transaction
        connection.commit()

        _logger.info(f"Database schema upgraded to version {SCHEMA_VERSION}")
        return True

    except Exception as e:
        # Roll back the transaction on error
        connection.rollback()
        _logger.error(f"Schema upgrade failed: {e}")
        raise


def drop_tables(connection: sqlite3.Connection) -> None:
    """
    Drop all database tables.

    Args:
        connection: SQLite database connection.

    Raises:
        sqlite3.Error: If table deletion fails.
    """
    cursor = connection.cursor()

    # Get all table names
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]

    # Drop each table
    for table in tables:
        cursor.execute(f"DROP TABLE IF EXISTS {table}")

    # Commit the transaction
    connection.commit()

    _logger.info("All database tables dropped")


# Helper functions for schema upgrades


def _upgrade_to_version_1(connection: sqlite3.Connection) -> None:
    """
    Upgrade to schema version 1.

    Args:
        connection: SQLite database connection.

    Raises:
        sqlite3.Error: If the upgrade fails.
    """
    # Create initial tables
    create_tables(connection)

    _logger.info("Upgraded to schema version 1")
