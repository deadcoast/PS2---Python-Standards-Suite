"""
Metrics Database Module for PS2.

This module provides functionality for:
- Storing, retrieving, and managing performance metrics in a database
- Enabling long-term tracking and analysis of project performance
"""

import csv
import json
import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from ps2.database.schema import create_tables, get_schema_version

# Constants
DEFAULT_DB_PATH = "ps2_metrics.db"

_db_connection = None
_logger = logging.getLogger("ps2.database.metrics_db")


class MetricsDatabase:
    """
    Class for managing metrics database operations.

    This class provides methods for storing, retrieving, and managing
    performance metrics in a database.
    """

    def __init__(self, db_path: Union[str, Path]):
        """
        Initialize the metrics database.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self.connection = None
        self.logger = logging.getLogger("src.database.metrics_db")

    def connect(self) -> None:
        """
        Connect to the database.

        Raises:
            sqlite3.Error: If the connection fails.
        """
        # Ensure the directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Connect to the database
        self.connection = sqlite3.connect(str(self.db_path))

        # Enable foreign keys
        self.connection.execute("PRAGMA foreign_keys = ON")

        # Use Row as the row factory
        self.connection.row_factory = sqlite3.Row

        # Check if the database schema is initialized
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name='schema_version'"
        )
        if not cursor.fetchone():
            # Initialize the database schema
            self.logger.info(f"Initializing database schema at {self.db_path}")
            create_tables(self.connection)

        # Log connection
        self.logger.debug(f"Connected to database at {self.db_path}")

    def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.logger.debug("Database connection closed")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Context manager for database transactions.

        Yields:
            Database connection with transaction.

        Raises:
            sqlite3.Error: If any database operation fails.
        """
        if not self.connection:
            self.connect()

        try:
            yield self.connection
            self.connection.commit()
        except Exception as e:
            self.connection.rollback()
            self.logger.error(f"Transaction failed: {e}")
            raise

    def store_metric(
        self,
        name: str,
        value: Union[int, float],
        unit: str = "",
        tags: Optional[Dict[str, str]] = None,
        timestamp: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> int:
        """
        Store a metric in the database.

        Args:
            name: Name of the metric.
            value: Value of the metric.
            unit: Unit of the metric.
            tags: Tags for categorizing the metric.
            timestamp: Timestamp of the metric. If None, use current time.
            context: Additional context as JSON serializable dict.

        Returns:
            ID of the inserted metric record.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        if not self.connection:
            self.connect()

        # Use current time if timestamp not provided
        if timestamp is None:
            timestamp = time.time()

        # Default empty dicts
        if tags is None:
            tags = {}
        if context is None:
            context = {}

        # Serialize tags and context to JSON
        tags_json = json.dumps(tags)
        context_json = json.dumps(context)

        # Get datetime from timestamp
        dt = datetime.fromtimestamp(timestamp)

        with self.transaction() as conn:
            cursor = conn.cursor()

            # Insert the metric
            cursor.execute(
                """
                INSERT INTO metrics (name, value, unit, tags, timestamp, datetime, context)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (name, value, unit, tags_json, timestamp, dt.isoformat(), context_json),
            )

            # Get the ID of the inserted metric
            metric_id = cursor.lastrowid

        return metric_id

    def _build_query_conditions(
        self,
        name: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> tuple[list[str], list]:
        """
        Build query conditions for filtering metrics.

        Args:
            name: Name of the metric to filter by
            start_time: Filter metrics after this timestamp
            end_time: Filter metrics before this timestamp
            tags: Filter metrics by tags

        Returns:
            Tuple of (conditions, params) for the SQL query
        """
        conditions = []
        params = []

        # Add name filter
        if name is not None:
            conditions.append("name = ?")
            params.append(name)

        # Add time range filters
        if start_time is not None:
            conditions.append("timestamp >= ?")
            params.append(start_time)

        if end_time is not None:
            conditions.append("timestamp <= ?")
            params.append(end_time)

        # Add tags filter
        if tags is not None and tags:
            # Process each tag as a separate condition
            for key, value in tags.items():
                conditions.append(f"json_extract(tags, '$.{key}') = ?")
                params.append(value)

        return conditions, params

    def _parse_metric_json_fields(self, metric: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse JSON fields in a metric record.

        Args:
            metric: The metric record with JSON string fields

        Returns:
            Metric with parsed JSON fields
        """
        # Parse JSON fields
        metric["tags"] = json.loads(metric["tags"]) if metric["tags"] else {}
        metric["context"] = json.loads(metric["context"]) if metric["context"] else {}
        return metric

    def query_metrics(
        self,
        name: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
        limit: Optional[int] = None,
        order_by: str = "timestamp DESC",
    ) -> List[Dict[str, Any]]:
        """
        Query metrics from the database.

        Args:
            name: Name of the metric to filter by. If None, return all metrics.
            start_time: Filter metrics after this timestamp.
            end_time: Filter metrics before this timestamp.
            tags: Filter metrics by tags. If None, don't filter by tags.
            limit: Maximum number of metrics to return. If None, return all.
            order_by: Order by clause for the query.

        Returns:
            List of metrics matching the query.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        if not self.connection:
            self.connect()

        # Build the query
        query = "SELECT * FROM metrics"
        conditions, params = self._build_query_conditions(
            name, start_time, end_time, tags
        )

        # Add WHERE clause if there are conditions
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Add ORDER BY clause
        if order_by:
            query += f" ORDER BY {order_by}"

        # Add LIMIT clause
        if limit is not None:
            query += " LIMIT ?"
            params.append(limit)

        # Execute the query
        cursor = self.connection.cursor()
        cursor.execute(query, params)

        # Convert rows to dictionaries and parse JSON fields
        return [self._parse_metric_json_fields(dict(row)) for row in cursor.fetchall()]

    def delete_metrics(
        self,
        name: Optional[str] = None,
        older_than: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Delete metrics from the database.

        Args:
            tags: Delete metrics with these tags. If None, don't filter by tags.  # TODO: Line too long, needs manual fixing
            older_than: Delete metrics older than this timestamp.
            tags: Delete metrics with these tags. If None, don't filter by tags.

        Returns:
            Number of metrics deleted.

        Raises:
            sqlite3.Error: If the database operation fails.
        """
        if not self.connection:
            self.connect()

        # Build the query
        query = "DELETE FROM metrics"
        params = []
        conditions = []

        # Add name filter
        if name is not None:
            conditions.append("name = ?")
            params.append(name)

        # Add time filter
        if older_than is not None:
            conditions.append("timestamp < ?")
            params.append(older_than)

        # Add tags filter
        if tags is not None and tags:
            # Process each tag as a separate condition
            for key, value in tags.items():
                conditions.append(f"json_extract(tags, '$.{key}') = ?")
                params.append(value)

        # Add WHERE clause if there are conditions
        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        # Execute the query
        with self.transaction() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            # Get the number of rows affected
            deleted_count = cursor.rowcount

        return deleted_count

    def _export_json(self, metrics: List[Dict[str, Any]], output_path: Path) -> None:
        """
        Export metrics to a JSON file.

        Args:
            metrics: List of metrics to export
            output_path: Path to the output file
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2)

    def _export_csv(self, metrics: List[Dict[str, Any]], output_path: Path) -> None:
        """
        Export metrics to a CSV file.

        Args:
            metrics: List of metrics to export
            output_path: Path to the output file
        """
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            # Define the CSV fields
            if metrics:
                fieldnames = metrics[0].keys()
            else:
                fieldnames = [
                    "id",
                    "name",
                    "value",
                    "unit",
                    "tags",
                    "timestamp",
                    "datetime",
                    "context",
                ]

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for metric in metrics:
                # Convert complex types to strings for CSV
                if "context" in metric and isinstance(metric["context"], dict):
                    metric["context"] = json.dumps(metric["context"])
                if "tags" in metric and isinstance(metric["tags"], dict):
                    metric["tags"] = json.dumps(metric["tags"])

                writer.writerow(metric)

    def export_metrics(
        self,
        output_file: Union[str, Path],
        format: str = "json",
        name: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Export metrics to a file.

        Args:
            output_file: Path to the output file.
            format: Output format. One of "json", "csv".
            name: Name of the metric to export. If None, export all metrics.
            start_time: Filter metrics after this timestamp.
            end_time: Filter metrics before this timestamp.
            tags: Filter metrics with these tags. If None, don't filter by tags.

        Returns:
            Number of metrics exported.

        Raises:
            ValueError: If the format is not supported.
            IOError: If the file cannot be written.
        """
        # Query the metrics
        metrics = self.query_metrics(name, start_time, end_time, tags)

        # Ensure the output directory exists
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Export in the specified format
        format_lower = format.lower()
        if format_lower == "json":
            self._export_json(metrics, output_path)
        elif format_lower == "csv":
            self._export_csv(metrics, output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")

        return len(metrics)

    def get_database_status(self) -> Dict[str, Any]:
        """
        Get the status of the database.

        Returns:
            Dictionary with database status information.
        """
        if not self.connection:
            self.connect()

        cursor = self.connection.cursor()

        # Get the schema version
        schema_version = get_schema_version(self.connection)

        # Get the total number of metrics
        cursor.execute("SELECT COUNT(*) FROM metrics")
        total_metrics = cursor.fetchone()[0]

        # Get the number of distinct metric names
        cursor.execute("SELECT COUNT(DISTINCT name) FROM metrics")
        distinct_names = cursor.fetchone()[0]

        # Get the size of the database file
        db_size = os.path.getsize(self.db_path) if self.db_path.exists() else 0

        # Get the earliest and latest metrics
        cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM metrics")
        min_timestamp, max_timestamp = cursor.fetchone()

        earliest_metric = (
            datetime.fromtimestamp(min_timestamp).isoformat() if min_timestamp else None
        )
        latest_metric = (
            datetime.fromtimestamp(max_timestamp).isoformat() if max_timestamp else None
        )

        # Get the number of metrics in the last day
        one_day_ago = time.time() - 86400  # 24 hours in seconds
        cursor.execute(
            "SELECT COUNT(*) FROM metrics WHERE timestamp >= ?", (one_day_ago,)
        )
        metrics_last_day = cursor.fetchone()[0]

        return {
            "schema_version": schema_version,
            "total_metrics": total_metrics,
            "distinct_metric_names": distinct_names,
            "database_size_bytes": db_size,
            "earliest_metric": earliest_metric,
            "latest_metric": latest_metric,
            "metrics_last_day": metrics_last_day,
            "database_path": str(self.db_path),
        }


# Module-level functions for convenience


def connect_database(db_path: Union[str, Path]) -> MetricsDatabase:
    """
    Connect to the metrics database.

    Args:
        db_path: Path to the database file.

    Returns:
        Metrics database instance.
    """
    global _db_connection, _db_path

    if _db_connection:
        if _db_path == str(db_path):
            return _db_connection

        _db_connection.close()
        _db_connection = None

    # Create a new connection
    _db_connection = MetricsDatabase(db_path)
    _db_connection.connect()
    _db_path = str(db_path)

    return _db_connection


def close_database() -> None:
    """Close the current database connection."""
    global _db_connection, _db_path

    if _db_connection:
        _db_connection.close()
        _db_connection = None
        _db_path = None


def store_metric(
    name: str,
    value: Union[int, float],
    unit: str = "",
    tags: Optional[Dict[str, str]] = None,
    timestamp: Optional[float] = None,
    context: Optional[Dict[str, Any]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """
    Store a metric in the database.

    Args:
        name: Name of the metric.
        value: Value of the metric.
        unit: Unit of the metric.
        db_path: Path to the database file. If None, use the current connection.  # TODO: Line too long, needs manual fixing
        timestamp: Timestamp of the metric. If None, use current time.
        context: Additional context as JSON serializable dict.
        db_path: Path to the database file. If None, use the current connection.

    Returns:
        ID of the inserted metric record.
    """
    global _db_connection

    # Connect to the database if needed
    if db_path or not _db_connection:
        _db_connection = connect_database(
            db_path or os.environ.get("PS2_METRICS_DB", DEFAULT_DB_PATH)
        )

    # Store the metric
    return _db_connection.store_metric(name, value, unit, tags, timestamp, context)


def query_metrics(
    name: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    tags: Optional[Dict[str, str]] = None,
    limit: Optional[int] = None,
    order_by: str = "timestamp DESC",
    db_path: Optional[Union[str, Path]] = None,
) -> List[Dict[str, Any]]:
    """
    Query metrics from the database.
        db_path: Path to the database file. If None, use the current connection.  # TODO: Line too long, needs manual fixing
    Args:
        name: Name of the metric to filter by. If None, return all metrics.
        start_time: Filter metrics after this timestamp.
        end_time: Filter metrics before this timestamp.
        tags: Filter metrics by tags.
        limit: Maximum number of metrics to return.
        order_by: Order by clause for the query.
        db_path: Path to the database file. If None, use the current connection.

    Returns:
        List of metrics matching the query.
    """
    global _db_connection

    # Connect to the database if needed
    if db_path or not _db_connection:
        _db_connection = connect_database(
            db_path or os.environ.get("PS2_METRICS_DB", DEFAULT_DB_PATH)
        )

    # Query the metrics
    return _db_connection.query_metrics(
        name, start_time, end_time, tags, limit, order_by
    )


def delete_metrics(
    name: Optional[str] = None,
    older_than: Optional[float] = None,
    tags: Optional[Dict[str, str]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """
    Delete metrics from the database.

    Args:
        name: Name of the metric to delete. If None, delete all metrics.
        older_than: Delete metrics older than this timestamp.
        tags: Delete metrics with these tags.
        db_path: Path to the database file. If None, use the current connection.

    Returns:
        Number of metrics deleted.
    """
    global _db_connection

    # Connect to the database if needed
    if db_path or not _db_connection:
        _db_connection = connect_database(
            db_path or os.environ.get("PS2_METRICS_DB", DEFAULT_DB_PATH)
        )

    # Delete the metrics
    return _db_connection.delete_metrics(name, older_than, tags)


def export_metrics(
    output_file: Union[str, Path],
    format: str = "json",
    name: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    tags: Optional[Dict[str, str]] = None,
    db_path: Optional[Union[str, Path]] = None,
) -> int:
    """
    Export metrics to a file.

    Args:
        output_file: Path to the output file.
        format: Output format. One of "json", "csv".
        name: Name of the metric to export. If None, export all metrics.
        start_time: Export metrics after this timestamp.
        end_time: Export metrics before this timestamp.
        tags: Export metrics with these tags.
        db_path: Path to the database file. If None, use the current connection.

    Returns:
        Number of metrics exported.
    """
    global _db_connection

    # Connect to the database if needed
    if db_path or not _db_connection:
        _db_connection = connect_database(
            db_path or os.environ.get("PS2_METRICS_DB", DEFAULT_DB_PATH)
        )

    # Query metrics from the database
    metrics = _db_connection.query_metrics(
        name=name, start_time=start_time, end_time=end_time, tags=tags
    )

    # Convert output_file to Path object
    output_path = Path(output_file)

    # Export metrics based on format
    if format.lower() == "json":
        _db_connection._export_json(metrics, output_path)
    elif format.lower() == "csv":
        _db_connection._export_csv(metrics, output_path)
    else:
        raise ValueError(
            f"Unsupported export format: {format}. Supported formats: json, csv"
        )

    return len(metrics)


def get_database_status(db_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Get the status of the database.

    Args:
        db_path: Path to the database file. If None, use the current connection.

    Returns:
        Dictionary with database status information.
    """
    global _db_connection

    # Connect to the database if needed
    if db_path or not _db_connection:
        _db_connection = connect_database(
            db_path or os.environ.get("PS2_METRICS_DB", DEFAULT_DB_PATH)
        )

    # Get the database status
    return _db_connection.get_database_status()
