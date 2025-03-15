"""
Database Package for PS2.

This package provides database functionality for PS2, including metrics storage,
performance tracking, and historical data analysis.
"""

from src.database.metrics_db import (
    MetricsDatabase,
    connect_database,
    close_database,
    store_metric,
    query_metrics,
    delete_metrics,
    export_metrics,
    get_database_status,
)

from src.database.schema import (
    create_tables,
    drop_tables,
    get_schema_version,
    upgrade_schema,
)
