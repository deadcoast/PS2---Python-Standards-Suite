"""
Utilities Package for PS2.

This package provides utility functions and helpers used across
the PS2 system, including file operations, logging, and metrics.
"""

from src.utils.file_operations import (
    get_project_root,
    is_python_file,
    read_file_content,
    write_file_content,
    ensure_directory_exists,
    find_files_by_pattern,
    get_module_path,
)

from src.utils.logging_utils import (
    setup_logging,
    get_logger,
    log_function_call,
    log_execution_time,
)

from src.utils.metrics import (
    track_metric,
    get_metrics,
    calculate_average,
    calculate_percentile,
    format_metric,
)
