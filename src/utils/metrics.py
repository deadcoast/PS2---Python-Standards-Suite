"""
Metrics Utilities Module for PS2.

This module provides utility functions for tracking, storing, and analyzing
metrics throughout the PS2 system, enabling performance monitoring and
resource usage tracking.
"""
import time
import json
import statistics
from pathlib import Path
from datetime import datetime
from typing import (Any, Dict, List, Optional, Tuple, Union)

# Global metrics storage
_metrics: Dict[str, List[Dict[str, Any]]] = {}


def track_metric(
    name: str,
    value: Union[int, float],
    unit: str = "",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Track a metric for later analysis.

    Args:
        name: Name of the metric.
        value: Value of the metric.
        unit: Unit of the metric. Defaults to "".
        context: Additional context information. Defaults to None.

    Returns:
        The recorded metric entry.
    """
    # Initialize context if not provided
    if context is None:
        context = {}

    # Create metric entry
    metric = {
        "name": name,
        "value": value,
        "unit": unit,
        "timestamp": time.time(),
        "datetime": datetime.now().isoformat(),
        "context": context,
    }

    # Store metric
    if name not in _metrics:
        _metrics[name] = []

    _metrics[name].append(metric)

    return metric


def get_metrics(
    name: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
    filter_func: Optional[callable] = None,
) -> List[Dict[str, Any]]:
    """
    Get tracked metrics, optionally filtered.

    Args:
        name: Name of the metric to filter by. If None, return all metrics. Defaults to None.  # TODO: Line too long, needs manual fixing
        start_time: Filter metrics after this timestamp. Defaults to None.
        end_time: Filter metrics before this timestamp. Defaults to None.
        filter_func: Custom filter function that takes a metric and returns a boolean. Defaults to None.  # TODO: Line too long, needs manual fixing

    Returns:
        List of matching metric entries.
    """
    # Determine which metrics to retrieve
    if name is not None:
        # Get metrics with the specified name
        metrics_to_search = _metrics.get(name, [])
    else:
        # Get all metrics
        metrics_to_search = []
        for metric_list in _metrics.values():
            metrics_to_search.extend(metric_list)

    # Apply filters
    filtered_metrics = metrics_to_search

    # Filter by time range
    if start_time is not None or end_time is not None:
        start_time = start_time or 0
        end_time = end_time or float("inf")

        filtered_metrics = [
            m for m in filtered_metrics if start_time <= m["timestamp"] <= end_time
        ]

    # Apply custom filter
    if filter_func is not None:
        filtered_metrics = [m for m in filtered_metrics if filter_func(m)]

    return filtered_metrics


def calculate_average(
    name: str, start_time: Optional[float] = None, end_time: Optional[float] = None
) -> Tuple[Optional[float], int]:
    """
    Calculate the average value of a metric.

    Args:
        name: Name of the metric.
        start_time: Start time for filtering. Defaults to None.
        end_time: End time for filtering. Defaults to None.

    Returns:
        Tuple of (average value, count of metrics used in calculation).
        If no metrics are found, returns (None, 0).
    """
    metrics = get_metrics(name, start_time, end_time)

    if not metrics:
        return None, 0

    values = [m["value"] for m in metrics]
    avg_value = sum(values) / len(values)

    return avg_value, len(metrics)


def calculate_percentile(
    name: str,
    percentile: float,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
) -> Tuple[Optional[float], int]:
    """
    Calculate a percentile value of a metric.

    Args:
        name: Name of the metric.
        percentile: Percentile to calculate (0-100).
        start_time: Start time for filtering. Defaults to None.
        end_time: End time for filtering. Defaults to None.

    Returns:
        Tuple of (percentile value, count of metrics used in calculation).
        If no metrics are found, returns (None, 0).
    """
    metrics = get_metrics(name, start_time, end_time)

    if not metrics:
        return None, 0

    values = [m["value"] for m in metrics]

    # Calculate percentile
    try:
        # Use statistics.quantiles for larger datasets
        percentile_value = statistics.quantiles(values,
            n=100)[int(percentile)]
    except (statistics.StatisticsError, IndexError):
        # Fall back to more basic method for small samples
        values.sort()
        index = int(percentile / 100.0 * len(values))
        percentile_value = values[max(0, min(index, len(values) - 1))]

    return percentile_value, len(metrics)


def format_metric(value: float, unit: str = "") -> str:
    """
    Format a metric value with its unit for display.

    Args:
        value: Value to format.
        unit: Unit of the value. Defaults to "".

    Returns:
        Formatted string.
    """
    # Handle time units
    if unit in ["s", "seconds"]:
        if value < 0.001:
            return f"{value * 1_000_000:.2f} µs"
        elif value < 1:
            return f"{value * 1_000:.2f} ms"
        elif value < 60:
            return f"{value:.2f} s"
        elif value < 3600:
            minutes = value // 60
            seconds = value % 60
            return f"{int(minutes)}m {int(seconds)}s"
        else:
            hours = value // 3600
            minutes = (value % 3600) // 60
            return f"{int(hours)}h {int(minutes)}m"

    elif unit in ["b", "bytes"]:
        if value < 1024:
            return f"{value:.0f} B"
        elif value < 1024 * 1024:
            return f"{value / 1024:.2f} KB"
        elif value < 1024 * 1024 * 1024:
            return f"{value / (1024 * 1024):.2f} MB"
        else:
            return f"{value / (1024 * 1024 * 1024):.2f} GB"

    elif unit in ["%", "percent", "percentage"]:
        return f"{value:.2f}%"

    else:
        if isinstance(value, int) or value.is_integer():
            return f"{int(value)}{f' {unit}' if unit else ''}"
        else:
            return f"{value:.2f}{f' {unit}' if unit else ''}"


def save_metrics_to_file(file_path: Union[str, Path]) -> int:
    """
    Save all tracked metrics to a JSON file.

    Args:
        file_path: Path to the file to save metrics to.

    Returns:
        Number of metrics saved.
    """
    # Count total metrics
    total_metrics = sum(len(metrics) for metrics in _metrics.values())

    # Prepare file path
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # Save metrics
    with open(file_path, "w") as f:
        json.dump(_metrics, f, indent=2)

    return total_metrics


def load_metrics_from_file(file_path: Union[str, Path]) -> int:
    """
    Load metrics from a JSON file.

    Args:
        file_path: Path to the file to load metrics from.

    Returns:
        Number of metrics loaded.
    """
    global _metrics

    # Load metrics
    with open(file_path, "r") as f:
        loaded_metrics = json.load(f)

    # Merge with existing metrics
    for name, metrics in loaded_metrics.items():
        if name not in _metrics:
            _metrics[name] = []
        _metrics[name].extend(metrics)

    return sum(len(metrics) for metrics in loaded_metrics.values())


def clear_metrics(name: Optional[str] = None) -> int:
    """
    Clear tracked metrics.

        name: Name of the metric to clear. If None, clear all metrics. Defaults to None.  # TODO: Line too long, needs manual fixing
        name: Name of the metric to clear. If None, clear all metrics. Defaults to None.

    Returns:
        Number of metrics cleared.
    """
    global _metrics

    if name is not None:
        # Clear specific metric
        metrics_count = len(_metrics.get(name, []))
        if name in _metrics:
            del _metrics[name]
    else:
        # Clear all metrics
        metrics_count = sum(len(metrics) for metrics in _metrics.values())
        _metrics = {}

    return metrics_count