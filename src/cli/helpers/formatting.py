"""
Formatting Helper Module for PS2 CLI.

This module provides helper functions for formatting output in the PS2 CLI.
"""

from typing import (  # TODO: Remove unused imports; TODO: Remove unused imports  # TODO: Remove unused imports
    Any, Dict, Optional, Union)

try:
    from colorama import (  # TODO: Remove unused imports; TODO: Remove unused imports  # TODO: Remove unused imports
        Fore, Style, init)

    init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False


# Define output formats
output_formats = {
    "pretty": "Human-readable output with color (if available)",
    "json": "JSON output",
    "simple": "Simple text output without color",
}


def format_result(result: Dict[str, Any], format_type: str) -> str:
    """
    Format a result dictionary for output.

    Args:
        result: Result dictionary to format.
        format_type: Output format type.

    Returns:
        Formatted output string.
    """
    if format_type == "json":
        return json.dumps(result, indent=2)
    elif format_type == "simple":
        return _format_simple(result)
    else:  # "pretty" is the default
        return _format_pretty(result)


def _format_simple(result: Dict[str, Any]) -> str:
    """
    Format result as simple text.

    Args:
        result: Result dictionary to format.

    Returns:
        Simple text output.
    """
    lines = []

    # Add status and message
    if "status" in result:
        lines.append(f"Status: {result['status'].upper()}")

    if "message" in result:
        lines.append(f"Message: {result['message']}")

    # Add other fields
    for key, value in result.items():
        if isinstance(value, dict):
            if key not in ["status", "message"]:
                lines.append(f"\n{key}:")
                lines.extend(f"  {k}: {v}" for k, v in value.items())
        elif isinstance(value, list):
            if key not in ["status", "message"]:
                lines.append(f"\n{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.extend(f"  {k}: {v}" for k, v in item.items())
                        lines.append("")
                    else:
                        lines.append(f"  {item}")
        elif key not in ["status", "message"]:
            lines.append(f"\n{key}: {value}")

    return "\n".join(lines)


def _format_pretty(result: Dict[str, Any]) -> str:
    """
    Format result as pretty text with color (if available).

    Args:
        result: Result dictionary to format.

    Returns:
        Pretty output string.
    """
    if not HAS_COLORAMA:
        # Fall back to simple formatting if colorama is not available
        return _format_simple(result)

    lines = []

    # Add status with color
    if "status" in result:
        status = result["status"].upper()
        if status == "FAIL":
            status_str = f"{Fore.RED}{status}{Style.RESET_ALL}"
        elif status in ["FIXED", "WARNING"]:
            status_str = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
        elif status == "INFO":
            status_str = f"{Fore.BLUE}{status}{Style.RESET_ALL}"
        elif status == "PASS":
            status_str = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        else:
            status_str = f"{status}"

        lines.append(f"Status: {status_str}")

    # Add message
    if "message" in result:
        lines.append(f"Message: {result['message']}")

    # Add other fields with pretty formatting
    for key, value in result.items():
            # Format dictionary fields
        if isinstance(value, dict):
            if key not in ["status", "message"]:
                lines.append(f"\n{Fore.CYAN}{key}:{Style.RESET_ALL}")
                for k, v in value.items():
                    # Format nested dictionaries recursively
                    if isinstance(v, dict):
                        lines.append(f"  {Fore.CYAN}{k}:{Style.RESET_ALL}")
                        lines.extend(f"    {nk}: {_format_value(nv)}" for nk, nv in v.items())
                    else:
                        lines.append(f"  {k}: {_format_value(v)}")

        elif isinstance(value, list):
            if key not in ["status", "message"]:
                lines.append(f"\n{Fore.CYAN}{key}:{Style.RESET_ALL}")
                if value:
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            if i > 0:
                                lines.append("")  # Add separator between items
                            lines.extend(f"  {k}: {_format_value(v)}" for k, v in item.items())
                        else:
                            lines.append(f"  {_format_value(item)}")
                else:
                    lines.append("  (empty)")

        elif key not in ["status", "message"]:
            lines.append(
                f"\n{Fore.CYAN}{key}:{Style.RESET_ALL} {_format_value(value)}"
            )

    return "\n".join(lines)


def _format_value(value: Any) -> str:
    """
    Format a single value with appropriate styling.

    Args:
        value: Value to format.

    Returns:
        Formatted value string.
    """
    if not HAS_COLORAMA:
        return str(value)

    # Format based on value type or content
    if isinstance(value, bool):
        return (
            f"{Fore.GREEN}True{Style.RESET_ALL}"
            if value
            else f"{Fore.RED}False{Style.RESET_ALL}"
        )

    if isinstance(value, (int, float)):
        return f"{Fore.BLUE}{value}{Style.RESET_ALL}"

    if isinstance(value, str):
        # Check if the string represents a status or severity
        lower_value = value.lower()
        if lower_value in ["pass", "fixed", "ok", "success"]:
            return f"{Fore.GREEN}{value}{Style.RESET_ALL}"
        elif lower_value in ["fail", "error", "critical"]:
            return f"{Fore.RED}{value}{Style.RESET_ALL}"
        elif lower_value in ["warning", "medium"]:
            return f"{Fore.YELLOW}{value}{Style.RESET_ALL}"
        elif lower_value in ["info", "low"]:
            return f"{Fore.BLUE}{value}{Style.RESET_ALL}"

        # Format file paths and code differently
        if value.endswith((".py", ".json", ".yml", ".yaml", ".toml", ".ini")):
            return f"{Fore.MAGENTA}{value}{Style.RESET_ALL}"
        if "def " in value or "class " in value or "import " in value:
            return f"{Fore.MAGENTA}{value}{Style.RESET_ALL}"

    # Default formatting
    return str(value)


def shorten_list(items: list, max_items: int = 5) -> list:
    """
    Shorten a list to a maximum number of items.

    Args:
        items: List to shorten.
        max_items: Maximum number of items to keep.

    Returns:
        Shortened list, with count info appended if truncated.
    """
    if len(items) <= max_items:
        return items

    result = items[:max_items].copy()
    remaining = len(items) - max_items
    result.append(f"... and {remaining} more items")
    return result


def get_status_icon(status: str) -> str:
    """
    Get an icon representing the status.

    Args:
        status: Status string.

    Returns:
        Icon character representing the status.
    """
    status = status.lower()
    if status in ["pass", "fixed", "ok", "success"]:
        return "✅" if HAS_COLORAMA else "[PASS]"
    elif status in ["fail", "error", "critical"]:
        return "❌" if HAS_COLORAMA else "[FAIL]"
    elif status in ["warning", "medium"]:
        return "⚠️" if HAS_COLORAMA else "[WARNING]"
    elif status in ["info", "low"]:
        return "ℹ️" if HAS_COLORAMA else "[INFO]"
    else:
        return "•" if HAS_COLORAMA else "[•]"
