"""
Validation Helper Module for PS2 CLI.

This module provides helper functions for validating user input in the PS2 CLI.
"""

import os
import re
from pathlib import Path
from typing import Optional, List, Tuple, Any


def validate_project_name(name: str) -> Tuple[bool, str]:
    """
    Validate a project name.

    Args:
        name: Project name to validate.

    Returns:
        Tuple of (is_valid, message).
    """
    # Check if name is valid Python package name
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", name):
        return False, "Project name must be a valid Python package name"

    # Check if name is not a Python reserved word
    python_keywords = {
        "False",
        "None",
        "True",
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
    }

    if name in python_keywords:
        return False, f"'{name}' is a Python reserved keyword"

    return True, "Project name is valid"


def validate_project_path(path: str) -> Tuple[bool, str]:
    """
    Validate a project path.

    Args:
        path: Project path to validate.

    Returns:
        Tuple of (is_valid, message).
    """
    # Convert to Path object
    path_obj = Path(path)

    # Check if path exists
    if not path_obj.exists():
        return False, f"Path does not exist: {path}"

    # Check if path is a directory
    if not path_obj.is_dir():
        return False, f"Path is not a directory: {path}"

    # Check if path is readable
    if not os.access(path, os.R_OK):
        return False, f"Path is not readable: {path}"

    return True, "Project path is valid"


def validate_python_version(version: str) -> Tuple[bool, str]:
    """
    Validate a Python version string.

    Args:
        version: Python version to validate (e.g. ">=3.8").

    Returns:
        Tuple of (is_valid, message).
    """
    # Match version patterns like ">=3.8", "~=3.7", "==3.9", "3.8"
    if not re.match(r"^(>=|<=|==|~=|!=|>|<)?(\d+)\.(\d+)(\.(\d+))?$", version):
        return False, f"Invalid Python version format: {version}"

    return True, "Python version is valid"


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate an email address.

    Args:
        email: Email address to validate.

    Returns:
        Tuple of (is_valid, message).
    """
    if not email:
        return True, "Email is optional"

    # Simple email validation regex
    if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
        return False, f"Invalid email format: {email}"

    return True, "Email is valid"


def validate_license(license: str) -> Tuple[bool, str]:
    """
    Validate a license identifier.

    Args:
        license: License identifier to validate.

    Returns:
        Tuple of (is_valid, message).
    """
    # Common license identifiers
    valid_licenses = {
        "MIT",
        "Apache-2.0",
        "BSD-3-Clause",
        "GPL-3.0",
        "LGPL-3.0",
        "MPL-2.0",
        "AGPL-3.0",
        "Unlicense",
        "Proprietary",
    }

    if license not in valid_licenses:
        return (
            False,
            f"Unknown license: {license}. Valid options are: {', '.join(valid_licenses)}",
        )

    return True, "License is valid"


def validate_output_file(file_path: str, format_type: str) -> Tuple[bool, str]:
    """
    Validate an output file path.

    Args:
        file_path: Output file path to validate.
        format_type: Expected format type.

    Returns:
        Tuple of (is_valid, message).
    """
    # Convert to Path object
    path_obj = Path(file_path)

    # Check if directory exists
    if not path_obj.parent.exists():
        return False, f"Directory does not exist: {path_obj.parent}"

    # Check if directory is writable
    if not os.access(path_obj.parent, os.W_OK):
        return False, f"Directory is not writable: {path_obj.parent}"

    # Check file extension
    extension = path_obj.suffix.lower()[1:]  # Remove the dot
    if format_type.lower() != extension and format_type.lower() != "any":
        return (
            False,
            f"File extension '{extension}' does not match expected format '{format_type}'",
        )

    return True, "Output file path is valid"


def validate_config_file(file_path: str) -> Tuple[bool, str]:
    """
    Validate a configuration file.

    Args:
        file_path: Path to configuration file.

    Returns:
        Tuple of (is_valid, message).
    """
    # Convert to Path object
    path_obj = Path(file_path)

    # Check if file exists
    if not path_obj.exists():
        return False, f"Configuration file does not exist: {file_path}"

    # Check if file is readable
    if not os.access(file_path, os.R_OK):
        return False, f"Configuration file is not readable: {file_path}"

    # Check if file has valid extension
    valid_extensions = [".json", ".yaml", ".yml", ".toml"]
    if path_obj.suffix.lower() not in valid_extensions:
        return (
            False,
            f"Configuration file must have one of these extensions: {', '.join(valid_extensions)}",
        )

    return True, "Configuration file is valid"
