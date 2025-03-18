"""
Default Configuration Module for PS2.

This module provides default configuration settings for all PS2 components,
serving as the baseline configuration that can be overridden by user-specific
settings.
"""

import os
from pathlib import Path
from typing import Dict, Any

import json
import yaml
import toml

# File extension constants
JSON_EXT = ".json"
YAML_EXT = ".yaml"
YML_EXT = ".yml"
TOML_EXT = ".toml"


def get_default_config() -> Dict[str, Any]:
    """
    Get the default configuration for PS2.

    Returns:
        Dictionary with default configuration settings.
    """
    return {
        # General settings
        "general": {
            "verbose": False,
            "log_level": "INFO",
            "colored_output": True,
        },
        # Analyzer settings
        "analyzer": {
            "exclude_patterns": [
                r"\.git",
                r"\.venv",
                r"venv",
                r"env",
                r"__pycache__",
                r"\.pytest_cache",
                r"\.mypy_cache",
                r"\.tox",
                r"build",
                r"dist",
                r"\.eggs",
                r"\.vscode",
                r"\.idea",
            ],
            "max_methods_per_class": 20,
            "max_line_length": 100,
            "max_complexity": 10,
        },
        # Code quality settings
        "code_quality": {
            "style_tools": ["black", "isort"],
            "linting_tools": ["flake8", "pylint"],
            "type_checking_tools": ["mypy"],
            "documentation_tools": ["pydocstyle"],
            "complexity_tools": ["radon"],
            "check_coverage": True,
            "min_coverage": 70.0,
        },
        # Conflict resolver settings
        "conflict_resolver": {
            "auto_rename": False,
            "protected_names": ["main", "app", "run", "test"],
            "class_name_convention": "PascalCase",
            "function_name_convention": "snake_case",
            "variable_name_convention": "snake_case",
            "constant_name_convention": "UPPER_SNAKE_CASE",
        },
        # Dependency manager settings
        "dependency_manager": {
            "auto_update_requirements": True,
            "track_dev_dependencies": True,
            "pin_versions": True,
            "check_vulnerabilities": True,
        },
        # Duplication detector settings
        "duplication_detector": {
            "min_lines": 6,
            "min_tokens": 25,
            "ignore_comments": True,
            "ignore_docstrings": False,
            "ignore_imports": True,
            "ignore_variable_names": False,
            "function_similarity_threshold": 0.8,
        },
        # Import enforcer settings
        "import_enforcer": {
            "prefer_absolute_imports": True,
            "enforce_import_order": True,
            "enforce_import_grouping": True,
            "disallow_star_imports": True,
            "max_import_line_length": 79,
        },
        # Performance monitor settings
        "performance_monitor": {
            "track_memory_usage": True,
            "track_execution_time": True,
            "execution_time_threshold": 1.0,  # seconds
            "memory_usage_threshold": 100,  # MB
            "log_performance_stats": True,
        },
        # Project generator settings
        "project_generator": {
            "author_name": os.environ.get("USER", "Unknown"),
            "author_email": "",
            "license": "MIT",
            "python_version": ">=3.8",
            "use_src_layout": True,
            "include_tests": True,
            "include_docs": True,
            "include_ci": True,
            "include_docker": False,
            "create_virtual_env": True,
            "initialize_git": True,
        },
        # Security scanner settings
        "security_scanner": {
            "scan_dependencies": True,
            "scan_code": True,
            "scan_web_security": True,
            "check_secrets": True,
            "min_severity": "medium",
            "ignore_patterns": [],
        },
        # Task manager settings
        "task_manager": {
            "task_file": "ps2_tasks.json",
            "priority_levels": ["critical", "high", "medium", "low"],
            "default_priority": "medium",
            "assign_tasks": False,
            "track_resolution_time": True,
        },
    }


def get_config_from_file(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from a file.

    Args:
        config_path: Path to the configuration file.

    Returns:
        Dictionary with configuration settings.
    """

    # Default config
    config = get_default_config()

    if not config_path.exists():
        return config

    # Determine file format and load
    if config_path.suffix == JSON_EXT:
        with open(config_path, "r") as f:
            user_config = json.load(f)
    elif config_path.suffix in [YML_EXT, YAML_EXT]:
        with open(config_path, "r") as f:
            user_config = yaml.safe_load(f)
    elif config_path.suffix == TOML_EXT:
        with open(config_path, "r") as f:
            user_config = toml.load(f)
    else:
        # Unsupported format
        return config

    # Merge user config with default config
    config = _merge_configs(config, user_config)

    return config


def _merge_configs(
    default_config: Dict[str, Any], user_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Recursively merge two configuration dictionaries.

    Args:
        default_config: Default configuration dictionary.
        user_config: User configuration dictionary.

    Returns:
        Merged configuration dictionary.
    """
    merged_config = default_config.copy()

    for key, value in user_config.items():
        if (
            key in default_config
            and isinstance(default_config[key], dict)
            and isinstance(value, dict)
        ):
            # Recursively merge nested dictionaries
            merged_config[key] = _merge_configs(default_config[key], value)
        else:
            # Override or add the user value
            merged_config[key] = value

    return merged_config


def get_user_config_path() -> Path:
    """
    Get the path to the user's PS2 configuration file.

    Looks for configuration files in the following locations (in order):
    1. Current directory (.ps2.{json,yaml,yml,toml})
    2. User's home directory (~/.ps2.{json,yaml,yml,toml})

    Returns:
        Path to the user's configuration file, or None if not found.
    """
    # Check current directory
    current_dir = Path.cwd()
    for ext in [JSON_EXT, YAML_EXT, YML_EXT, TOML_EXT]:
        config_path = current_dir / f".ps2{ext}"
        if config_path.exists():
            return config_path

    # Check home directory
    home_dir = Path.home()
    for ext in [JSON_EXT, YAML_EXT, YML_EXT, TOML_EXT]:
        config_path = home_dir / f".ps2{ext}"
        if config_path.exists():
            return config_path

    # Default to JSON in current directory
    return current_dir / f".ps2{JSON_EXT}"
