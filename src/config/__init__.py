"""
Configuration Package for PS2.

This package contains configuration modules and default settings for the PS2 system,
providing centralized configuration management for all PS2 components.
"""

from src.config.default_settings import (
    get_default_config,
    get_config_from_file,
    get_user_config_path,
)
