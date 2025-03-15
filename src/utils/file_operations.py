"""
File Operations Utility Module for PS2.

This module provides utility functions for file and directory operations,
simplifying common tasks like finding project roots, reading and writing
files, and locating modules.
"""

import os
import fnmatch
import shutil
from pathlib import Path
from typing import List, Optional, Union, Set, Dict, Any, Iterator


def get_project_root(start_dir: Union[str, Path] = None) -> Path:
    """
    Find the project root directory based on common markers.

    Starts from the given directory (or current directory if None) and
    searches upward until a project root marker is found.

    Args:
        start_dir: Directory to start the search from. Defaults to current directory.

    Returns:
        Path to the project root directory.
    """
    if start_dir is None:
        start_dir = Path.cwd()
    else:
        start_dir = Path(start_dir).absolute()

    # Common project root markers
    root_markers = [
        ".git",
        "setup.py",
        "pyproject.toml",
        "requirements.txt",
        ".ps2.json",
        ".ps2.yaml",
        ".ps2.yml",
        ".ps2.toml",
    ]

    # Start from the given directory and move upward
    current_dir = start_dir
    while current_dir != current_dir.parent:  # Stop at the filesystem root
        # Check for root markers
        for marker in root_markers:
            if (current_dir / marker).exists():
                return current_dir

        # Move up one level
        current_dir = current_dir.parent

    # If no root marker is found, return the original directory
    return start_dir


def is_python_file(file_path: Union[str, Path]) -> bool:
    """
    Check if a file is a Python file based on extension.

    Args:
        file_path: Path to the file to check.

    Returns:
        True if the file is a Python file, False otherwise.
    """
    return str(file_path).endswith(".py")


def read_file_content(file_path: Union[str, Path], encoding: str = "utf-8") -> str:
    """
    Read the content of a file.

    Args:
        file_path: Path to the file to read.
        encoding: File encoding. Defaults to utf-8.

    Returns:
        Content of the file as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
        UnicodeDecodeError: If the file cannot be decoded with the given encoding.
    """
    with open(file_path, "r", encoding=encoding) as f:
        return f.read()


def write_file_content(
    file_path: Union[str, Path], content: str, encoding: str = "utf-8"
) -> None:
    """
    Write content to a file.

    Args:
        file_path: Path to the file to write.
        content: Content to write to the file.
        encoding: File encoding. Defaults to utf-8.

    Raises:
        PermissionError: If the file cannot be written.
    """
    # Ensure directory exists
    file_dir = Path(file_path).parent
    ensure_directory_exists(file_dir)

    # Write file
    with open(file_path, "w", encoding=encoding) as f:
        f.write(content)


def ensure_directory_exists(directory: Union[str, Path]) -> None:
    """
    Ensure that a directory exists, creating it if necessary.

    Args:
        directory: Path to the directory to ensure exists.

    Raises:
        PermissionError: If the directory cannot be created.
    """
    Path(directory).mkdir(parents=True, exist_ok=True)


def find_files_by_pattern(
    directory: Union[str, Path],
    pattern: str = "*.py",
    recursive: bool = True,
    exclude_patterns: List[str] = None,
) -> List[Path]:
    """
    Find files matching a pattern in a directory.

    Args:
        directory: Directory to search in.
        pattern: File pattern to match (glob syntax). Defaults to "*.py".
        recursive: Whether to search recursively. Defaults to True.
        exclude_patterns: List of patterns to exclude. Defaults to None.

    Returns:
        List of paths to matching files.
    """
    directory = Path(directory)

    if not exclude_patterns:
        exclude_patterns = []

    matching_files = []

    # Walk through the directory
    if recursive:
        for root, dirs, files in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [
                d
                for d in dirs
                if not any(fnmatch.fnmatch(d, ep) for ep in exclude_patterns)
            ]

            # Find matching files
            for file in files:
                if fnmatch.fnmatch(file, pattern):
                    file_path = Path(root) / file
                    rel_path = file_path.relative_to(directory)

                    # Skip excluded files
                    if any(
                        fnmatch.fnmatch(str(rel_path), ep) for ep in exclude_patterns
                    ):
                        continue

                    matching_files.append(file_path)
    else:
        # Non-recursive search
        for file in directory.iterdir():
            if file.is_file() and fnmatch.fnmatch(file.name, pattern):
                rel_path = file.relative_to(directory)

                # Skip excluded files
                if any(fnmatch.fnmatch(str(rel_path), ep) for ep in exclude_patterns):
                    continue

                matching_files.append(file)

    return matching_files


def get_module_path(
    module_name: str, base_dir: Union[str, Path] = None
) -> Optional[Path]:
    """
    Get the file path for a Python module.

    Args:
        module_name: Fully qualified module name (e.g., "package.module").
        base_dir: Base directory to search from. Defaults to project root.

    Returns:
        Path to the module file, or None if not found.
    """
    if base_dir is None:
        base_dir = get_project_root()
    else:
        base_dir = Path(base_dir)

    # Convert module name to path
    module_parts = module_name.split(".")

    # Try direct match first
    module_path = base_dir
    for part in module_parts[:-1]:  # All parts except the last one (directory parts)
        module_path = module_path / part
        if not module_path.exists() or not module_path.is_dir():
            return None

    # Try different options for the last part (file part)
    last_part = module_parts[-1]

    # Option 1: Last part is a Python file
    file_path = module_path / f"{last_part}.py"
    if file_path.exists() and file_path.is_file():
        return file_path

    # Option 2: Last part is a directory with __init__.py
    dir_path = module_path / last_part
    init_path = dir_path / "__init__.py"
    if (
        dir_path.exists()
        and dir_path.is_dir()
        and init_path.exists()
        and init_path.is_file()
    ):
        return init_path

    # Not found
    return None
