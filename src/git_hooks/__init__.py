"""
Git Hooks Package for PS2.

This package provides Git hooks that can be installed in a Git repository
to enforce PS2 standards during the Git workflow.
"""

import os
import shutil
import stat
from pathlib import Path
from typing import List, Optional


def install_git_hooks(
    repo_path: str, hooks_to_install: Optional[List[str]] = None, force: bool = False
) -> List[str]:
    """
    Install PS2 Git hooks into a Git repository.

    Args:
        repo_path: Path to the Git repository.
        hooks_to_install: List of hook names to install. If None, install all hooks.
        force: Whether to overwrite existing hooks.

    Returns:
        List of installed hook names.
    """
    # Get the path to the hooks directory
    hooks_dir = Path(__file__).parent

    # Get the path to the Git hooks directory
    git_hooks_dir = Path(repo_path) / ".git" / "hooks"

    # Ensure the Git hooks directory exists
    if not git_hooks_dir.exists():
        raise ValueError(f"Git hooks directory not found: {git_hooks_dir}")

    # Get all available hooks if hooks_to_install is None
    if hooks_to_install is None:
        hooks_to_install = []
        for hook_file in hooks_dir.iterdir():
            if not hook_file.name.startswith("__") and not hook_file.is_dir():
                hooks_to_install.append(hook_file.name)

    # Install each hook
    installed_hooks = []
    for hook_name in hooks_to_install:
        hook_path = hooks_dir / hook_name

        # Skip if hook doesn't exist
        if not hook_path.exists():
            continue

        # Destination path in the Git repository
        dest_path = git_hooks_dir / hook_name

        # Check if the hook already exists
        if dest_path.exists() and not force:
            continue

        # Copy the hook
        shutil.copy2(hook_path, dest_path)

        # Make the hook executable
        os.chmod(
            dest_path,
            os.stat(dest_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH,
        )

        installed_hooks.append(hook_name)

    return installed_hooks


def uninstall_git_hooks(
    repo_path: str, hooks_to_uninstall: Optional[List[str]] = None
) -> List[str]:
    """
    Uninstall PS2 Git hooks from a Git repository.

    Args:
        repo_path: Path to the Git repository.
        hooks_to_uninstall: List of hook names to uninstall. If None, uninstall all hooks.

    Returns:
        List of uninstalled hook names.
    """
    # Get the path to the hooks directory
    hooks_dir = Path(__file__).parent

    # Get the path to the Git hooks directory
    git_hooks_dir = Path(repo_path) / ".git" / "hooks"

    # Ensure the Git hooks directory exists
    if not git_hooks_dir.exists():
        raise ValueError(f"Git hooks directory not found: {git_hooks_dir}")

    # Get all available hooks if hooks_to_uninstall is None
    if hooks_to_uninstall is None:
        hooks_to_uninstall = []
        for hook_file in hooks_dir.iterdir():
            if not hook_file.name.startswith("__") and not hook_file.is_dir():
                hooks_to_uninstall.append(hook_file.name)

    # Uninstall each hook
    uninstalled_hooks = []
    for hook_name in hooks_to_uninstall:
        # Destination path in the Git repository
        dest_path = git_hooks_dir / hook_name

        # Skip if hook doesn't exist
        if not dest_path.exists():
            continue

        # Check if the hook is a PS2 hook
        with open(dest_path, "r") as f:
            content = f.read()
            if "Python Standards Suite (PS2)" not in content:
                continue

        # Remove the hook
        os.remove(dest_path)

        uninstalled_hooks.append(hook_name)

    return uninstalled_hooks
