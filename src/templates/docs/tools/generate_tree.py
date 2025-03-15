#!/usr/bin/env python3
"""
Rich Directory Tree Generator

A simple script that uses the Rich library to generate beautiful directory trees.
This approach uses a third-party library instead of custom code for reliability.

Usage:
    python rich_directory_tree.py [options]

Options:
    --path PATH         Directory to generate tree for (default: current script location)
    --output FILE       Output file (default: rich_directory_tree.md in script directory)
    --ignore PATTERN    Patterns to ignore (can be specified multiple times)
    --max-depth N       Maximum depth to display

Author: Space Muck Team
"""

import os
import sys
import glob
import argparse
from pathlib import Path

try:
    from rich.tree import Tree
    from rich.console import Console
    from rich import print as rprint
except ImportError:
    print("This script requires the Rich library. Installing it now...")
    import subprocess

    subprocess.check_call([sys.executable, "-m", "pip", "install", "rich"])
    from rich.tree import Tree
    from rich.console import Console
    from rich import print as rprint

# Default patterns to ignore
DEFAULT_IGNORE = [
    # Common directories to ignore
    "__pycache__",
    ".git",
    ".husky",
    ".idea",
    ".vscode",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".venv",
    "env",
    ".env",
    ".tox",
    ".cache",
    ".tmp",
    "tmp",
    # Package manager directories
    ".npm",
    ".yarn",
    ".pnpm-store",
    # Build output directories
    "out",
    ".next",
    ".nuxt",
    # Test directories
    ".jest",
    ".pytest_cache",
    "__tests__",
    "__snapshots__",
    "tests/fixtures",
    "test-results",
    "cypress/videos",
    "cypress/screenshots",
    # TypeScript/JavaScript specific
    "*.js.map",
    "*.d.ts.map",
    "*.tsbuildinfo",
    "*.js.LICENSE.txt",
    "*.chunk.js",
    # Common files to ignore
    "*.pyc",
    "*.pyo",
    ".DS_Store",
    "*.egg-info",
    "*.log",
    "*.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    ".eslintcache",
    ".stylelintcache",
    ".prettierignore",
    ".eslintignore",
    ".npmrc",
    ".yarnrc",
    ".gitignore",
    ".gitattributes",
    ".editorconfig",
    "thumbs.db",
    "desktop.ini",
    ".git",
    # Common config files (unless you want to see them)
    "*.config.js",
    "*.config.ts",
    "tsconfig*.json",
    "jest.config.js",
    "jest.config.ts",
    "babel.config.js",
    "webpack.*.js",
    "rollup.*.js",
    "vite.*.js",
    # Project-specific (for Galactic_Sprawl)
    "eslint-output.json",
    "*.snap",
    "CodeBase_Docs/CodeBase_Error_Log.md",
    "CodeBase_Docs/CodeBase_Linting_Progress.md",
    ".pixelArtAssets",
    ".assets",
    "CodeBase_Docs/",
]


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate a beautiful directory tree using Rich"
    )
    parser.add_argument("--path", type=str, help="Directory to generate tree for")
    parser.add_argument("--output", type=str, help="Output file")
    parser.add_argument(
        "--ignore", action="append", help="Patterns to ignore", default=[]
    )
    parser.add_argument("--max-depth", type=int, help="Maximum depth to display")
    parser.add_argument(
        "--use-default-ignore", action="store_true", help="Use default ignore patterns"
    )
    return parser.parse_args()


def should_ignore(path, ignore_patterns):
    """Check if path should be ignored based on patterns."""
    if not ignore_patterns:
        return False
        
    # Get the path as string and the filename/dirname
    path_str = str(path)
    name = path.name
    
    for pattern in ignore_patterns:
        # Exact name match (needed for directories like .git)
        if pattern == name:
            return True
            
        # Handle glob patterns with fnmatch
        if "*" in pattern or "?" in pattern:
            if glob.fnmatch.fnmatch(name, pattern):
                return True
            
        # Direct substring match in full path
        elif pattern in path_str:
            return True
    
    return False


def build_directory_tree(
    directory, tree, ignore_patterns=None, max_depth=None, current_depth=0
):
    """Build a Rich Tree representation of the directory structure."""
    if ignore_patterns is None:
        ignore_patterns = []

    if max_depth is not None and current_depth > max_depth:
        return

    try:
        # Get and sort all entries
        entries = sorted(
            [e for e in directory.iterdir() if not should_ignore(e, ignore_patterns)],
            key=lambda x: (not x.is_dir(), x.name.lower()),
        )
    except (PermissionError, FileNotFoundError):
        return

    # Process all entries
    for entry in entries:
        # If it's a directory, create a subtree and process recursively
        if entry.is_dir():
            subtree = tree.add(f"[bold blue]{entry.name}/[/]")
            build_directory_tree(
                entry, subtree, ignore_patterns, max_depth, current_depth + 1
            )
        else:
            # It's a file, just add it to the tree
            tree.add(f"[green]{entry.name}[/]")


def main():
    """Main function."""
    args = parse_args()

    # Set up ignore patterns - ALWAYS use default ignore patterns
    ignore_patterns = DEFAULT_IGNORE.copy()
    
    # Add any additional custom ignore patterns
    if args.ignore:
        ignore_patterns.extend(args.ignore)

    # Determine the directory to process
    if args.path:
        directory = Path(args.path)
    else:
        directory = Path(os.path.dirname(os.path.abspath(__file__)))

    # Create the console and tree
    console = Console(record=True)
    tree = Tree(f"[bold yellow]{directory}[/]")

    # Build the tree
    build_directory_tree(directory, tree, ignore_patterns, args.max_depth)

    # Display the tree
    console.print(tree)

    # Determine output file
    if args.output:
        output_file = args.output
    else:
        dir_name = directory.name
        output_file = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"rich_directory_tree_{dir_name}.md",
        )

    # Save to file
    with open(output_file, "w") as f:
        f.write("# Directory Tree\n\n")
        f.write(f"Generated for: {directory}\n\n")
        if ignore_patterns:
            f.write(f"Excluded patterns: {', '.join(ignore_patterns)}\n\n")
        f.write("```\n")
        f.write(console.export_text())
        f.write("\n```\n")

    print(f"Tree saved to {output_file}")


if __name__ == "__main__":
    main()
