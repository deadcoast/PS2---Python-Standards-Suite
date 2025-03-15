"""
Command Line Interface for PS2.

This module provides a command-line interface for using the PS2 system,
allowing users to access PS2 features directly from the terminal.
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

# Add parent directory to path to allow importing PS2 modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from ps2 import initialize_ps2
from ps2.config import default_settings


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Python Standards Suite (PS2) - Enforce Python coding standards"
    )

    # Global options
    parser.add_argument(
        "-p",
        "--project",
        help="Path to the Python project (default: current directory)",
        default=".",
    )
    parser.add_argument(
        "-c", "--config", help="Path to configuration file", default=None
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose output", action="store_true"
    )
    parser.add_argument(
        "-f",
        "--fix",
        help="Automatically fix issues where possible",
        action="store_true",
    )
    parser.add_argument(
        "--no-color", help="Disable colored output", action="store_true"
    )

    # Commands
    subparsers = parser.add_subparsers(dest="command", help="PS2 command to run")

    # Generate project command
    generate_parser = subparsers.add_parser(
        "generate", help="Generate a new Python project"
    )
    generate_parser.add_argument("name", help="Name of the project")
    generate_parser.add_argument(
        "-t",
        "--type",
        help="Type of project to generate (default: standard)",
        choices=[
            "standard",
            "flask",
            "django",
            "fastapi",
            "cli",
            "package",
            "data_science",
        ],
        default="standard",
    )

    # Check code quality command
    check_parser = subparsers.add_parser("check", help="Check code quality")
    check_parser.add_argument(
        "-t",
        "--type",
        help="Type of check to perform (default: all)",
        choices=["all", "style", "lint", "type", "doc", "complexity"],
        default="all",
    )

    # Detect conflicts command
    conflict_parser = subparsers.add_parser("conflicts", help="Detect naming conflicts")

    # Manage dependencies command
    dependency_parser = subparsers.add_parser(
        "dependencies", help="Manage dependencies"
    )
    dependency_parser.add_argument(
        "-u",
        "--update",
        help="Update dependencies to latest compatible versions",
        action="store_true",
    )

    # Detect duplications command
    duplication_parser = subparsers.add_parser(
        "duplications", help="Detect code duplications"
    )

    # Enforce imports command
    import_parser = subparsers.add_parser("imports", help="Enforce import standards")

    # Monitor performance command
    performance_parser = subparsers.add_parser(
        "performance", help="Monitor code performance"
    )
    performance_parser.add_argument(
        "-d",
        "--duration",
        help="Duration to monitor in seconds (default: 3600)",
        type=int,
        default=3600,
    )

    # Scan security command
    security_parser = subparsers.add_parser("security", help="Scan for security issues")

    # Generate tasks command
    task_parser = subparsers.add_parser("tasks", help="Generate task list")

    # Analyze codebase command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze codebase")

    # Run all checks command
    all_parser = subparsers.add_parser("all", help="Run all PS2 checks")

    # Install git hooks command
    hooks_parser = subparsers.add_parser("hooks", help="Install PS2 git hooks")

    # Setup CI pipeline command
    ci_parser = subparsers.add_parser("ci", help="Set up CI pipeline")
    ci_parser.add_argument(
        "-t",
        "--type",
        help="Type of CI system to configure (default: github)",
        choices=["github", "gitlab", "jenkins"],
        default="github",
    )

    return parser.parse_args()


def setup_logging(verbose: bool, no_color: bool) -> logging.Logger:
    """
    Set up logging configuration.

    Args:
        verbose: Whether to enable verbose output.
        no_color: Whether to disable colored output.

    Returns:
        Configured logger.
    """
    log_level = logging.DEBUG if verbose else logging.INFO

    # Configure logging
    if no_color:
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        try:
            import coloredlogs

            coloredlogs.install(
                level=log_level,
                fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%H:%M:%S",
            )
        except ImportError:
            logging.basicConfig(
                level=log_level,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                datefmt="%H:%M:%S",
            )

    return logging.getLogger("ps2")


def print_result(result: Dict, no_color: bool) -> None:
    """
    Print command result with optional coloring.

    Args:
        result: Result dictionary to print.
        no_color: Whether to disable colored output.
    """
    if no_color:
        if result.get("status") == "pass":
            status_str = "PASS"
        elif result.get("status") == "fail":
            status_str = "FAIL"
        elif result.get("status") == "fixed":
            status_str = "FIXED"
        elif result.get("status") == "info":
            status_str = "INFO"
        else:
            status_str = result.get("status", "UNKNOWN").upper()

        print(f"Status: {status_str}")
        print(f"Message: {result.get('message', '')}")
    else:
        try:
            from colorama import Fore, Style, init

            init()

            if result.get("status") == "pass":
                status_str = Fore.GREEN + "PASS" + Style.RESET_ALL
            elif result.get("status") == "fail":
                status_str = Fore.RED + "FAIL" + Style.RESET_ALL
            elif result.get("status") == "fixed":
                status_str = Fore.YELLOW + "FIXED" + Style.RESET_ALL
            elif result.get("status") == "info":
                status_str = Fore.BLUE + "INFO" + Style.RESET_ALL
            else:
                status_str = (
                    Fore.WHITE
                    + result.get("status", "UNKNOWN").upper()
                    + Style.RESET_ALL
                )

            print(f"Status: {status_str}")
            print(f"Message: {result.get('message', '')}")
        except ImportError:
            # Fall back to plain output
            print_result(result, True)

    # Print additional result fields if present
    extra_fields = [k for k in result.keys() if k not in ["status", "message"]]
    if extra_fields:
        print("\nDetails:")
        for field in extra_fields:
            field_value = result[field]
            if isinstance(field_value, dict) and field_value:
                print(f"  {field}:")
                for k, v in field_value.items():
                    print(f"    {k}: {v}")
            elif isinstance(field_value, list) and field_value:
                print(f"  {field}: {len(field_value)} items")
                if len(field_value) <= 5:
                    for item in field_value:
                        if isinstance(item, dict):
                            for k, v in item.items():
                                print(f"    {k}: {v}")
                            print()
                        else:
                            print(f"    {item}")
            else:
                print(f"  {field}: {field_value}")


def main() -> int:
    """
    Main entry point for the PS2 CLI.

    Returns:
        Exit code (0 for success, non-zero for failure).
    """
    # Parse command line arguments
    args = parse_args()

    # Set up logging
    logger = setup_logging(args.verbose, args.no_color)

    # Convert project path to absolute path
    project_path = Path(args.project).absolute()

    # Load configuration
    config_path = args.config

    # Initialize PS2
    try:
        ps2 = initialize_ps2(project_path, config_path)
        logger.info(f"Initialized PS2 for project: {project_path}")
    except Exception as e:
        logger.error(f"Failed to initialize PS2: {e}")
        return 1

    # Execute command
    try:
        if args.command == "generate":
            result = ps2.generate_project(args.name, args.type)
            print(f"Generated project at: {result}")
            return 0

        elif args.command == "check":
            result = ps2.check_code_quality(fix=args.fix)

        elif args.command == "conflicts":
            result = ps2.detect_conflicts(fix=args.fix)

        elif args.command == "dependencies":
            result = ps2.manage_dependencies(update=args.update)

        elif args.command == "duplications":
            result = ps2.detect_duplications(fix=args.fix)

        elif args.command == "imports":
            result = ps2.enforce_imports(fix=args.fix)

        elif args.command == "performance":
            result = ps2.monitor_performance(duration=args.duration)

        elif args.command == "security":
            result = ps2.scan_security(fix=args.fix)

        elif args.command == "tasks":
            result = ps2.generate_tasks()

        elif args.command == "analyze":
            result = ps2.analyze_codebase()

        elif args.command == "all":
            result = ps2.run_all_checks(fix=args.fix)

        elif args.command == "hooks":
            success = ps2.install_git_hooks()
            result = {
                "status": "pass" if success else "fail",
                "message": (
                    "Git hooks installed successfully"
                    if success
                    else "Failed to install git hooks"
                ),
            }

        elif args.command == "ci":
            success = ps2.setup_ci_pipeline(ci_type=args.type)
            result = {
                "status": "pass" if success else "fail",
                "message": (
                    f"{args.type.capitalize()} CI pipeline configured successfully"
                    if success
                    else f"Failed to configure {args.type} CI pipeline"
                ),
            }

        else:
            # No command specified, show help
            print("No command specified. Use --help for available commands.")
            return 0

        # Print result
        print_result(result, args.no_color)

        # Return exit code based on result status
        if result.get("status") in ["pass", "fixed", "info"]:
            return 0
        else:
            return 1

    except Exception as e:
        logger.error(f"Command failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
