"""
Command Line Interface for PS2.

This module provides a command-line interface for using the PS2 system,
allowing users to access PS2 features directly from the terminal.
"""

import argparse
from pathlib import Path
import sys
import logging
import traceback
import coloredlogs

from typing import Dict

# Import PS2 initialization function
from src.ps2 import initialize_ps2

# Constants
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%H:%M:%S"


# Add parent directory to path to allow importing PS2 modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def parse_args() -> argparse.Namespace:
    """
    Parse command line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="""
            Python Standards Suite (PS2) - Enforce Python coding standards
        """
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
    subparsers.add_parser("conflicts", help="Detect naming conflicts")

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
    subparsers.add_parser("duplications", help="Detect code duplications")

    # Enforce imports command
    subparsers.add_parser("imports", help="Enforce import standards")

    # Monitor performance command
    performance_parser = subparsers.add_parser(
        "performance", help="Monitor code performance"
    )
    performance_parser.add_argument(
        "-d",
        "--duration",
        help="Duration to monitor in seconds (default: 3600)",
        default=3600,
    )

    # Scan security command
    subparsers.add_parser("security", help="Scan for security issues")

    # Generate tasks command
    subparsers.add_parser("tasks", help="Generate task list")

    # Analyze codebase command
    subparsers.add_parser("analyze", help="Analyze codebase")

    # Run all checks command
    subparsers.add_parser("all", help="Run all PS2 checks")

    # Install git hooks command
    subparsers.add_parser("hooks", help="Install PS2 git hooks")

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
            format=LOG_FORMAT,
            datefmt=LOG_DATE_FORMAT,
        )
    else:
        try:
            coloredlogs.install(
                level=log_level,
                fmt=LOG_FORMAT,
                datefmt=LOG_DATE_FORMAT,
            )
        except ImportError:
            logging.basicConfig(
                level=log_level,
                format=LOG_FORMAT,
                datefmt=LOG_DATE_FORMAT,
            )

    return logging.getLogger("ps2")


def _get_plain_status_str(status: str) -> str:
    """
    Get a plain text status string.

    Args:
        status: The status value from the result.

    Returns:
        Formatted status string without color.
    """
    if status == "pass":
        return "PASS"
    elif status == "fail":
        return "FAIL"
    elif status == "fixed":
        return "FIXED"
    elif status == "info":
        return "INFO"
    else:
        return status.upper() if status else "UNKNOWN"


def _get_colored_status_str(status: str) -> str:
    """
    Get a colored status string.

    Args:
        status: The status value from the result.

    Returns:
        Formatted status string with color.
    """
    from colorama import Fore, Style

    if status == "pass":
        return f"{Fore.GREEN}PASS{Style.RESET_ALL}"
    elif status == "fail":
        return f"{Fore.RED}FAIL{Style.RESET_ALL}"
    elif status == "fixed":
        return f"{Fore.YELLOW}FIXED{Style.RESET_ALL}"
    elif status == "info":
        return f"{Fore.BLUE}INFO{Style.RESET_ALL}"
    else:
        return f"{Fore.WHITE}{status.upper() if status else 'UNKNOWN'}{Style.RESET_ALL}"


def _print_dict_value(field: str, value: dict) -> None:
    """
    Print a dictionary value with proper formatting.

    Args:
        field: The field name.
        value: The dictionary value to print.
    """
    print(f"  {field}:")
    for k, v in value.items():
        print(f"    {k}: {v}")


def _print_list_value(field: str, value: list) -> None:
    """
    Print a list value with proper formatting.

    Args:
        field: The field name.
        value: The list value to print.
    """
    print(f"  {field}: {len(value)} items")
    if len(value) <= 5:
        for item in value:
            if isinstance(item, dict):
                for k, v in item.items():
                    print(f"    {k}: {v}")
                print()
            else:
                print(f"    {item}")


def _print_header(result: Dict, status_str: str) -> None:
    """
    Print the header (status and message) of a result.

    Args:
        result: The result dictionary.
        status_str: The formatted status string.
    """
    print(f"Status: {status_str}")
    print(f"Message: {result.get('message', '')}")


def _print_details(result: Dict) -> None:
    """
    Print the details section of a result.

    Args:
        result: The result dictionary.
    """
    if extra_fields := [k for k in result.keys() if k not in ["status", "message"]]:
        print("\nDetails:")
        for field in extra_fields:
            field_value = result[field]
            if isinstance(field_value, dict) and field_value:
                _print_dict_value(field, field_value)
            elif isinstance(field_value, list) and field_value:
                _print_list_value(field, field_value)
            else:
                print(f"  {field}: {field_value}")


def print_result(result: Dict, no_color: bool) -> None:
    """
    Print command result with optional coloring.

    Args:
        result: Result dictionary to print.
        no_color: Whether to disable colored output.
    """
    status = result.get("status")

    if no_color:
        status_str = _get_plain_status_str(status)
        _print_header(result, status_str)
    else:
        try:
            from colorama import init

            init()
            status_str = _get_colored_status_str(status)
            _print_header(result, status_str)
        except ImportError:
            # Fall back to plain output
            print_result(result, True)
            return

    _print_details(result)


def _handle_generate_command(ps2, args):
    """
    Handle the 'generate' command.

    Args:
        ps2: PS2 instance
        args: Command line arguments

    Returns:
        Tuple of (result, exit_code)
    """
    result = ps2.generate_project(args.name, args.type)
    print(f"Generated project at: {result}")
    return None, 0


def _handle_standard_command(ps2, args):
    """
    Handle standard commands that follow a simple pattern.

    Args:
        ps2: PS2 instance
        args: Command line arguments

    Returns:
        Result from the command execution
    """
    if args.command == "check":
        return ps2.check_code_quality(fix=args.fix), None
    elif args.command == "conflicts":
        return ps2.detect_conflicts(fix=args.fix), None
    elif args.command == "dependencies":
        return ps2.manage_dependencies(update=args.update), None
    elif args.command == "duplications":
        return ps2.detect_duplications(fix=args.fix), None
    elif args.command == "imports":
        return ps2.enforce_imports(fix=args.fix), None
    elif args.command == "performance":
        return ps2.monitor_performance(duration=args.duration), None
    elif args.command == "security":
        return ps2.scan_security(fix=args.fix), None
    elif args.command == "tasks":
        return ps2.generate_tasks(), None
    elif args.command == "analyze":
        return ps2.analyze_codebase(), None
    elif args.command == "all":
        return ps2.run_all_checks(fix=args.fix), None

    return None, None


def _handle_hooks_command(ps2):
    """
    Handle the 'hooks' command.

    Args:
        ps2: PS2 instance

    Returns:
        Result dictionary
    """
    success = ps2.install_git_hooks()
    return {
        "status": "pass" if success else "fail",
        "message": (
            "Git hooks installed successfully"
            if success
            else "Failed to install git hooks"
        ),
    }


def _handle_ci_command(ps2, args):
    """
    Handle the 'ci' command.

    Args:
        ps2: PS2 instance
        args: Command line arguments

    Returns:
        Result dictionary
    """
    success = ps2.setup_ci_pipeline(ci_type=args.type)
    return {
        "status": "pass" if success else "fail",
        "message": (
            f"{args.type.capitalize()} CI pipeline configured successfully"
            if success
            else f"Failed to configure {args.type} CI pipeline"
        ),
    }


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
        result = None
        exit_code = None

        # Handle generate command (special case with early return)
        if args.command == "generate":
            _, exit_code = _handle_generate_command(ps2, args)
            return exit_code

        # Handle hooks command
        elif args.command == "hooks":
            result = _handle_hooks_command(ps2)

        # Handle CI command
        elif args.command == "ci":
            result = _handle_ci_command(ps2, args)

        # Handle standard commands
        else:
            result, exit_code = _handle_standard_command(ps2, args)

            # If no command matched
            if result is None:
                print("No command specified. Use --help for available commands.")
                return 0

        # Print result
        print_result(result, args.no_color)

        # Return exit code based on result status
        return 0 if result.get("status") in ["pass", "fixed", "info"] else 1
    except Exception as e:
        logger.error(f"Command failed: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
