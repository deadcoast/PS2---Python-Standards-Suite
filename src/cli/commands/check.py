"""
Check Command Module for PS2 CLI.

This module provides the 'check' command for the PS2 CLI, allowing users
to check code quality and standards from the command line.
"""

import argparse
import sys
import traceback
from typing import Any

from ps2.cli.helpers.formatting import format_result, output_formats


class CheckCommand:
    """
    Command class for checking code quality.

    This command checks the code for compliance with style standards,
    linting rules, type safety, and documentation standards.
    """

    name = "check"
    help = "Check code quality and standards"

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add command-specific arguments to the parser.

        Args:
            parser: ArgumentParser instance for this command.
        """
        parser.add_argument(
            "--output",
            "-o",
            choices=output_formats.keys(),
            default="pretty",
            help="Output format (default: pretty)",
        )
        parser.add_argument(
            "--output-file", "-f", help="Output file path (default: stdout)"
        )
        parser.add_argument(
            "--style", "-s", action="store_true", help="Check code style"
        )
        parser.add_argument("--lint", "-l", action="store_true", help="Check linting")
        parser.add_argument(
            "--type", "-t", action="store_true", help="Check type safety"
        )
        parser.add_argument("--all", "-a", action="store_true", help="Run all checks")
        parser.add_argument(
            "--doc", "-d", action="store_true", help="Check documentation"
        )

    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the check command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # Command-line arguments are processed but currently only 'fix' is used
        # The specific check type (all, style, lint, type, doc) is determined by
        # the PS2 implementation internally

        # Run the check
        try:
            result = ps2.check_code_quality(fix=args.fix)
        except Exception as e:
            print(f"Error checking code quality: {e}", file=sys.stderr)
            if args.verbose:
                traceback.print_exc()
            return 1

        # Format the output
        output = format_result(result, args.output)

        # Write the output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)

        # Return appropriate exit code
        return 0 if result.get("status") in ["pass", "fixed", "info"] else 1
