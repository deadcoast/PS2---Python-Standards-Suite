"""
Fix Command Module for PS2 CLI.

This module provides the 'fix' command for the PS2 CLI, allowing users
to automatically fix code issues from the command line.
"""

import argparse
import sys
import traceback
from typing import Any

from ps2.cli.helpers.formatting import format_result, output_formats


class FixCommand:
    """
    Command class for fixing code issues.

    This command automatically fixes code issues like style violations,
    import problems, and other automatically fixable issues.
    """

    name = "fix"
    help = "Automatically fix code issues"

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
            "--style", "-s", action="store_true", help="Fix code style issues"
        )
        parser.add_argument(
            "--imports", "-i", action="store_true", help="Fix import issues"
        )
        parser.add_argument(
            "--conflicts", "-c", action = "store_true", help="Fix naming conflicts"
        )
        parser.add_argument("--all",
            "-a",
            action="store_true",
            help="Fix all issues")
        parser.add_argument(
            "--dry-run",
            "-d",
            action="store_true",
            help="Show what would be fixed without making changes",
        )

    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the fix command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # Determine what to fix
        fix_all = args.all
        fix_style = args.style or fix_all
        fix_imports = args.imports or fix_all
        fix_conflicts = args.conflicts or fix_all

        # If nothing specified, fix everything
        if not (fix_style or fix_imports or fix_conflicts):
            fix_style = fix_imports = fix_conflicts = True

        # Actual fix flag depends on whether this is a dry run
        actually_fix = not args.dry_run

        results = []

        # Run the fixes as requested
        try:
            if fix_style:
                result = ps2.check_code_quality(fix=actually_fix)
                results.append(("Code Style", result))

            if fix_imports:
                result = ps2.enforce_imports(fix=actually_fix)
                results.append(("Imports", result))

            if fix_conflicts:
                result = ps2.detect_conflicts(fix=actually_fix)
                results.append(("Conflicts", result))

        except Exception as e:
            print(f"Error fixing code issues: {e}", file=sys.stderr)
            if args.verbose:

                traceback.print_exc()
            return 1

        # Build aggregate result
        aggregate_result = {
            "status": "pass",
            "message": "All fixes applied successfully",
            "dry_run": args.dry_run,
            "results": {},
        }

        for name, result in results:
            aggregate_result["results"][name] = result
            # If any check failed, the aggregate result is fail
            if result.get("status") == "fail":
                aggregate_result["status"] = "fail"
                aggregate_result["message"] = (
                    "Some issues could not be fixed automatically"
                )

        # Format the output
        output = format_result(aggregate_result, args.output)

        # Write the output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)

        # Return appropriate exit code
        return 0 if aggregate_result.get("status") in ["pass", "fixed", "info"] else 1