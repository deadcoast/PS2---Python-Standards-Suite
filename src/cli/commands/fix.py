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
            "--conflicts", "-c", action="store_true", help="Fix naming conflicts"
        )
        parser.add_argument("--all", "-a", action="store_true", help="Fix all issues")
        parser.add_argument(
            "--dry-run",
            "-d",
            action="store_true",
            help="Show what would be fixed without making changes",
        )

    @staticmethod
    def _determine_fixes(args) -> tuple:
        """
        Determine which fixes to apply based on command line arguments.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Tuple of (fix_style, fix_imports, fix_conflicts, actually_fix)
        """
        fix_all = args.all
        fix_style = args.style or fix_all
        fix_imports = args.imports or fix_all
        fix_conflicts = args.conflicts or fix_all

        # If nothing specified, fix everything
        if not (fix_style or fix_imports or fix_conflicts):
            fix_style = fix_imports = fix_conflicts = True

        # Actual fix flag depends on whether this is a dry run
        actually_fix = not args.dry_run

        return fix_style, fix_imports, fix_conflicts, actually_fix

    @staticmethod
    def _run_fixes(
        ps2, fix_style, fix_imports, fix_conflicts, actually_fix, verbose=False
    ) -> list:
        """
        Run the requested fixes.

        Args:
            ps2: Initialized PS2 instance.
            fix_style: Whether to fix style issues.
            fix_imports: Whether to fix import issues.
            fix_conflicts: Whether to fix conflicts.
            actually_fix: Whether to actually apply fixes.
            verbose: Whether to print verbose error information.

        Returns:
            List of (name, result) tuples.

        Raises:
            Exception: If any fix operation fails.
        """
        results = []

        if fix_style:
            result = ps2.check_code_quality(fix=actually_fix)
            results.append(("Code Style", result))

        if fix_imports:
            result = ps2.enforce_imports(fix=actually_fix)
            results.append(("Imports", result))

        if fix_conflicts:
            result = ps2.detect_conflicts(fix=actually_fix)
            results.append(("Conflicts", result))

        return results

    @staticmethod
    def _build_aggregate_result(results, dry_run) -> dict:
        """
        Build an aggregate result from individual fix results.

        Args:
            results: List of (name, result) tuples.
            dry_run: Whether this was a dry run.

        Returns:
            Aggregate result dictionary.
        """
        aggregate_result = {
            "status": "pass",
            "message": "All fixes applied successfully",
            "dry_run": dry_run,
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

        return aggregate_result

    @staticmethod
    def _output_result(aggregate_result, output_format, output_file=None) -> None:
        """
        Format and output the result.

        Args:
            aggregate_result: Aggregate result dictionary.
            output_format: Output format.
            output_file: Optional file to write output to.
        """
        output = format_result(aggregate_result, output_format)

        if output_file:
            with open(output_file, "w") as f:
                f.write(output)
        else:
            print(output)

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
        fix_style, fix_imports, fix_conflicts, actually_fix = (
            FixCommand._determine_fixes(args)
        )

        try:
            # Run the fixes as requested
            results = FixCommand._run_fixes(
                ps2, fix_style, fix_imports, fix_conflicts, actually_fix, args.verbose
            )

            # Build aggregate result
            aggregate_result = FixCommand._build_aggregate_result(results, args.dry_run)

            # Format and output the result
            FixCommand._output_result(aggregate_result, args.output, args.output_file)

            # Return appropriate exit code
            return (
                0 if aggregate_result.get("status") in ["pass", "fixed", "info"] else 1
            )

        except Exception as e:
            print(f"Error fixing code issues: {e}", file=sys.stderr)
            if args.verbose:
                traceback.print_exc()
            return 1
