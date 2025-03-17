"""
Analyze Command Module for PS2 CLI.

This module provides the 'analyze' command for the PS2 CLI, allowing users
to perform comprehensive codebase analysis from the command line.
"""

from typing import (  # TODO: Remove unused imports; TODO: Remove unused imports  # TODO: Remove unused imports
    Any, Dict, Optional)

from ps2.cli.helpers.formatting import format_result, output_formats


class AnalyzeCommand:
    """
    Command class for running codebase analysis.

    This command analyzes the codebase structure, complexity, and metrics
    to provide insights and recommendations for the Python project.
    """

    name = "analyze"
    help = "Analyze codebase structure and metrics"

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
            "--modules", "-m", action = """
                store_true", help="Analyze module structure
            """
            "--complexity", "-c", action = """
                store_true", help="Analyze code complexity
            """
            "--dependencies", "-d", action = """
                store_true", help="Analyze dependencies
        parser.add_argument("--all",
            "-a",
            action="store_true",
            help="Run all analyses")
            "--complexity", "-c", action="store_true", help="Analyze code complexity"
        )
        parser.add_argument(
            "--dependencies", "-d", action="store_true", help="Analyze dependencies"
        )
        parser.add_argument("--all", "-a", action="store_true", help="Run all analyses")

    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the analyze command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # Get analysis options
        options = {}

        if args.all:
            # Enable all analyses
            options["analyze_modules"] = True
            options["analyze_complexity"] = True
            options["analyze_dependencies"] = True
        else:
            # Only enable specified analyses
            options["analyze_modules"] = args.modules
            options["analyze_complexity"] = args.complexity
            options["analyze_dependencies"] = args.dependencies

            # If no specific analyses were requested, enable all
            if not any(options.values()):
                options = {
                    "analyze_modules": True,
                    "analyze_complexity": True,
                    "analyze_dependencies": True,
                }

        # Run the analysis
        try:
            result = ps2.analyze_codebase()
        except Exception as e:
            print(f"Error analyzing codebase: {e}", file=sys.stderr)
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
        if result.get("status") in ["pass", "fixed", "info"]:
            return 0
        else:
            return 1