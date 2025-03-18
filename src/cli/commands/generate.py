"""
Generate Command Module for PS2 CLI.

This module provides the 'generate' command for the PS2 CLI, allowing users
to generate new Python projects with standardized structure from the command line.  # TODO: Line too long, needs manual fixing
"""
import argparse
import sys
import traceback
from typing import Any

from ps2.cli.helpers.formatting import format_result, output_formats


class GenerateCommand:
    """
    Command class for generating new Python projects.

    This command creates new Python projects with standardized structure
    and boilerplate code, ensuring consistent project setup.
    """

    name = "generate"
    help = "Generate a new Python project"

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        """
        Add command-specific arguments to the parser.

        Args:
            parser: ArgumentParser instance for this command.
        """
        parser.add_argument("name", help="Name of the project to generate")
        parser.add_argument(
            "--type",
            "-t",
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
            help="Type of project to generate (default: standard)",
        )
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
        parser.add_argument("--author", help="Name of the project author")
        parser.add_argument("--email", help="Email of the project author")
        parser.add_argument(
            "--license",
            choices=["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause"],
            default="MIT",
            help="License to use for the project (default: MIT)",
        )
        parser.add_argument(
            "--no-git", action = "store_true", help="Don't initialize Git repository"
        )
        parser.add_argument(
            "--no-venv", action = "store_true", help="Don't create virtual environment"
        )

    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the generate command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            ps2.config.get("project_generator",
                {})
        """
        if args.author:
            ps2.config.get("project_generator", {})["author_name"] = args.author

        if args.email:
            ps2.config.get("project_generator", {})["author_email"] = args.email

        if args.license:
            ps2.config.get("project_generator",
                {})

        if args.no_git:
            ps2.config.get("project_generator", {})["initialize_git"] = False

        if args.no_venv:
            ps2.config.get("project_generator", {})["create_virtual_env"] = False

        # Generate the project
        try:
            result = ps2.generate_project(args.name, args.type)

            # Build a result dictionary
            output_result = {
                "status": "pass",
                "message": f"Project '{args.name}' generated successfully",
                "project_path": str(result),
                "project_type": args.type,
            }

        except Exception as e:
            print(f"Error generating project: {e}", file=sys.stderr)
            if args.verbose:

                traceback.print_exc()
            return 1

        # Format the output
        output = format_result(output_result, args.output)

        # Write the output
        if args.output_file:
            with open(args.output_file, "w") as f:
                f.write(output)
        else:
            print(output)

        return 0  # Project generation always returns success if no exception