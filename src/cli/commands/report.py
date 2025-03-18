"""
Report Command Module for PS2 CLI.

This module provides the 'report' command for the PS2 CLI, allowing users
to generate comprehensive reports about their Python projects.
"""

import os
import json
from datetime import datetime
import argparse
import sys
import traceback
import re
import markdown

from typing import Any, Dict, List
import weasyprint


class ReportCommand:
    """
    This command creates comprehensive reports about Python projects,
    including code quality, performance, and other metrics.
    """

    name = "report"
    help = "Generate a comprehensive project report"

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
            choices=["html", "markdown", "pdf", "json"],
            default="html",
            help="Output format (default: html)",
        )
        parser.add_argument(
            "--output-file",
            "-f",
            help="Output file path (default: ps2_report.<format>)",
        )
        parser.add_argument(
            "--title", "-t", help="Report title (default: <project name> PS2 Report)"
        )
        parser.add_argument(
            "--quality", "-q", action="store_true", help="Include code quality analysis"
        )
        parser.add_argument(
            "--structure",
            "-s",
            action="store_true",
            help="Include project structure analysis",
        )
        parser.add_argument(
            "--performance",
            "-p",
            action="store_true",
            help="Include performance analysis",
        )
        parser.add_argument(
            "--security", "-e", action="store_true", help="Include security analysis"
        )
        parser.add_argument(
            "--all", "-a", action="store_true", help="Include all analyses (default)"
        )

    @staticmethod
    def _determine_report_inclusions(args):
        """
        Determine what sections to include in the report based on command-line arguments.

        Args:
            args: Parsed command-line arguments.

        Returns:
            Dictionary with boolean flags for each section.
        """
        include_all = args.all or not any(
            [args.quality, args.structure, args.performance, args.security]
        )
        return {
            "quality": args.quality or include_all,
            "structure": args.structure or include_all,
            "performance": args.performance or include_all,
            "security": args.security or include_all,
        }

    @staticmethod
    def _initialize_report_data(project_name, report_title, ps2):
        """
        Initialize the basic report data structure.

        Args:
            project_name: Name of the project.
            report_title: Title for the report.
            ps2: Initialized PS2 instance.

        Returns:
            Dictionary with basic report data.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data = {
            "title": report_title,
            "project": project_name,
            "date": timestamp,
            "sections": [],
        }

        # Add basic project info section
        project_info = {
            "title": "Project Information",
            "data": {
                "name": project_name,
                "path": str(ps2.project_path),
                "report_date": timestamp,
            },
        }
        report_data["sections"].append(project_info)

        return report_data

    @staticmethod
    def _collect_analysis_data(ps2, inclusions, report_data):
        """
        Collect analysis data based on what sections are included.

        Args:
            ps2: Initialized PS2 instance.
            inclusions: Dictionary with boolean flags for each section.
            report_data: Report data dictionary to update.

        Returns:
            Updated report data dictionary.
        """
        # Include code quality analysis if requested
        if inclusions["quality"]:
            print("Running code quality analysis...")
            quality_result = ps2.check_code_quality(fix=False)

            quality_section = {"title": "Code Quality Analysis", "data": quality_result}
            report_data["sections"].append(quality_section)

        # Include structure analysis if requested
        if inclusions["structure"]:
            print("Running structure analysis...")
            structure_result = ps2.analyze_codebase()

            structure_section = {
                "title": "Project Structure Analysis",
                "data": structure_result,
            }
            report_data["sections"].append(structure_section)

        # Include performance analysis if requested
        if inclusions["performance"]:
            print("Running performance analysis...")
            performance_result = ps2.monitor_performance(
                duration=0
            )  # No active monitoring

            performance_section = {
                "title": "Performance Analysis",
                "data": performance_result,
            }
            report_data["sections"].append(performance_section)

        # Include security analysis if requested
        if inclusions["security"]:
            print("Running security analysis...")
            security_result = ps2.scan_security(fix=False)

            security_section = {"title": "Security Analysis", "data": security_result}
            report_data["sections"].append(security_section)

        return report_data

    @staticmethod
    def _generate_output_file(args, report_data):
        """
        Generate the output file based on the specified format.

        Args:
            args: Parsed command-line arguments.
            report_data: Report data dictionary.

        Returns:
            Tuple of (success, error_message).
        """
        print(f"Generating {args.output} report...")

        try:
            if args.output == "json":
                # JSON output is straightforward
                with open(args.output_file, "w") as f:
                    json.dump(report_data, f, indent=2)

            elif args.output == "markdown":
                # Generate Markdown report
                markdown_content = ReportCommand._generate_markdown_report(report_data)
                with open(args.output_file, "w") as f:
                    f.write(markdown_content)

            elif args.output == "html":
                # Generate HTML report
                html_content = ReportCommand._generate_html_report(report_data)
                with open(args.output_file, "w") as f:
                    f.write(html_content)

            elif args.output == "pdf":
                ReportCommand._generate_pdf_report(args, report_data)

            return True, None
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _generate_pdf_report(args, report_data):
        """
        Generate a PDF report, falling back to HTML if necessary.

        Args:
            args: Parsed command-line arguments.
            report_data: Report data dictionary.
        """
        try:
            # First generate HTML
            html_content = ReportCommand._generate_html_report(report_data)

            # Convert to PDF
            pdf = weasyprint.HTML(string=html_content).write_pdf()
            with open(args.output_file, "wb") as f:
                f.write(pdf)
        except ImportError:
            print(
                "Warning: weasyprint module not available. Falling back to HTML format."
            )
            # Fall back to HTML if weasyprint is not available
            args.output_file = args.output_file.replace(".pdf", ".html")
            html_content = ReportCommand._generate_html_report(report_data)
            with open(args.output_file, "w") as f:
                f.write(html_content)

    @staticmethod
    def execute(args: argparse.Namespace, ps2: Any) -> int:
        """
        Execute the report command.

        Args:
            args: Parsed command-line arguments.
            ps2: Initialized PS2 instance.

        Returns:
            Exit code (0 for success, non-zero for failure).
        """
        # Determine project name and report title
        project_name = os.path.basename(os.path.abspath(args.project))
        report_title = args.title or f"{project_name} PS2 Report"

        # Determine output file
        if not args.output_file:
            args.output_file = f"ps2_report.{args.output}"

        try:
            # Determine what to include in the report
            inclusions = ReportCommand._determine_report_inclusions(args)

            # Initialize report data
            report_data = ReportCommand._initialize_report_data(
                project_name, report_title, ps2
            )

            # Collect analysis data
            report_data = ReportCommand._collect_analysis_data(
                ps2, inclusions, report_data
            )

            # Generate the output file
            success, error_message = ReportCommand._generate_output_file(
                args, report_data
            )

            if not success:
                raise ValueError(error_message)

            print(f"Report generated successfully: {args.output_file}")
            return 0

        except Exception as e:
            print(f"Error generating report: {e}", file=sys.stderr)
            if args.verbose:
                traceback.print_exc()
            return 1

    @staticmethod
    def _generate_markdown_report(report_data: Dict) -> str:
        """
        Generate a Markdown report from the report data.

        Args:
            report_data: Dictionary containing report data.

        Returns:
            Markdown report as a string.
        """
        lines = [
            f"# {report_data['title']}",
            "",
            f"*Generated on: {report_data['date']}*",
            "",
        ]

        # Add each section
        for section in report_data["sections"]:
            lines.extend((f"## {section['title']}", ""))
            data = section["data"]

            # Special handling for project info section
            if section["title"] == "Project Information":
                lines.extend(
                    f"- **{key.replace('_', ' ').title()}**: {value}"
                    for key, value in data.items()
                )
                lines.append("")
                continue
            # Handle standard analysis results
            if "status" in data:
                status = data["status"].upper()
                status_icon = "✅" if status in ["PASS", "FIXED", "INFO"] else "❌"
                lines.extend((f"**Status**: {status_icon} {status}", ""))
            if "message" in data:
                lines.extend((f"**Summary**: {data['message']}", ""))
            # Add specific details based on section type
            if section["title"] == "Code Quality Analysis":
                ReportCommand._add_quality_details_markdown(lines, data)

            elif section["title"] == "Project Structure Analysis":
                ReportCommand._add_structure_details_markdown(lines, data)

            elif section["title"] == "Performance Analysis":
                ReportCommand._add_performance_details_markdown(lines, data)

            elif section["title"] == "Security Analysis":
                ReportCommand._add_security_details_markdown(lines, data)

            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _add_style_check_details(lines: List[str], style_data: Dict) -> None:
        """Add style check details to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            style_data: Style check data.
        """
        if "black" in style_data:
            lines.append(f"- **Black**: {style_data['black'].get('message', '')}")

        if "isort" in style_data:
            lines.append(f"- **Isort**: {style_data['isort'].get('message', '')}")

        lines.append("")

    @staticmethod
    def _add_flake8_details(lines: List[str], flake8_data: Dict) -> None:
        """Add Flake8 details to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            flake8_data: Flake8 data.
        """
        lines.append(f"- **Flake8**: {flake8_data.get('message', '')}")

        if "issues" in flake8_data and flake8_data["issues"]:
            lines.append("  - Issues found:")
            lines.extend((f"    - {issue}" for issue in flake8_data["issues"][:5]))
            if len(flake8_data["issues"]) > 5:
                lines.append(f"    - ... and {len(flake8_data['issues']) - 5} more")

    @staticmethod
    def _add_pylint_details(lines: List[str], pylint_data: Dict) -> None:
        """Add Pylint details to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            pylint_data: Pylint data.
        """
        score = pylint_data.get("score", 0)
        lines.append(f"- **Pylint Score**: {score}/10")

        if "issues_by_type" in pylint_data:
            lines.append("  - Issues by type:")
            lines.extend(
                f"    - {issue_type}: {count}"
                for issue_type, count in pylint_data["issues_by_type"].items()
            )

    @staticmethod
    def _add_quality_details_markdown(lines: List[str], data: Dict) -> None:
        """Add code quality details to Markdown report."""

        # Add style checks
        if "style" in data:
            style_data = ReportCommand._append_status("### Style Checks", data, "style")
            ReportCommand._add_style_check_details(lines, style_data)

        # Add linting checks
        if "linting" in data:
            linting_data = ReportCommand._append_status(
                "### Linting Checks", data, "linting"
            )
            if "flake8" in linting_data:
                ReportCommand._add_flake8_details(lines, linting_data["flake8"])

            if "pylint" in linting_data:
                ReportCommand._add_pylint_details(lines, linting_data["pylint"])

            lines.append("")

    @staticmethod
    def _append_status(lines: List[str], data: Dict, key: str) -> Dict:
        lines.append(f"### {key.title()}")
        result = data[key]

        lines.append(f"- **Status**: {result.get('status', 'unknown').upper()}")

        return result

    @staticmethod
    def _add_package_hierarchy(lines: List[str], package_hierarchy: Dict) -> None:
        """Add package hierarchy to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            package_hierarchy: Package hierarchy data.
        """
        lines.append("### Package Hierarchy")

        # Convert to tree-like representation
        for package, modules in package_hierarchy.items():
            if package == "root":
                lines.append("- Root:")
            else:
                lines.append(f"- {package}:")

            lines.extend(f"  - {module}" for module in modules)
        lines.append("")

    @staticmethod
    def _add_entry_points(lines: List[str], entry_points: List[str]) -> None:
        """Add entry points to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            entry_points: List of entry points.
        """
        lines.append("### Entry Points")
        lines.extend(f"- {entry_point}" for entry_point in entry_points)
        lines.append("")

    @staticmethod
    def _add_circular_dependencies(
        lines: List[str], circular_dependencies: List[List[str]]
    ) -> None:
        """Add circular dependencies to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            circular_dependencies: List of circular dependency cycles.
        """
        lines.append("### Circular Dependencies")

        for cycle in circular_dependencies:
            cycle_str = " -> ".join(cycle) + " -> " + cycle[0]
            lines.append(f"- {cycle_str}")

        lines.append("")

    @staticmethod
    def _add_external_dependencies(
        lines: List[str], external_dependencies: Dict
    ) -> None:
        """Add external dependencies to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            external_dependencies: External dependencies data.
        """
        lines.append("### External Dependencies")

        if processed_deps := {module for module, deps in external_dependencies.items()}:
            lines.extend(f"- {dep}" for dep in sorted(processed_deps))
        else:
            lines.append("- No external dependencies found")

        lines.append("")

    @staticmethod
    def _add_structure_details_markdown(lines: List[str], data: Dict) -> None:
        """Add structure details to Markdown report."""

        if "files_analyzed" in data:
            lines.append(f"- **Files Analyzed**: {data['files_analyzed']}")

        if "module_structure" in data:
            module_structure = data["module_structure"]

            if "package_hierarchy" in module_structure:
                ReportCommand._add_package_hierarchy(
                    lines, module_structure["package_hierarchy"]
                )

            if "entry_points" in module_structure:
                ReportCommand._add_entry_points(lines, module_structure["entry_points"])

        if "import_structure" in data:
            import_structure = data["import_structure"]

            if (
                "circular_dependencies" in import_structure
                and import_structure["circular_dependencies"]
            ):
                ReportCommand._add_circular_dependencies(
                    lines, import_structure["circular_dependencies"]
                )

            if "external_dependencies" in import_structure:
                ReportCommand._add_external_dependencies(
                    lines, import_structure["external_dependencies"]
                )

    @staticmethod
    def _add_static_performance_issues(
        lines: List[str], static_issues: List[Dict]
    ) -> None:
        """Add static performance issues to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            static_issues: List of static performance issues.
        """
        lines.append("### Potential Performance Issues")

        for issue in static_issues:
            lines.append(
                f"- **{issue.get('type', 'Unknown')}** ({issue.get('severity', 'unknown')})"
            )
            lines.append(
                f"  - File: {issue.get('file', 'unknown')}, Line: {issue.get('line', 'unknown')}"
            )
            lines.append(f"  - Description: {issue.get('description', '')}")
            if "suggestion" in issue:
                lines.append(f"  - Suggestion: {issue['suggestion']}")
            lines.append("")

    @staticmethod
    def _add_profiling_results(lines: List[str], profiling_results: List[Dict]) -> None:
        """Add profiling results to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            profiling_results: List of profiling metrics.
        """
        lines.append("### Profiling Results")

        for metric in profiling_results:
            lines.extend(
                (
                    f"- **{metric.get('name', 'Unknown')}**: {metric.get('value', 0)} {metric.get('unit', '')}",
                    f"- **Status**: {metric.get('status', 'unknown').upper()}",
                )
            )
            if "reason" in metric:
                lines.append(f"  - {metric['reason']}")

        lines.append("")

    @staticmethod
    def _add_performance_details_markdown(lines: List[str], data: Dict) -> None:
        """Add performance details to Markdown report."""

        if "static_issues" in data and data["static_issues"]:
            ReportCommand._add_static_performance_issues(lines, data["static_issues"])

        if "profiling_results" in data:
            ReportCommand._add_profiling_results(lines, data["profiling_results"])

        if "metrics" in data and data["metrics"]:
            lines.append("### Performance Metrics")

            lines.extend(
                f"- **{metric.get('name', 'Unknown')}**: {metric.get('value', 0)} {metric.get('unit', '')}"
                for metric in data["metrics"][:10]
            )
            if "total_metrics" in data and data["total_metrics"] > 10:
                lines.append(f"- ... and {data['total_metrics'] - 10} more metrics")

            lines.append("")

    @staticmethod
    def _add_severity_counts(lines: List[str], severity_counts: Dict) -> None:
        """Add severity counts to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            severity_counts: Dictionary of severity counts.
        """
        lines.append("### Security Issues by Severity")

        lines.extend(
            f"- **{severity}**: {count}" for severity, count in severity_counts.items()
        )
        lines.append("")

    @staticmethod
    def _add_dependency_vulnerabilities(
        lines: List[str], dep_vulns: List[Dict]
    ) -> None:
        """Add dependency vulnerabilities to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            dep_vulns: List of dependency vulnerabilities.
        """
        lines.append("### Dependency Vulnerabilities")

        for vuln in dep_vulns[:5]:  # Show only first 5
            lines.append(
                f"- **{vuln.get('package', 'Unknown')}** ({vuln.get('severity', 'unknown')})"
            )
            lines.append(f"  - ID: {vuln.get('vulnerability_id', 'unknown')}")
            lines.append(f"  - Description: {vuln.get('description', '')}")
            lines.append(f"  - Installed version: {vuln.get('installed_version', '')}")
            if vuln.get("fix_available", False):
                lines.append(
                    f"  - Fix available: version {vuln.get('fix_version', 'unknown')}"
                )
            lines.append("")

        if len(dep_vulns) > 5:
            lines.extend((f"- ... and {len(dep_vulns) - 5} more vulnerabilities", ""))

    @staticmethod
    def _add_code_vulnerabilities(lines: List[str], code_vulns: List[Dict]) -> None:
        """Add code vulnerabilities to the markdown report.

        Args:
            lines: List of markdown lines to append to.
            code_vulns: List of code vulnerabilities.
        """
        lines.append("### Code Vulnerabilities")

        for vuln in code_vulns[:5]:  # Show only first 5
            lines.append(
                f"- **{vuln.get('issue_name', 'Unknown')}** ({vuln.get('severity', 'unknown')})"
            )
            lines.append(
                f"  - File: {vuln.get('file', 'unknown')}, Line: {vuln.get('line', 'unknown')}"
            )
            lines.append(f"  - Description: {vuln.get('description', '')}")
            if "fix_suggestion" in vuln:
                lines.append(f"  - Suggestion: {vuln['fix_suggestion']}")
            lines.append("")

        if len(code_vulns) > 5:
            lines.extend((f"- ... and {len(code_vulns) - 5} more vulnerabilities", ""))

    @staticmethod
    def _add_security_details_markdown(lines: List[str], data: Dict) -> None:
        """Add security details to Markdown report."""

        if "severity_counts" in data:
            ReportCommand._add_severity_counts(lines, data["severity_counts"])

        if "dependency_vulnerabilities" in data:
            if dep_vulns := data["dependency_vulnerabilities"].get(
                "vulnerabilities", []
            ):
                ReportCommand._add_dependency_vulnerabilities(lines, dep_vulns)

        if "code_vulnerabilities" in data:
            if code_vulns := data["code_vulnerabilities"].get("vulnerabilities", []):
                ReportCommand._add_code_vulnerabilities(lines, code_vulns)

    @staticmethod
    def _generate_html_report(report_data: Dict) -> str:
        """
        Generate an HTML report from the report data.

        Args:
            report_data: Dictionary containing report data.

        Returns:
            HTML report as a string.
        """
        # Convert to markdown first, then use markdown2html
        markdown_content = ReportCommand._generate_markdown_report(report_data)

        try:
            html_body = markdown.markdown(
                markdown_content, extensions=["tables", "fenced_code"]
            )
        except ImportError:
            # Simple conversion without the markdown package
            html_body = ReportCommand._simple_markdown_to_html(markdown_content)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data["title"]}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1, h2, h3, h4 {{
            color: #0066cc;
        }}
        h1 {{
            border-bottom: 2px solid #0066cc;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #ccc;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        code {{
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 4px;
        }}
        table {{
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f2f2f2;
        }}
        .pass {{
            color: green;
        }}
        .fail {{
            color: red;
        }}
        .warning {{
            color: orange;
        }}
        .info {{
            color: blue;
        }}
    </style>
</head>
<body>
    {html_body}
</body>
</html>
"""

    @staticmethod
    def _simple_markdown_to_html(markdown_text: str) -> str:
        """
        Simple conversion from markdown to HTML.

        Args:
            markdown_text: Markdown text to convert.

        Returns:
            HTML text.
        """
        # Convert lists
        html = re.sub(
            r"(<li>.*?</li>(\n|$))+", r"<ul>\g<0></ul>", markdown_text, flags=re.DOTALL
        )

        # Headers
        html = re.sub(r"^# (.*)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)
        html = re.sub(r"^## (.*)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
        html = re.sub(r"^### (.*)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)

        # Bold
        html = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", html)

        # Italic
        html = re.sub(r"\*(.*?)\*", r"<em>\1</em>", html)

        # Lists
        html = re.sub(r"^- (.*)$", r"<li>\1</li>", html, flags=re.MULTILINE)
        html = re.sub(
            r"(<li>.*?</li>(\n|$))+", r"<ul>\g<0></ul>", html, flags=re.DOTALL
        )

        # Code
        html = re.sub(r"`(.*?)`", r"<code>\1</code>", html)

        # Line breaks
        html = html.replace("\n\n", "<br><br>")

        return html
