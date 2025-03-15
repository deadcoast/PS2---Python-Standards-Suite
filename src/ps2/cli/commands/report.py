"""
Report Command Module for PS2 CLI.

This module provides the 'report' command for the PS2 CLI, allowing users
to generate comprehensive reports about their Python projects.
"""

import argparse
import json
import re
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from ps2.cli.helpers.formatting import format_result, output_formats


class ReportCommand:
    """
    Command class for generating project reports.
    
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
            help="Output format (default: html)"
        )
        parser.add_argument(
            "--output-file",
            "-f",
            help="Output file path (default: ps2_report.<format>)"
        )
        parser.add_argument(
            "--title",
            "-t",
            help="Report title (default: <project name> PS2 Report)"
        )
        parser.add_argument(
            "--quality",
            "-q",
            action="store_true",
            help="Include code quality analysis"
        )
        parser.add_argument(
            "--structure",
            "-s",
            action="store_true",
            help="Include project structure analysis"
        )
        parser.add_argument(
            "--performance",
            "-p",
            action="store_true",
            help="Include performance analysis"
        )
        parser.add_argument(
            "--security",
            "-e",
            action="store_true",
            help="Include security analysis"
        )
        parser.add_argument(
            "--all",
            "-a",
            action="store_true",
            help="Include all analyses (default)"
        )
    
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
        # Determine what to include in the report
        include_all = args.all or not any([args.quality, args.structure, args.performance, args.security])
        include_quality = args.quality or include_all
        include_structure = args.structure or include_all
        include_performance = args.performance or include_all
        include_security = args.security or include_all
        
        # Determine project name and report title
        project_name = os.path.basename(os.path.abspath(args.project))
        report_title = args.title or f"{project_name} PS2 Report"
        
        # Determine output file
        if not args.output_file:
            args.output_file = f"ps2_report.{args.output}"
        
        try:
            # Run the appropriate analyses
            report_data = {
                "title": report_title,
                "project": project_name,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "sections": []
            }
            
            # Always include basic project info
            project_info = {
                "title": "Project Information",
                "data": {
                    "name": project_name,
                    "path": str(ps2.project_path),
                    "report_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                }
            }
            report_data["sections"].append(project_info)
            
            # Include code quality analysis if requested
            if include_quality:
                print("Running code quality analysis...")
                quality_result = ps2.check_code_quality(fix=False)
                
                quality_section = {
                    "title": "Code Quality Analysis",
                    "data": quality_result
                }
                report_data["sections"].append(quality_section)
            
            # Include structure analysis if requested
            if include_structure:
                print("Running structure analysis...")
                structure_result = ps2.analyze_codebase()
                
                structure_section = {
                    "title": "Project Structure Analysis",
                    "data": structure_result
                }
                report_data["sections"].append(structure_section)
            
            # Include performance analysis if requested
            if include_performance:
                print("Running performance analysis...")
                performance_result = ps2.monitor_performance(duration=0)  # No active monitoring
                
                performance_section = {
                    "title": "Performance Analysis",
                    "data": performance_result
                }
                report_data["sections"].append(performance_section)
            
            # Include security analysis if requested
            if include_security:
                print("Running security analysis...")
                security_result = ps2.scan_security(fix=False)
                
                security_section = {
                    "title": "Security Analysis",
                    "data": security_result
                }
                report_data["sections"].append(security_section)
            
            # Generate the report
            print(f"Generating {args.output} report...")
            
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
                # Generate PDF report (via HTML)
                try:
                    import weasyprint
                    
                    # First generate HTML
                    html_content = ReportCommand._generate_html_report(report_data)
                    
                    # Convert to PDF
                    pdf = weasyprint.HTML(string=html_content).write_pdf()
                    with open(args.output_file, "wb") as f:
                        f.write(pdf)
                
                except ImportError:
                    print("Warning: weasyprint module not available. Falling back to HTML format.")
                    # Fall back to HTML if weasyprint is not available
                    args.output_file = args.output_file.replace(".pdf", ".html")
                    html_content = ReportCommand._generate_html_report(report_data)
                    with open(args.output_file, "w") as f:
                        f.write(html_content)
            
            print(f"Report generated successfully: {args.output_file}")
            return 0
        
        except Exception as e:
            print(f"Error generating report: {e}", file=sys.stderr)
            if args.verbose:
                import traceback
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
    def _add_quality_details_markdown(self, data: Dict) -> None:
        """Add code quality details to Markdown report."""
        
        # Add style checks
        if "style" in data:
            style_data = self._extracted_from__add_quality_details_markdown_6(
                "### Style Checks", data, "style"
            )
            if "black" in style_data:
                self.append(f"- **Black**: {style_data['black'].get('message', '')}")

            if "isort" in style_data:
                self.append(f"- **isort**: {style_data['isort'].get('message', '')}")

            self.append("")

        # Add linting checks
        if "linting" in data:
            linting_data = self._extracted_from__add_quality_details_markdown_6(
                "### Linting Checks", data, "linting"
            )
            if "flake8" in linting_data:
                flake8_data = linting_data["flake8"]
                self.append(f"- **Flake8**: {flake8_data.get('message', '')}")

                if "issues" in flake8_data and flake8_data["issues"]:
                    self.append("  - Issues found:")
                    self.extend((f"    - {issue}" for issue in flake8_data["issues"][:5]))
                    if len(flake8_data["issues"]) > 5:
                        self.append(f"    - ... and {len(flake8_data['issues']) - 5} more")

            if "pylint" in linting_data:
                pylint_data = linting_data["pylint"]
                score = pylint_data.get("score", 0)
                self.append(f"- **Pylint Score**: {score}/10")

                if "issues_by_type" in pylint_data:
                    self.append("  - Issues by type:")
                    self.extend(
                        (
                            f"    - {issue_type}: {count}"
                            for issue_type, count in pylint_data[
                                "issues_by_type"
                            ].items()
                        )
                    )
            self.append("")

    # TODO Rename this here and in `_add_quality_details_markdown`
    def _extracted_from__add_quality_details_markdown_6(self, arg0, data, arg2):
        self.append(arg0)
        result = data[arg2]

        self.append(f"- **Status**: {result.get('status', 'unknown').upper()}")

        return result
    
    @staticmethod
    def _add_structure_details_markdown(lines: List[str], data: Dict) -> None:
        """Add structure details to Markdown report."""
        
        if "files_analyzed" in data:
            lines.append(f"- **Files Analyzed**: {data['files_analyzed']}")

        if "module_structure" in data:
            module_structure = data["module_structure"]

            if "package_hierarchy" in module_structure:
                lines.append("### Package Hierarchy")
                package_hierarchy = module_structure["package_hierarchy"]

                # Convert to tree-like representation
                for package, modules in package_hierarchy.items():
                    if package == "root":
                        lines.append("- Root:")
                    else:
                        lines.append(f"- {package}:")

                    lines.extend(f"  - {module}" for module in modules)
                lines.append("")

            if "entry_points" in module_structure:
                lines.append("### Entry Points")

                lines.extend(
                    f"- {entry_point}"
                    for entry_point in module_structure["entry_points"]
                )
                lines.append("")

        if "import_structure" in data:
            import_structure = data["import_structure"]

            if "circular_dependencies" in import_structure and import_structure["circular_dependencies"]:
                lines.append("### Circular Dependencies")

                for cycle in import_structure["circular_dependencies"]:
                    cycle_str = " -> ".join(cycle) + " -> " + cycle[0]
                    lines.append(f"- {cycle_str}")

                lines.append("")

            if "external_dependencies" in import_structure:
                lines.append("### External Dependencies")

                processed_deps = set()
                for module, deps in import_structure["external_dependencies"].items():
                    for dep in deps:
                        processed_deps.add(dep)

                if processed_deps:
                    lines.extend(f"- {dep}" for dep in sorted(processed_deps))
                else:
                    lines.append("- No external dependencies found")

                lines.append("")
    
    @staticmethod
    def _add_performance_details_markdown(lines: List[str], data: Dict) -> None:
        """Add performance details to Markdown report."""
        
        if "static_issues" in data and data["static_issues"]:
            lines.append("### Potential Performance Issues")

            for issue in data["static_issues"]:
                lines.append(f"- **{issue.get('type', 'Unknown')}** ({issue.get('severity', 'unknown')})")
                lines.append(f"  - File: {issue.get('file', 'unknown')}, Line: {issue.get('line', 'unknown')}")
                lines.append(f"  - Description: {issue.get('description', '')}")
                if "suggestion" in issue:
                    lines.append(f"  - Suggestion: {issue['suggestion']}")
                lines.append("")

        if "profiling_results" in data:
            lines.append("### Profiling Results")

            for key, result in data["profiling_results"].items():
                status = result.get("status", "unknown")
                lines.append(f"- **{key}**: {status}")
                if "reason" in result:
                    lines.append(f"  - {result['reason']}")

            lines.append("")

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
    def _add_security_details_markdown(lines: List[str], data: Dict) -> None:
        """Add security details to Markdown report."""
        
        if "severity_counts" in data:
            lines.append("### Security Issues by Severity")

            lines.extend(
                f"- **{severity}**: {count}"
                for severity, count in data["severity_counts"].items()
            )
            lines.append("")

        if "dependency_vulnerabilities" in data:
            if dep_vulns := data["dependency_vulnerabilities"].get(
                "vulnerabilities", []
            ):
                lines.append("### Dependency Vulnerabilities")

                for vuln in dep_vulns[:5]:  # Show only first 5
                    lines.append(f"- **{vuln.get('package', 'Unknown')}** ({vuln.get('severity', 'unknown')})")
                    lines.append(f"  - ID: {vuln.get('vulnerability_id', 'unknown')}")
                    lines.append(f"  - Description: {vuln.get('description', '')}")
                    lines.append(f"  - Installed version: {vuln.get('installed_version', '')}")
                    if vuln.get("fix_available", False):
                        lines.append(f"  - Fix available: version {vuln.get('fix_version', 'unknown')}")
                    lines.append("")

                if len(dep_vulns) > 5:
                    lines.extend((f"- ... and {len(dep_vulns) - 5} more vulnerabilities", ""))
        if "code_vulnerabilities" in data:
            if code_vulns := data["code_vulnerabilities"].get(
                "vulnerabilities", []
            ):
                lines.append("### Code Vulnerabilities")

                for vuln in code_vulns[:5]:  # Show only first 5
                    lines.append(f"- **{vuln.get('issue_name', 'Unknown')}** ({vuln.get('severity', 'unknown')})")
                    lines.append(f"  - File: {vuln.get('file', 'unknown')}, Line: {vuln.get('line', 'unknown')}")
                    lines.append(f"  - Description: {vuln.get('description', '')}")
                    if "fix_suggestion" in vuln:
                        lines.append(f"  - Suggestion: {vuln['fix_suggestion']}")
                    lines.append("")

                if len(code_vulns) > 5:
                    lines.extend((f"- ... and {len(code_vulns) - 5} more vulnerabilities", ""))
    
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
            import markdown
            html_body = markdown.markdown(markdown_content, extensions=['tables', 'fenced_code'])
        except ImportError:
            # Simple conversion without the markdown package
            html_body = ReportCommand._simple_markdown_to_html(markdown_content)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{report_data['title']}</title>
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
        # This is a very basic converter for when the markdown package is not available
        html = markdown_text
        
        # Headers
        html = re.sub(r'^# (.*)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.*)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        html = re.sub(r'^### (.*)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
        
        # Italic
        html = re.sub(r'\*(.*?)\*', r'<em>\1</em>', html)
        
        # Lists
        html = re.sub(r'^- (.*)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        html = re.sub(r'(<li>.*?</li>(\n|$))+', r'<ul>\g<0></ul>', html, flags=re.DOTALL)
        
        # Code
        html = re.sub(r'`(.*?)`', r'<code>\1</code>', html)
        
        # Line breaks
        html = html.replace('\n\n', '<br><br>')
        
        return html