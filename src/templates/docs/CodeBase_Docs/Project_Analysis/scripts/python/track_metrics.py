#!/usr/bin/env python3
"""
track_metrics.py

This script tracks code quality metrics over time and generates reports
comparing current metrics with historical data.

Usage: python track_metrics.py [options] [current_analysis_file]

Options:
  --history-file FILE   Path to the metrics history file (default: metrics_history.json)
  --report-file FILE    Path to output report file (default: metrics_report.md)
  --baseline FILE       Compare against a specific baseline file
  --format FORMAT       Output format (md, json) (default: md)
  --chart               Generate charts for visualization
  --verbose             Show detailed output
"""

import json
import os
import re
import sys
import argparse
import datetime
import subprocess
from typing import Dict, List, Any, Optional, Tuple, Union


# Default values
DEFAULT_CURRENT = "error_categories.json"
DEFAULT_HISTORY = "metrics_history.json"
DEFAULT_REPORT = "metrics_report.md"
DEFAULT_FORMAT = "md"


def read_json_file(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Reads and parses JSON files
    Args:
        file_path: Path to the JSON file
    Returns:
        Parsed JSON data or None if file doesn't exist or has errors
    """
    try:
        if not os.path.exists(file_path):
            return None
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        print(f"Error reading {file_path}: {str(e)}")
        return None


def update_history_file(history_file: str, current_metrics: Dict[str, Any]) -> None:
    """
    Updates the metrics history file with current metrics
    Args:
        history_file: Path to the history file
        current_metrics: Current metrics to add
    """
    try:
        history = []

        # Read existing history if available
        if os.path.exists(history_file):
            with open(history_file, "r", encoding="utf-8") as file:
                history = json.load(file)

        # Add current metrics to history
        history.append(
            {
                "date": datetime.datetime.now().strftime("%Y-%m-%d"),
                "commit": get_git_commit(),
                "metrics": current_metrics,
            }
        )

        # Sort by date
        history.sort(key=lambda entry: entry["date"])

        # Write updated history
        with open(history_file, "w", encoding="utf-8") as file:
            json.dump(history, file, indent=2)

        print(f"Updated metrics history in {history_file}")
    except Exception as e:
        print(f"Error updating history file: {str(e)}")


def get_git_commit() -> str:
    """
    Gets the current git commit hash
    Returns:
        Current git commit hash or "unknown"
    """
    try:
        return (
            subprocess.check_output(["git", "rev-parse", "HEAD"])
            .decode("utf-8")
            .strip()
        )
    except Exception:
        return "unknown"


def calculate_change(current: float, previous: float) -> str:
    """
    Calculates the percentage change between two values
    Args:
        current: Current value
        previous: Previous value
    Returns:
        Formatted percentage change
    """
    if previous == 0:
        return "0%" if current == 0 else "∞%"

    change = ((current - previous) / previous) * 100
    return f"{'+' if change > 0 else ''}{change:.1f}%"


def extract_metrics(analysis_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extracts metrics from an analysis file
    Args:
        analysis_data: Analysis data
    Returns:
        Extracted metrics
    """
    if not analysis_data:
        return None

    # Extract summary metrics
    summary = analysis_data.get("summary", {})

    # Calculate additional metrics
    total_issues = summary.get("totalIssues", 0)
    critical_issues = summary.get("criticalIssues", 0)
    important_issues = summary.get("importantIssues", 0)
    minor_issues = summary.get("minorIssues", 0)
    automated_fix_candidates = summary.get("automatedFixCandidates", 0)

    critical_percentage = (
        (critical_issues / total_issues * 100) if total_issues > 0 else 0
    )
    automation_percentage = (
        (automated_fix_candidates / total_issues * 100) if total_issues > 0 else 0
    )

    # Estimate technical debt in hours
    technical_debt = (
        (critical_issues * 4) + (important_issues * 2) + (minor_issues * 0.5)
    )

    # Extract category metrics
    category_breakdown = {}
    categories = analysis_data.get("categories", {})

    for severity, category_group in categories.items():
        for category, issues in category_group.items():
            if category not in category_breakdown:
                category_breakdown[category] = 0

            category_breakdown[category] += sum(
                issue.get("count", 0) for issue in issues
            )

    # Estimate code quality score (0-100)
    max_score = 100
    critical_penalty = critical_issues * 5
    important_penalty = important_issues * 1
    minor_penalty = minor_issues * 0.2

    quality_score = max_score - critical_penalty - important_penalty - minor_penalty
    quality_score = max(0, min(100, quality_score))

    return {
        "timestamp": datetime.datetime.now().isoformat(),
        "totalFiles": summary.get("totalFilesAnalyzed", 0),
        "filesWithIssues": summary.get("filesWithIssues", 0),
        "totalIssues": total_issues,
        "criticalIssues": critical_issues,
        "importantIssues": important_issues,
        "minorIssues": minor_issues,
        "automatedFixCandidates": automated_fix_candidates,
        "manualReviewRequired": summary.get("manualReviewRequired", 0),
        "criticalPercentage": f"{critical_percentage:.1f}",
        "automationPercentage": f"{automation_percentage:.1f}",
        "technicalDebt": f"{technical_debt:.1f}",
        "qualityScore": f"{quality_score:.1f}",
        "categoryBreakdown": category_breakdown,
    }


def generate_comparison(
    current_metrics: Dict[str, Any], baseline_metrics: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Generates a comparison report between current and baseline metrics
    Args:
        current_metrics: Current metrics
        baseline_metrics: Baseline metrics
    Returns:
        Comparison data
    """
    if not current_metrics or not baseline_metrics:
        return None

    # Calculate changes for key metrics
    comparison = {
        "period": {
            "from": baseline_metrics["timestamp"].split("T")[0],
            "to": current_metrics["timestamp"].split("T")[0],
        },
        "metrics": {
            "totalIssues": {
                "before": baseline_metrics["totalIssues"],
                "after": current_metrics["totalIssues"],
                "change": calculate_change(
                    current_metrics["totalIssues"], baseline_metrics["totalIssues"]
                ),
            },
            "criticalIssues": {
                "before": baseline_metrics["criticalIssues"],
                "after": current_metrics["criticalIssues"],
                "change": calculate_change(
                    current_metrics["criticalIssues"],
                    baseline_metrics["criticalIssues"],
                ),
            },
            "importantIssues": {
                "before": baseline_metrics["importantIssues"],
                "after": current_metrics["importantIssues"],
                "change": calculate_change(
                    current_metrics["importantIssues"],
                    baseline_metrics["importantIssues"],
                ),
            },
            "minorIssues": {
                "before": baseline_metrics["minorIssues"],
                "after": current_metrics["minorIssues"],
                "change": calculate_change(
                    current_metrics["minorIssues"], baseline_metrics["minorIssues"]
                ),
            },
            "technicalDebt": {
                "before": baseline_metrics["technicalDebt"],
                "after": current_metrics["technicalDebt"],
                "change": calculate_change(
                    float(current_metrics["technicalDebt"]),
                    float(baseline_metrics["technicalDebt"]),
                ),
            },
            "qualityScore": {
                "before": baseline_metrics["qualityScore"],
                "after": current_metrics["qualityScore"],
                "change": calculate_change(
                    float(current_metrics["qualityScore"]),
                    float(baseline_metrics["qualityScore"]),
                ),
            },
            "automationPercentage": {
                "before": baseline_metrics["automationPercentage"],
                "after": current_metrics["automationPercentage"],
                "change": calculate_change(
                    float(current_metrics["automationPercentage"]),
                    float(baseline_metrics["automationPercentage"]),
                ),
            },
        },
        "categories": {},
    }

    # Compare category breakdowns
    all_categories = set(
        list(current_metrics.get("categoryBreakdown", {}).keys())
        + list(baseline_metrics.get("categoryBreakdown", {}).keys())
    )

    for category in all_categories:
        current_count = current_metrics.get("categoryBreakdown", {}).get(category, 0)
        baseline_count = baseline_metrics.get("categoryBreakdown", {}).get(category, 0)

        comparison["categories"][category] = {
            "before": baseline_count,
            "after": current_count,
            "change": calculate_change(current_count, baseline_count),
        }

    return comparison


def get_highest_category(category_data: Dict[str, Any]) -> str:
    """
    Helper function to get the category with the highest count
    Args:
        category_data: Category data object
    Returns:
        Category with highest count
    """
    if not category_data or len(category_data) == 0:
        return "unknown"

    highest_category = ""
    highest_count = -1

    for category, data in category_data.items():
        count = (
            data
            if isinstance(data, int)
            else (data.get("after", 0) or data.get("before", 0) or 0)
        )

        if count > highest_count:
            highest_count = count
            highest_category = category

    return highest_category


def generate_markdown_report(
    current_metrics: Dict[str, Any],
    comparison: Optional[Dict[str, Any]],
    report_file: str,
) -> None:
    """
    Generates a markdown report
    Args:
        current_metrics: Current metrics
        comparison: Comparison with baseline
        report_file: Output file path
    """
    try:
        report = "# Code Quality Metrics Report\n\n"

        if comparison:
            report += f"**Report Period**: {comparison['period']['from']} to {comparison['period']['to']}  \n"
        else:
            report += (
                f"**Report Date**: {current_metrics['timestamp'].split('T')[0]}  \n"
            )

        report += f"**Codebase Version**: {get_git_commit()}  \n"
        report += f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d')}\n\n"

        # Executive summary
        report += "## Executive Summary\n\n"

        if comparison:
            total_issues_change = float(
                comparison["metrics"]["totalIssues"]["change"]
                .rstrip("%")
                .replace("+", "")
            )
            quality_score_change = float(
                comparison["metrics"]["qualityScore"]["change"]
                .rstrip("%")
                .replace("+", "")
            )

            report += "This report summarizes the code quality improvement metrics for the specified period. "
            report += f"During this time, the total number of issues has changed by {comparison['metrics']['totalIssues']['change']} "
            report += f"(from {comparison['metrics']['totalIssues']['before']} to {comparison['metrics']['totalIssues']['after']}). "
            report += f"The overall code quality score has {'improved' if quality_score_change >= 0 else 'decreased'} "
            report += f"from {comparison['metrics']['qualityScore']['before']} to {comparison['metrics']['qualityScore']['after']}.\n\n"
        else:
            report += (
                "This report provides a snapshot of the current code quality metrics. "
            )
            report += f"Currently, there are {current_metrics['totalIssues']} issues identified, "
            report += (
                f"with a code quality score of {current_metrics['qualityScore']}.\n\n"
            )

        # Key metrics
        report += "## Key Metrics\n\n"

        if comparison:
            report += "| Metric | Before | After | Change | Target |\n"
            report += "|--------|--------|-------|--------|--------|\n"
            report += f"| Total Issues | {comparison['metrics']['totalIssues']['before']} | {comparison['metrics']['totalIssues']['after']} | {comparison['metrics']['totalIssues']['change']} | - |\n"
            report += f"| Critical Issues | {comparison['metrics']['criticalIssues']['before']} | {comparison['metrics']['criticalIssues']['after']} | {comparison['metrics']['criticalIssues']['change']} | 0 |\n"
            report += f"| Important Issues | {comparison['metrics']['importantIssues']['before']} | {comparison['metrics']['importantIssues']['after']} | {comparison['metrics']['importantIssues']['change']} | < 50 |\n"
            report += f"| Minor Issues | {comparison['metrics']['minorIssues']['before']} | {comparison['metrics']['minorIssues']['after']} | {comparison['metrics']['minorIssues']['change']} | < 200 |\n"
            report += f"| Technical Debt (hours) | {comparison['metrics']['technicalDebt']['before']} | {comparison['metrics']['technicalDebt']['after']} | {comparison['metrics']['technicalDebt']['change']} | < 500 |\n"
            report += f"| Quality Score | {comparison['metrics']['qualityScore']['before']} | {comparison['metrics']['qualityScore']['after']} | {comparison['metrics']['qualityScore']['change']} | > 80 |\n"
            report += f"| Automation Potential | {comparison['metrics']['automationPercentage']['before']}% | {comparison['metrics']['automationPercentage']['after']}% | {comparison['metrics']['automationPercentage']['change']} | > 70% |\n"
        else:
            report += "| Metric | Current | Target |\n"
            report += "|--------|---------|--------|\n"
            report += f"| Total Issues | {current_metrics['totalIssues']} | - |\n"
            report += f"| Critical Issues | {current_metrics['criticalIssues']} | 0 |\n"
            report += (
                f"| Important Issues | {current_metrics['importantIssues']} | < 50 |\n"
            )
            report += f"| Minor Issues | {current_metrics['minorIssues']} | < 200 |\n"
            report += f"| Technical Debt (hours) | {current_metrics['technicalDebt']} | < 500 |\n"
            report += f"| Quality Score | {current_metrics['qualityScore']} | > 80 |\n"
            report += f"| Automation Potential | {current_metrics['automationPercentage']}% | > 70% |\n"

        report += "\n"

        # Issue distribution by category
        report += "## Issue Distribution by Category\n\n"

        if comparison:
            report += "### Before Remediation\n\n"

            report += "| Category | Count | Percentage |\n"
            report += "|----------|-------|------------|\n"

            baseline_total_issues = comparison["metrics"]["totalIssues"]["before"]
            for category, data in comparison["categories"].items():
                percentage = (
                    "0.0"
                    if baseline_total_issues == 0
                    else f"{(data['before'] / baseline_total_issues * 100):.1f}"
                )
                report += f"| {category} | {data['before']} | {percentage}% |\n"

            report += "\n### After Remediation\n\n"

            report += "| Category | Count | Percentage | Change |\n"
            report += "|----------|-------|------------|--------|\n"

            current_total_issues = comparison["metrics"]["totalIssues"]["after"]
            for category, data in comparison["categories"].items():
                percentage = (
                    "0.0"
                    if current_total_issues == 0
                    else f"{(data['after'] / current_total_issues * 100):.1f}"
                )
                report += f"| {category} | {data['after']} | {percentage}% | {data['change']} |\n"
        else:
            report += "| Category | Count | Percentage |\n"
            report += "|----------|-------|------------|\n"

            total_issues = current_metrics["totalIssues"]
            for category, count in current_metrics.get("categoryBreakdown", {}).items():
                percentage = (
                    "0.0"
                    if total_issues == 0
                    else f"{(count / total_issues * 100):.1f}"
                )
                report += f"| {category} | {count} | {percentage}% |\n"

        report += "\n"

        # Next steps
        report += "## Next Steps\n\n"

        if comparison:
            total_issues_change = float(
                comparison["metrics"]["totalIssues"]["change"]
                .rstrip("%")
                .replace("+", "")
            )

            if total_issues_change < 0:
                report += f"1. Continue with the current remediation strategy which has successfully reduced issues by {abs(total_issues_change):.1f}%\n"
                report += f"2. Focus next on {get_highest_category(comparison['categories'])} issues which still have the highest count\n"
                report += (
                    "3. Update standards documentation based on common fixes applied\n"
                )
                report += "4. Implement preventive measures for the most frequently fixed issues\n"
            else:
                report += f"1. Review current remediation strategy as issues have increased by {total_issues_change:.1f}%\n"
                report += f"2. Prioritize fixing {get_highest_category(comparison['categories'])} issues which have the highest count\n"
                report += "3. Consider implementing stricter code review guidelines\n"
                report += "4. Explore additional automated checks that can prevent these issues\n"
        else:
            report += f"1. Prioritize addressing the {current_metrics['criticalIssues']} critical issues first\n"
            report += f"2. Focus on {get_highest_category(current_metrics.get('categoryBreakdown', {}))} issues which have the highest count\n"
            report += f"3. Implement automated fixes for the {current_metrics['automatedFixCandidates']} automatable issues\n"
            report += "4. Schedule regular follow-up analysis to track progress\n"

        report += "\n"

        # Appendix with methodology
        report += "## Appendix: Methodology\n\n"
        report += "This report was generated using the following methodology:\n\n"
        report += "1. **Data Collection**: Linting and static analysis tools were used to identify code issues\n"
        report += "2. **Metrics Calculation**: Issues were categorized by severity and type, then quantified\n"
        report += "3. **Technical Debt Estimation**: Critical issues (4 hours), Important issues (2 hours), Minor issues (0.5 hours)\n"
        report += "4. **Quality Score Calculation**: Base score of 100 with deductions for each issue based on severity\n"

        # Write the report to file
        with open(report_file, "w", encoding="utf-8") as file:
            file.write(report)
        print(f"Generated markdown report: {report_file}")
    except Exception as e:
        print(f"Error generating markdown report: {str(e)}")


def generate_json_report(
    current_metrics: Dict[str, Any],
    comparison: Optional[Dict[str, Any]],
    report_file: str,
) -> None:
    """
    Generates a JSON report
    Args:
        current_metrics: Current metrics
        comparison: Comparison with baseline
        report_file: Output file path
    """
    try:
        report = {
            "generatedAt": datetime.datetime.now().isoformat(),
            "codebaseVersion": get_git_commit(),
            "currentMetrics": current_metrics,
            "comparison": comparison,
        }

        with open(report_file, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)
        print(f"Generated JSON report: {report_file}")
    except Exception as e:
        print(f"Error generating JSON report: {str(e)}")


def main() -> None:
    """Main function"""
    parser = argparse.ArgumentParser(description="Track code quality metrics over time")
    parser.add_argument(
        "--history-file",
        default=DEFAULT_HISTORY,
        help=f"Path to the metrics history file (default: {DEFAULT_HISTORY})",
    )
    parser.add_argument(
        "--report-file",
        default=DEFAULT_REPORT,
        help=f"Path to output report file (default: {DEFAULT_REPORT})",
    )
    parser.add_argument("--baseline", help="Compare against a specific baseline file")
    parser.add_argument(
        "--format",
        choices=["md", "json"],
        default=DEFAULT_FORMAT,
        help=f"Output format (default: {DEFAULT_FORMAT})",
    )
    parser.add_argument(
        "--chart", action="store_true", help="Generate charts for visualization"
    )
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    parser.add_argument(
        "current_file",
        nargs="?",
        default=DEFAULT_CURRENT,
        help=f"Current analysis file (default: {DEFAULT_CURRENT})",
    )

    args = parser.parse_args()

    print("Code Quality Metrics Tracker")
    print(f"Analyzing current metrics from: {args.current_file}")

    # Read current analysis data
    current_analysis = read_json_file(args.current_file)

    if not current_analysis:
        print(f"Could not read current analysis file: {args.current_file}")
        sys.exit(1)

    # Extract metrics from current analysis
    current_metrics = extract_metrics(current_analysis)

    if not current_metrics:
        print("Failed to extract metrics from current analysis")
        sys.exit(1)

    # Update metrics history
    update_history_file(args.history_file, current_metrics)

    # Determine baseline for comparison
    baseline_analysis = None
    baseline_metrics = None
    comparison = None

    if args.baseline:
        # Use specified baseline file
        print(f"Using specified baseline file: {args.baseline}")
        baseline_analysis = read_json_file(args.baseline)

        if baseline_analysis:
            baseline_metrics = extract_metrics(baseline_analysis)
            comparison = generate_comparison(current_metrics, baseline_metrics)
        else:
            print(f"Could not read baseline file: {args.baseline}")
    else:
        # Try to use history file for comparison
        history = read_json_file(args.history_file)

        if history and isinstance(history, list) and len(history) > 1:
            # Use the second most recent entry as baseline
            baseline_entry = history[-2]
            baseline_metrics = baseline_entry["metrics"]
            comparison = generate_comparison(current_metrics, baseline_metrics)

            print(f"Using historical baseline from: {baseline_entry['date']}")
        else:
            print("No historical baseline available for comparison")

    # Generate report
    if args.format == "json":
        generate_json_report(current_metrics, comparison, args.report_file)
    else:
        generate_markdown_report(current_metrics, comparison, args.report_file)

    print("Metrics tracking completed successfully")


if __name__ == "__main__":
    main()
