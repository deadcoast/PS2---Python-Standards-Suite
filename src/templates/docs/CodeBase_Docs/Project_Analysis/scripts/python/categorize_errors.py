#!/usr/bin/env python3
"""
categorize_errors.py

This script processes linting output and categorizes errors into structured formats
for easier analysis, prioritization, and remediation planning.

Usage: python categorize_errors.py [input_file] [output_file]
"""

import json
import os
import re
import sys
import datetime
import subprocess
from typing import Dict, List, Any, Optional, Union

# Default file paths
DEFAULT_INPUT = "project_analysis.md"
DEFAULT_OUTPUT = "error_categories.json"

# Error category mappings
ERROR_CATEGORIES = {
    # Security issues
    "security/no-eval": {
        "category": "security",
        "subCategory": "security",
        "severity": "critical",
        "description": "Forbidden eval usage",
        "automatedFix": True,
    },
    "security/detect-non-literal-regexp": {
        "category": "security",
        "subCategory": "security",
        "severity": "critical",
        "description": "Non-literal RegExp",
        "automatedFix": False,
    },
    "security/detect-object-injection": {
        "category": "security",
        "subCategory": "security",
        "severity": "critical",
        "description": "Potential object injection",
        "automatedFix": False,
    },
    # Performance issues
    "optimize/no-inefficient-loop": {
        "category": "performance",
        "subCategory": "performance",
        "severity": "critical",
        "description": "Inefficient loop pattern",
        "automatedFix": True,
    },
    "optimize/prefer-object-spread": {
        "category": "performance",
        "subCategory": "performance",
        "severity": "important",
        "description": "Use object spread instead of Object.assign",
        "automatedFix": True,
    },
    # Accessibility issues
    "jsx-a11y/alt-text": {
        "category": "accessibility",
        "subCategory": "accessibility",
        "severity": "critical",
        "description": "Missing alt text for images",
        "automatedFix": False,
    },
    "jsx-a11y/aria-role": {
        "category": "accessibility",
        "subCategory": "accessibility",
        "severity": "important",
        "description": "Invalid ARIA role",
        "automatedFix": True,
    },
    # Code maintainability
    "complexity": {
        "category": "maintainability",
        "subCategory": "maintainability",
        "severity": "important",
        "description": "Function exceeds complexity threshold",
        "automatedFix": False,
    },
    "max-depth": {
        "category": "maintainability",
        "subCategory": "maintainability",
        "severity": "important",
        "description": "Function exceeds maximum depth",
        "automatedFix": False,
    },
    "max-lines": {
        "category": "maintainability",
        "subCategory": "maintainability",
        "severity": "important",
        "description": "File exceeds maximum lines",
        "automatedFix": False,
    },
    # Type safety issues
    "typescript/no-explicit-any": {
        "category": "typeSafety",
        "subCategory": "typeSafety",
        "severity": "important",
        "description": "Use of explicit any type",
        "automatedFix": False,
    },
    "typescript/explicit-function-return-type": {
        "category": "typeSafety",
        "subCategory": "typeSafety",
        "severity": "important",
        "description": "Missing return type",
        "automatedFix": True,
    },
    # Style issues
    "indent": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Inconsistent indentation",
        "automatedFix": True,
    },
    "quotes": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Inconsistent quote style",
        "automatedFix": True,
    },
    "max-len": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Line length exceeds maximum",
        "automatedFix": True,
    },
    # Documentation issues
    "jsdoc/require-jsdoc": {
        "category": "documentation",
        "subCategory": "documentation",
        "severity": "minor",
        "description": "Missing function documentation",
        "automatedFix": True,
    },
    "jsdoc/require-param": {
        "category": "documentation",
        "subCategory": "documentation",
        "severity": "minor",
        "description": "Missing parameter documentation",
        "automatedFix": True,
    },
    # Python-specific issues
    "E501": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Line too long",
        "automatedFix": True,
    },
    "E101": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Indentation contains mixed spaces and tabs",
        "automatedFix": True,
    },
    "E111": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Indentation is not a multiple of four",
        "automatedFix": True,
    },
    "F401": {
        "category": "style",
        "subCategory": "style",
        "severity": "minor",
        "description": "Module imported but unused",
        "automatedFix": True,
    },
    "F841": {
        "category": "maintainability",
        "subCategory": "maintainability",
        "severity": "minor",
        "description": "Local variable is assigned to but never used",
        "automatedFix": True,
    },
    "C901": {
        "category": "maintainability",
        "subCategory": "maintainability",
        "severity": "important",
        "description": "Function is too complex",
        "automatedFix": False,
    },
    "S101": {
        "category": "security",
        "subCategory": "security",
        "severity": "critical",
        "description": "Use of assert detected",
        "automatedFix": False,
    },
    "S102": {
        "category": "security",
        "subCategory": "security",
        "severity": "critical",
        "description": "Use of exec detected",
        "automatedFix": False,
    },
}

# Default category for unknown error codes
DEFAULT_CATEGORY = {
    "category": "unknown",
    "subCategory": "unknown",
    "severity": "minor",
    "description": "Unknown issue",
    "automatedFix": False,
}


def parse_markdown_lint_results(file_path: str) -> Dict[str, Any]:
    """
    Parse a markdown file containing linting results
    Args:
        file_path: Path to the markdown file
    Returns:
        Structured data extracted from markdown
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()

        # Extract summary statistics
        summary_pattern = (
            r"## Summary Statistics\n\n\|.*\|\n\|.*\|([\s\S]*?)(?=\n\n##|$)"
        )
        summary_match = re.search(summary_pattern, content)
        summary = {}

        if summary_match:
            summary_lines = summary_match.group(1).strip().split("\n")
            for line in summary_lines:
                match = re.match(r"\| (.*?) \| (.*?) \|", line)
                if match:
                    key, value = match.groups()
                    summary[key.strip().lower().replace(" ", "_")] = (
                        int(value.strip()) if value.strip().isdigit() else 0
                    )

        # Extract error details
        error_details_pattern = r"## Error Details\n\n([\s\S]*?)(?=\n\n##|$)"
        error_details_match = re.search(error_details_pattern, content)
        file_errors = {}

        if error_details_match:
            file_pattern = r"### (.*?)\n\n```\n([\s\S]*?)```"
            for file_match in re.finditer(file_pattern, error_details_match.group(1)):
                file_path = file_match.group(1).strip()
                errors = []

                error_lines = file_match.group(2).strip().split("\n")
                for line in error_lines:
                    match = re.match(r"Line (\d+): \[(.*?)\] (.*)", line)
                    if match:
                        errors.append(
                            {
                                "line": int(match.group(1)),
                                "code": match.group(2),
                                "message": match.group(3),
                            }
                        )

                file_errors[file_path] = errors

        return {"summary": summary, "fileErrors": file_errors}
    except Exception as e:
        print(f"Error parsing markdown file: {str(e)}")
        sys.exit(1)


def parse_json_lint_results(file_path: str) -> Dict[str, Any]:
    """
    Parse a JSON file containing linting results
    Args:
        file_path: Path to the JSON file
    Returns:
        Structured data extracted from JSON
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception as e:
        print(f"Error parsing JSON file: {str(e)}")
        sys.exit(1)


def categorize_errors(lint_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Categorize errors based on their error codes
    Args:
        lint_results: Parsed linting results
    Returns:
        Categorized errors
    """
    result = {
        "metadata": {
            "analysisDate": datetime.datetime.now().strftime("%Y-%m-%d"),
            "codebaseVersion": get_git_commit(),
            "toolsUsed": ["flake8", "pylint", "eslint", "stylelint"],
        },
        "summary": {
            "totalFilesAnalyzed": 0,
            "filesWithIssues": 0,
            "totalIssues": 0,
            "criticalIssues": 0,
            "importantIssues": 0,
            "minorIssues": 0,
            "automatedFixCandidates": 0,
            "manualReviewRequired": 0,
        },
        "categories": {"critical": {}, "important": {}, "minor": {}},
        "fileDetails": {},
        "fixCandidates": {"automated": [], "manual": []},
    }

    # Initialize category counters
    categories = set()
    error_code_counts = {}

    # Process file errors
    file_errors = lint_results.get("fileErrors", {})
    result["summary"]["totalFilesAnalyzed"] = len(file_errors)
    result["summary"]["filesWithIssues"] = len(file_errors)

    for file_path, errors in file_errors.items():
        result["fileDetails"][file_path] = {"errors": []}

        for error in errors:
            # Get category info
            category_info = ERROR_CATEGORIES.get(error["code"], DEFAULT_CATEGORY)
            category = category_info["category"]
            sub_category = category_info["subCategory"]
            severity = category_info["severity"]
            description = category_info["description"]
            automated_fix = category_info["automatedFix"]

            # Count issue by severity
            result["summary"]["totalIssues"] += 1
            if severity == "critical":
                result["summary"]["criticalIssues"] += 1
            elif severity == "important":
                result["summary"]["importantIssues"] += 1
            elif severity == "minor":
                result["summary"]["minorIssues"] += 1

            # Count by automation potential
            if automated_fix:
                result["summary"]["automatedFixCandidates"] += 1
            else:
                result["summary"]["manualReviewRequired"] += 1

            # Track categories
            categories.add(category)

            # Track error code counts
            error_code_counts[error["code"]] = (
                error_code_counts.get(error["code"], 0) + 1
            )

            # Add to categories structure
            if category not in result["categories"][severity]:
                result["categories"][severity][category] = []

            # Check if error code already exists in the category
            existing_error = next(
                (
                    e
                    for e in result["categories"][severity][category]
                    if e["errorCode"] == error["code"]
                ),
                None,
            )

            if existing_error:
                existing_error["count"] += 1
                if file_path not in existing_error["files"]:
                    existing_error["files"].append(file_path)
            else:
                result["categories"][severity][category].append(
                    {
                        "errorCode": error["code"],
                        "description": description or error.get("message", ""),
                        "count": 1,
                        "files": [file_path],
                        "automatedFix": automated_fix,
                        "fixComplexity": "low" if automated_fix else "high",
                        "fixScriptTemplate": (
                            f"fix_{error['code'].replace('/', '_')}.py"
                            if automated_fix
                            else None
                        ),
                    }
                )

            # Add to file details
            result["fileDetails"][file_path]["errors"].append(
                {
                    "line": error.get("line", 0),
                    "column": error.get("column", 0),
                    "errorCode": error["code"],
                    "message": error.get("message", "") or description,
                    "severity": severity,
                    "context": error.get("context", ""),
                }
            )

    # Generate fix candidates
    for error_code, count in error_code_counts.items():
        category_info = ERROR_CATEGORIES.get(error_code, DEFAULT_CATEGORY)

        if category_info["automatedFix"]:
            result["fixCandidates"]["automated"].append(
                {
                    "pattern": error_code,
                    "occurrences": count,
                    "fixApproach": f"Apply standardized fix for {category_info['description']}",
                    "estimatedImpact": f"Resolve {count} instances of {error_code} across the codebase",
                }
            )
        else:
            result["fixCandidates"]["manual"].append(
                {
                    "pattern": error_code,
                    "occurrences": count,
                    "reason": (
                        "Critical issue requiring careful review"
                        if category_info["severity"] == "critical"
                        else "Complex logic changes needed"
                    ),
                    "recommendedApproach": f"Manually review each instance of {category_info['description']}",
                }
            )

    return result


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


def main():
    """Main function"""
    # Parse command line arguments
    args = sys.argv[1:]
    input_file = args[0] if len(args) > 0 else DEFAULT_INPUT
    output_file = args[1] if len(args) > 1 else DEFAULT_OUTPUT

    print(f"Categorizing errors from {input_file} to {output_file}...")

    # Determine file type and parse accordingly
    ext = os.path.splitext(input_file)[1].lower()
    if ext == ".md":
        lint_results = parse_markdown_lint_results(input_file)
    elif ext == ".json":
        lint_results = parse_json_lint_results(input_file)
    else:
        print(f"Unsupported file type: {ext}")
        sys.exit(1)

    # Categorize errors
    categorized_errors = categorize_errors(lint_results)

    # Write output
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(categorized_errors, file, indent=2)

    print(f"Error categorization complete. Results written to {output_file}")
    print(
        f"Summary: {categorized_errors['summary']['totalIssues']} issues found "
        f"({categorized_errors['summary']['criticalIssues']} critical, "
        f"{categorized_errors['summary']['importantIssues']} important, "
        f"{categorized_errors['summary']['minorIssues']} minor)"
    )
    print(
        f"{categorized_errors['summary']['automatedFixCandidates']} can be fixed automatically, "
        f"{categorized_errors['summary']['manualReviewRequired']} require manual review"
    )


if __name__ == "__main__":
    main()
