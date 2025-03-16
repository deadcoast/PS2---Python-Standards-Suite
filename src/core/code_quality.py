"""
Code Quality Enforcer Module for PS2.

This module enforces code quality standards in Python projects,
integrating with popular linting and formatting tools to maintain
consistent code style and quality.
"""

import logging
from pathlib import Path
import subprocess
import toml
import json
import contextlib

from typing import Dict, List, Optional, Union


# Configuration file constants
BLACK_CONFIG_FILENAME = "black.toml"
ISORT_CONFIG_FILENAME = "isort.cfg"


class CodeQualityEnforcer:
    """
    Enforcer for Python code quality standards.

    This class integrates with popular code quality tools like Black, isort,
    Flake8, Pylint, and MyPy to enforce consistent style and quality in
    Python projects.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the code quality enforcer.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the enforcer.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.code_quality")
        self.enabled = False

        # Tool availability cache
        self._available_tools = {}

        # Config paths
        self.config_dir = (
            Path(__file__).parent.parent.parent / "config" / "linter_configs"
        )

    def enable(self) -> None:
        """Enable the code quality enforcer."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the code quality enforcer."""
        self.enabled = False

    def check(self, fix: bool = False) -> Dict:
        """
        Check code quality against standards.

        Args:
            fix: Whether to automatically fix issues where possible.

        Returns:
            Dictionary with check results.
        """
        if not self.enabled:
            self.logger.warning(
                "Code quality enforcer is disabled. Enabling for this run."
            )
            self.enable()

        self.logger.info(f"Checking code quality (fix: {fix})")

        result = {
            "style": self._check_style(fix),
            "linting": self._check_linting(fix),
            "typing": self._check_typing(),
            "docstrings": self._check_docstrings(fix),
            "complexity": self._check_complexity(),
            "overall_status": "pass",
        }

        # Determine overall status
        if any(
            check.get("status") == "fail"
            for check in result.values()
            if isinstance(check, dict)
        ):
            result["overall_status"] = "fail"

        return result

    def _check_style(self, fix: bool = False) -> Dict:
        """
        Check and fix code style using Black and isort.

        Args:
            fix: Whether to automatically fix style issues.

        Returns:
            Dictionary with style check results.
        """
        self.logger.info("Checking code style")

        result = {
            "black": self._run_black(fix),
            "isort": self._run_isort(fix),
            "status": "pass",
        }

        # Determine style status
        if result["black"]["status"] == "fail" or result["isort"]["status"] == "fail":
            result["status"] = "fail"

        return result

    def _check_linting(self, fix: bool = False) -> Dict:
        """
        Check code with linters (Flake8, Pylint).

        Args:
            fix: Whether to automatically fix linting issues where possible.

        Returns:
            Dictionary with linting check results.
        """
        self.logger.info("Checking code linting")

        result = {
            "flake8": self._run_flake8(),
            "pylint": self._run_pylint(),
            "status": "pass",
        }

        # Determine linting status
        if result["flake8"]["status"] == "fail" or result["pylint"]["status"] == "fail":
            result["status"] = "fail"

        return result

    def _check_typing(self) -> Dict:
        """
        Check static typing with MyPy.

        Returns:
            Dictionary with typing check results.
        """
        self.logger.info("Checking static typing")

        result = {"mypy": self._run_mypy(), "status": "pass"}

        # Determine typing status
        if result["mypy"]["status"] == "fail":
            result["status"] = "fail"

        return result

    def _check_docstrings(self, fix: bool = False) -> Dict:
        """
        Check docstring quality and coverage.

        Args:
            fix: Whether to automatically fix docstring issues where possible.

        Returns:
            Dictionary with docstring check results.
        """
        self.logger.info("Checking docstrings")

        result = {
            "pydocstyle": self._run_pydocstyle(),
            "coverage": self._check_docstring_coverage(),
            "status": "pass",
        }

        # Determine docstring status
        if (
            result["pydocstyle"]["status"] == "fail"
            or result["coverage"]["status"] == "fail"
        ):
            result["status"] = "fail"

        return result

    def _check_complexity(self) -> Dict:
        """
        Check code complexity metrics.

        Returns:
            Dictionary with complexity check results.
        """
        self.logger.info("Checking code complexity")

        result = {"radon": self._run_radon(), "status": "pass"}

        # Determine complexity status
        if result["radon"]["status"] == "fail":
            result["status"] = "fail"

        return result

    def _run_black(self, fix: bool = False) -> Dict:
        """
        Run Black code formatter.

        Args:
            fix: Whether to automatically format code.

        Returns:
            Dictionary with Black results.
        """
        if not self._is_tool_available("black"):
            return {"status": "skip", "message": "Black not available"}

        config_path = self._ensure_config_file(BLACK_CONFIG_FILENAME)

        # Build command
        cmd = ["black"]
        if config_path:
            cmd.extend(["--config", str(config_path)])

        result = self._extracted_from__run_isort_21(fix, cmd)
        # Parse result
        if result["returncode"] == 0:
            return {"status": "pass", "message": "No style issues found"}
        elif fix and "reformatted" in result["stdout"]:
            return {"status": "fixed", "message": result["stdout"]}
        else:
            return {"status": "fail", "message": result["stdout"] or result["stderr"]}

    def _run_isort(self, fix: bool = False) -> Dict:
        """
        Run isort import sorter.

        Args:
            fix: Whether to automatically sort imports.

        Returns:
            Dictionary with isort results.
        """
        if not self._is_tool_available("isort"):
            return {"status": "skip", "message": "isort not available"}

        config_path = self._ensure_config_file(ISORT_CONFIG_FILENAME)

        # Build command
        cmd = ["isort"]
        if config_path:
            cmd.extend(["--settings-path", str(config_path)])

        result = self._extracted_from__run_isort_21(fix, cmd)
        # Parse result
        if result["returncode"] == 0:
            return {"status": "pass", "message": "Imports are sorted correctly"}
        elif fix:
            return {"status": "fixed", "message": "Imports have been sorted"}
        else:
            return {"status": "fail", "message": result["stderr"] or result["stdout"]}

    def _extracted_from__run_isort_21(self, fix, cmd):
        if not fix:
            cmd.append("--check")
        cmd.append(str(self.project_path))
        return self._run_command(cmd)

    def _run_flake8(self) -> Dict:
        """
        Run Flake8 linter.

        Returns:
            Dictionary with Flake8 results.
        """
        if not self._is_tool_available("flake8"):
            return {"status": "skip", "message": "Flake8 not available"}
        config_path = self._ensure_config_file("flake8.ini")
        cmd = ["flake8"]
        if config_path:
            cmd.extend(["--config", str(config_path)])
        cmd.append(str(self.project_path))
        result = self._run_command(cmd)
        if result["returncode"] == 0:
            return {"status": "pass", "message": "No Flake8 issues found"}
        issues = [line for line in result["stdout"].splitlines() if line.strip()]
        return {
            "status": "fail",
            "message": f"Found {len(issues)} Flake8 issues",
            "issues": issues[:100],
            "total_issues": len(issues),
        }

    # Helper method to process pylint results
    def _extracted_from__run_pylint_(self, result):
        if not result["stdout"]:
            return {
                "status": "pass",
                "message": "No Pylint issues found",
                "score": 10.0,
            }
        issues = json.loads(result["stdout"])
        score = self._extract_pylint_score(result["stderr"])

        # Group issues by type
        issues_by_type = {}
        for issue in issues:
            issue_type = issue.get("type", "undefined")
            if issue_type not in issues_by_type:
                issues_by_type[issue_type] = []
            issues_by_type[issue_type].append(issue)

        return (
            {
                "status": "pass",
                "message": f"Pylint score: {score}/10",
                "score": score,
                "issues_by_type": {k: len(v) for k, v in issues_by_type.items()},
            }
            if score >= 9.0
            else {
                "status": "fail",
                "message": f"Pylint score: {score}/10",
                "score": score,
                "issues_by_type": {k: len(v) for k, v in issues_by_type.items()},
                "sample_issues": issues[:20],  # Limit to 20 issues for readability
            }
        )

    def _run_pylint(self) -> Dict:
        """
        Run Pylint linter.

        Args:
            fix: Whether to attempt auto-fixing (limited support in Pylint).

        Returns:
            Dictionary with Pylint results.
        """
        if not self._is_tool_available("pylint"):
            return {"status": "skip", "message": "Pylint not available"}
        config_path = self._ensure_config_file("pylint.rc")
        cmd = ["pylint"]
        if config_path:
            cmd.extend(["--rcfile", str(config_path)])
        cmd.extend(("--output-format=json", str(self.project_path)))
        result = self._run_command(cmd)
        try:
            return self._extracted_from__run_pylint_(result)
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Failed to parse Pylint output",
                "stdout": result["stdout"],
                "stderr": result["stderr"],
            }

    def _run_mypy(self) -> Dict:
        """
        Run MyPy static type checker.

        Returns:
            Dictionary with MyPy results.
        """
        if not self._is_tool_available("mypy"):
            return {"status": "skip", "message": "MyPy not available"}
        config_path = self._ensure_config_file("mypy.ini")
        cmd = ["mypy"]
        if config_path:
            cmd.extend(["--config-file", str(config_path)])
        cmd.append(str(self.project_path))
        result = self._run_command(cmd)
        if result["returncode"] == 0:
            return {"status": "pass", "message": "No type issues found"}
        issues = [
            line
            for line in result["stdout"].splitlines()
            if line.strip() and ": error:" in line
        ]
        return {
            "status": "fail",
            "message": f"Found {len(issues)} type issues",
            "issues": issues[:100],
        }

    # This method runs the pydocstyle tool to check docstring quality
    def _run_pydocstyle(self) -> Dict:
        """
        Run pydocstyle docstring checker.

        Returns:
            Dictionary with pydocstyle results.
        """
        if not self._is_tool_available("pydocstyle"):
            return {"status": "skip", "message": "pydocstyle not available"}

        config_path = self._ensure_config_file("pydocstyle.ini")

        # Build command
        cmd = ["pydocstyle"]
        if config_path:
            cmd.extend(["--config", str(config_path)])

        cmd.append(str(self.project_path))

        # Run pydocstyle
        result = self._run_command(cmd)

        if result["returncode"] == 0:
            return {"status": "pass", "message": "No docstring issues found"}
        issues = [
            line
            for line in result["stdout"].splitlines()
            if (line.strip() and line[0].isalpha())
        ]
        return {
            "status": "fail",
            "message": f"Found {len(issues)} docstring issues",
            "issues": issues[:100],  # Limit to 100 issues for readability
        }

    def _check_docstring_coverage(self) -> Dict:
        """
        Check docstring coverage in the codebase.

        Returns:
            Dictionary with docstring coverage results.
        """
        if not self._is_tool_available("interrogate"):
            return {"status": "skip", "message": "interrogate not available"}

        # Build command
        cmd = ["interrogate", "-v", str(self.project_path)]

        # Run interrogate
        result = self._run_command(cmd)

        # Parse result
        if "RESULT: PASSED" in result["stdout"]:
            coverage = self._extract_coverage_percentage(result["stdout"])
            return {
                "status": "pass",
                "message": f"Docstring coverage: {coverage}%",
                "coverage": coverage,
            }
        else:
            coverage = self._extract_coverage_percentage(result["stdout"])
            return {
                "status": "fail",
                "message": f"Insufficient docstring coverage: {coverage}%",
                "coverage": coverage,
            }

    def _run_radon(self) -> Dict:
        """
        Run Radon code complexity checker.

        Returns:
            Dictionary with Radon results.
        """
        if not self._is_tool_available("radon"):
            return {"status": "skip", "message": "Radon not available"}

        # Check cyclomatic complexity
        cc_cmd = ["radon", "cc", "--json", str(self.project_path)]
        cc_result = self._run_command(cc_cmd)

        # Check maintainability index
        mi_cmd = ["radon", "mi", "--json", str(self.project_path)]
        mi_result = self._run_command(mi_cmd)

        cc_data = {}
        mi_data = {}

        # Parse Cyclomatic Complexity results
        try:
            if cc_result["stdout"]:
                cc_data = json.loads(cc_result["stdout"])
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse Radon CC output")

        # Parse Maintainability Index results
        try:
            if mi_result["stdout"]:
                mi_data = json.loads(mi_result["stdout"])
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse Radon MI output")

        # Analyze complexity results
        high_complexity = []
        for file_path, functions in cc_data.items():
            high_complexity.extend(
                {
                    "file": file_path,
                    "function": func["name"],
                    "line": func["line_number"],
                    "complexity": func["complexity"],
                    "rank": func["rank"],
                }
                for func in functions
                if func["rank"] in ["E", "F"]
            )
        low_maintainability = [
            {"file": file_path, "maintainability_index": float(mi_score)}
            for file_path, mi_score in mi_data.items()
            if float(mi_score) < 65
        ]
        # Determine overall status
        result = {
            "high_complexity": high_complexity[:10],  # Limit to 10 for readability
            "low_maintainability": low_maintainability[
                :10
            ],  # Limit to 10 for readability
            "total_high_complexity": len(high_complexity),
            "total_low_maintainability": len(low_maintainability),
        }

        if high_complexity or low_maintainability:
            result |= {
                "status": "fail",
                "message": f"Found {len(high_complexity)} high complexity functions and {len(low_maintainability)} low maintainability files",
            }
        else:
            result |= {"status": "pass", "message": "No complexity issues found"}

        return result

    def _is_tool_available(self, tool_name: str) -> bool:
        """
        Check if a tool is available in the environment.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if the tool is available, False otherwise.
        """
        if tool_name in self._available_tools:
            return self._available_tools[tool_name]

        try:
            result = subprocess.run(
                [tool_name, "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )
            available = result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            available = False

        self._available_tools[tool_name] = available
        return available

    def _ensure_config_file(self, config_filename: str) -> Optional[Path]:
        """
        Ensure a configuration file exists for the tool.
        This will check for a configuration file in the project directory first,  # TODO: Line too long, needs manual fixing
        This will check for a configuration file in the project directory first,
        then fall back to the PS2 default configuration.

        Args:
            config_filename: Filename of the configuration file.

        Returns:
            Path to the configuration file, or None if not available.
        """
        if config_path := self._find_config_in_project(config_filename):
            return config_path

        if config_path := self._find_config_in_common_locations(config_filename):
            return config_path

        if config_path := self._find_default_config(config_filename):
            return config_path

        self.logger.warning(f"No configuration found for {config_filename}")
        return None

    def _find_config_in_project(self, config_filename: str) -> Optional[Path]:
        """Find configuration file in the project directory."""
        project_config = self.project_path / config_filename
        return project_config if project_config.exists() else None

    def _find_config_in_common_locations(self, config_filename: str) -> Optional[Path]:
        """Find configuration file in common locations."""
        common_locations = [
            self.project_path
            / "pyproject.toml",  # Black and other tools use pyproject.toml
            self.project_path / ".config" / config_filename,
            self.project_path / "setup.cfg",  # Some tools use setup.cfg
        ]

        for location in common_locations:
            if not location.exists():
                continue

            # For non-pyproject.toml files or configs not requiring special handling
            if location.name != "pyproject.toml" or config_filename not in [
                BLACK_CONFIG_FILENAME,
                ISORT_CONFIG_FILENAME,
            ]:
                return location

            if config_path := self._check_pyproject_toml(location, config_filename):
                return config_path

    def _check_pyproject_toml(
        self, pyproject_path: Path, config_filename: str
    ) -> Optional[Path]:
        """Check if pyproject.toml contains configuration for the specified tool."""
        with contextlib.suppress(toml.TomlDecodeError):
            with open(pyproject_path, "r") as f:
                config = toml.load(f)

            # Check if the tool configuration exists in pyproject.toml
            if "tool" in config:
                if (
                    config_filename == BLACK_CONFIG_FILENAME
                    and "black" in config["tool"]
                ):
                    return pyproject_path
                if (
                    config_filename == ISORT_CONFIG_FILENAME
                    and "isort" in config["tool"]
                ):
                    return pyproject_path
        return None

    def _find_default_config(self, config_filename: str) -> Optional[Path]:
        """Find default configuration file in PS2 config directory."""
        ps2_config = self.config_dir / config_filename
        return ps2_config if ps2_config.exists() else None

    def _run_command(self, cmd: List[str]) -> Dict:
        """
        Run a command and return its output.

        Args:
            cmd: Command to run as a list of strings.

        Returns:
            Dictionary with command results.
        """
        self.logger.debug(f"Running command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,  # 1 minute timeout
                check=False,
                text=True,
            )

            return {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out: {' '.join(cmd)}")
            return {"returncode": -1, "stdout": "", "stderr": "Command timed out"}
        except subprocess.SubprocessError as e:
            self.logger.warning(f"Command failed: {' '.join(cmd)}, error: {e}")
            return {"returncode": -1, "stdout": "", "stderr": f"Command failed: {e}"}

    def _extract_pylint_score(self, stderr: str) -> float:
        """
        Extract Pylint score from stderr.

        Args:
            stderr: Standard error output from Pylint.

        Returns:
            Pylint score as a float, or 0.0 if not found.
        """
        for line in stderr.splitlines():
            if "Your code has been rated at" in line:
                with contextlib.suppress(IndexError, ValueError):
                    # Extract the score (e.g., "7.50/10")
                    score_str = (
                        line.split("Your code has been rated at")[1]
                        .split("/")[0]
                        .strip()
                    )
                    return float(score_str)
        return 0.0

    def _extract_coverage_percentage(self, output: str) -> float:
        """
        Extract coverage percentage from interrogate output.

        Args:
            output: Output from interrogate command.

        Returns:
            Coverage percentage as a float, or 0.0 if not found.
        """
        for line in output.splitlines():
            if "coverage: " in line:
                with contextlib.suppress(IndexError, ValueError):
                    # Extract the coverage (e.g., "coverage: 75.0%")
                    coverage_str = line.split("coverage: ")[1].split("%")[0].strip()
                    return float(coverage_str)
        return 0.0
