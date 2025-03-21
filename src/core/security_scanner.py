"""
Security Scanner Module for PS2.

This module identifies and addresses security vulnerabilities in Python projects,  # TODO: Line too long, needs manual fixing
including insecure code patterns, vulnerable dependencies, and common security
issues in web applications.
"""

import ast
import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Union, Optional

# Constants for security scanner
OS_ENVIRON = "os.environ"
FIX_ENV_VARS = "Use environment variables to store secret keys"
SECRET_KEY_WARNING = "Secret key should not be hardcoded"


class SecurityScanner:
    """
    Scanner for security vulnerabilities in Python projects.

    This class identifies security issues in Python projects, including insecure  # TODO: Line too long, needs manual fixing
    from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
    web applications, helping developers create more secure Python code.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the security scanner.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the scanner.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.security_scanner")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "scan_dependencies": True,
            "scan_code": True,
            "scan_web_security": True,
            "check_secrets": True,
            "min_severity": "medium",
            "ignore_patterns": [],
        }

        # Apply config settings
        self.settings = {
            **self.default_settings,
            **self.config.get("security_scanner", {}),
        }

        # Tool availability cache
        self._available_tools = {}

        # AST Cache
        self._ast_cache = {}

    def enable(self) -> None:
        """Enable the security scanner."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the security scanner."""
        self.enabled = False

    def scan(self, fix: bool = False) -> Dict:
        """
        Scan the project for security vulnerabilities.

        Args:
            fix: Whether to automatically fix security issues where possible.

        Returns:
            Dictionary with scanning results.
        """
        if not self.enabled:
            self.logger.warning("Security scanner is disabled. Enabling for this run.")
            self.enable()

        self.logger.info(f"Scanning for security issues (fix: {fix})")

        # Collect Python files
        python_files = self._collect_python_files()

        # Build AST cache
        self._build_ast_cache(python_files)

        # Scan results
        dependency_results = {}
        web_results = {}
        secrets_results = {}

        # Scan dependencies if configured
        if self.settings["scan_dependencies"]:
            dependency_results = self._scan_dependencies()

        code_results = self._scan_code() if self.settings["scan_code"] else {}
        # Scan web security if configured
        if self.settings["scan_web_security"]:
            web_results = self._scan_web_security()

        # Check for secrets if configured
        if self.settings["check_secrets"]:
            secrets_results = self._check_secrets()

        # Fix security issues if requested
        fixed_issues = []
        if fix:
            fixed_issues = self._fix_security_issues(
                dependency_results, code_results, web_results, secrets_results
            )

        # Count issues by severity
        severity_counts = self._count_issues_by_severity(
            dependency_results, code_results, web_results, secrets_results
        )

        # Build result
        result = {
            "files_analyzed": len(python_files),
            "dependency_vulnerabilities": dependency_results,
            "code_vulnerabilities": code_results,
            "web_vulnerabilities": web_results,
            "secrets_found": secrets_results,
            "fixed_issues": fixed_issues,
            "severity_counts": severity_counts,
        }

        # Determine overall status
        total_issues = sum(severity_counts.values())
        if total_issues == 0:
            result["status"] = "pass"
            result["message"] = "No security issues found"
        elif fix and fixed_issues:
            result["status"] = "fixed"
            result["message"] = (
                f"Fixed {len(fixed_issues)} of {total_issues} security issues"
            )
        else:
            result["status"] = "fail"
            result["message"] = f"Found {total_issues} security issues"

        return result

    def _collect_python_files(self) -> List[Path]:
        """
        Collect all Python files in the project.

        Returns:
            List of paths to Python files.
        """
        python_files = []
        ignore_patterns = self.settings.get("ignore_patterns", [])

        for root, dirs, files in os.walk(self.project_path):
            # Filter out directories to exclude
            dirs[:] = [
                d
                for d in dirs
                if not any(re.match(pattern, d) for pattern in ignore_patterns)
            ]

            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    # Check if file matches any ignore pattern
                    if not any(
                        re.match(pattern, str(file_path.relative_to(self.project_path)))
                        for pattern in ignore_patterns
                    ):
                        python_files.append(file_path)

        self.logger.info(f"Found {len(python_files)} Python files")
        return python_files

    def _build_ast_cache(self, python_files: List[Path]) -> None:
        """
        Build and cache AST for each Python file.

        Args:
            python_files: List of paths to Python files.
        """
        self.logger.info("Building AST cache")
        self._ast_cache = {}

        for file_path in python_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source = f.read()
                tree = ast.parse(source, filename=str(file_path))

                # Add the source file to the AST for reference
                tree.source_file = file_path

                # Add source code for potential fixes
                tree.source_code = source

                self._ast_cache[file_path] = tree
            except (SyntaxError, UnicodeDecodeError) as e:
                self.logger.warning(f"Failed to parse {file_path}: {e}")

    def _find_requirements_files(self) -> List[Path]:
        """Find requirements files in the project."""
        requirements_files = list(self.project_path.glob("requirements*.txt"))
        requirements_files.extend(list(self.project_path.glob("requirements/*.txt")))
        return requirements_files

    def _scan_with_safety(self, req_file: Path) -> List[Dict]:
        """Scan a requirements file with safety."""
        vulnerabilities = []
        self.logger.info(f"Scanning {req_file}")

        try:
            cmd = ["safety", "check", "--json", "-r", str(req_file)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode != 0:
                # Safety found vulnerabilities
                try:
                    safety_result = json.loads(result.stdout)

                    for vuln in safety_result:
                        vulnerability = {
                            "type": "dependency",
                            "package": vuln[0],
                            "installed_version": vuln[2],
                            "vulnerability_id": vuln[4],
                            "description": vuln[3],
                            "severity": self._map_safety_severity(vuln),
                            "file": str(req_file.relative_to(self.project_path)),
                            "fix_available": vuln[5] if len(vuln) > 5 else False,
                            "fix_version": vuln[6] if len(vuln) > 6 else None,
                        }

                        vulnerabilities.append(vulnerability)
                except (json.JSONDecodeError, IndexError) as e:
                    self.logger.warning(f"Failed to parse safety output: {e}")

        except subprocess.SubprocessError as e:
            self.logger.warning(f"Failed to run safety on {req_file}: {e}")

        return vulnerabilities

    def _scan_with_pip_audit(self) -> List[Dict]:
        """Scan dependencies with pip-audit."""
        vulnerabilities = []
        self.logger.info("Using pip-audit to scan dependencies")

        try:
            cmd = ["pip-audit", "--format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode != 0:
                # pip-audit found vulnerabilities
                try:
                    audit_result = json.loads(result.stdout)

                    for vuln in audit_result.get("vulnerabilities", []):
                        vulnerability = {
                            "type": "dependency",
                            "package": vuln.get("name"),
                            "installed_version": vuln.get("version"),
                            "vulnerability_id": vuln.get("id"),
                            "description": vuln.get("description"),
                            "severity": self._map_audit_severity(vuln.get("severity")),
                            "file": "requirements.txt",  # Placeholder
                            "fix_available": vuln.get("fix_version") is not None,
                            "fix_version": vuln.get("fix_version"),
                        }

                        vulnerabilities.append(vulnerability)
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse pip-audit output: {e}")

        except subprocess.SubprocessError as e:
            self.logger.warning(f"Failed to run pip-audit: {e}")

        return vulnerabilities

    def _scan_dependencies(self) -> Dict:
        """
        Scan project dependencies for vulnerabilities.

        Returns:
            Dictionary with dependency vulnerability results.
        """
        self.logger.info("Scanning dependencies for vulnerabilities")
        vulnerabilities = []

        # Try to use safety if available
        if self._is_tool_available("safety"):
            self.logger.info("Using safety to scan dependencies")
            requirements_files = self._find_requirements_files()

            if not requirements_files:
                self.logger.warning("No requirements files found")
                return {"vulnerabilities": vulnerabilities}

            # Scan each requirements file
            for req_file in requirements_files:
                vulnerabilities.extend(self._scan_with_safety(req_file))

        # Try to use pip-audit if safety is not available
        elif self._is_tool_available("pip-audit"):
            vulnerabilities.extend(self._scan_with_pip_audit())

        # Filter by minimum severity
        vulnerabilities = self._filter_vulnerabilities_by_severity(vulnerabilities)

        return {"vulnerabilities": vulnerabilities}

    def _scan_code(self) -> Dict:
        """
        Scan code for security vulnerabilities.

        Returns:
            Dictionary with code vulnerability results.
        """
        self.logger.info("Scanning code for security vulnerabilities")

        # Initialize the vulnerabilities list
        vulnerabilities = []

        if self._is_tool_available("bandit"):
            self.logger.info("Using Bandit to scan code")

            try:
                cmd = ["bandit", "-r", "-f", "json", str(self.project_path)]
                result = subprocess.run(
                    cmd, capture_output=True, text=True, check=False
                )

                try:
                    bandit_result = json.loads(result.stdout)

                    for issue in bandit_result.get("results", []):
                        vulnerability = {
                            "type": "code",
                            "issue_type": issue.get("test_id"),
                            "issue_name": issue.get("test_name"),
                            "description": issue.get("issue_text"),
                            "severity": issue.get("issue_severity", "medium").lower(),
                            "confidence": issue.get(
                                "issue_confidence", "medium"
                            ).lower(),
                            "file": issue.get("filename"),
                            "line": issue.get("line_number"),
                            "code": issue.get("code"),
                            "fix_suggestion": self._generate_fix_suggestion(issue),
                        }

                        vulnerabilities.append(vulnerability)

                except json.JSONDecodeError as e:
                    self.logger.warning(f"Failed to parse Bandit output: {e}")

            except subprocess.SubprocessError as e:
                self.logger.warning(f"Failed to run Bandit: {e}")

        # Also scan using our own AST-based checks
        custom_vulnerabilities = self._custom_code_scan()
        vulnerabilities.extend(custom_vulnerabilities)

        # Filter by minimum severity
        min_severity = self.settings.get("min_severity", "medium")
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        min_severity_level = severity_levels.get(min_severity, 0)
        vulnerabilities = [
            v
            for v in vulnerabilities
            if severity_levels.get(v["severity"], 0) >= min_severity_level
        ]

        return {"vulnerabilities": vulnerabilities}

    def _custom_code_scan(self) -> List[Dict]:
        """
                "fix_suggestion": "Move sensitive data to environment variables or a secure storage solution"  # TODO: Line too long, needs manual fixing

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []

        # Define security patterns to check
        security_patterns = {
            "hardcoded_password": {
                "pattern": self._check_hardcoded_password,
                "severity": "high",
                "fix_suggestion": "Move sensitive data to environment variables or a secure storage solution",
            },
            "sql_injection": {
                "severity": "high",
                "description": "Potential SQL injection vulnerability",
                "fix_suggestion": "Use parameterized queries or an ORM",
            },
            "command_injection": {
                "severity": "high",
                "description": "Potential command injection vulnerability",
                "fix_suggestion": "Use subprocess.run with shell=False and a list of arguments",
            },
            "insecure_deserialization": {
                "pattern": self._check_insecure_deserialization,
                "severity": "high",
                "description": "Insecure deserialization detected",
                "fix_suggestion": "Use safer alternatives like json instead of pickle",
            },
            "weak_crypto": {
                "pattern": self._check_weak_crypto,
                "severity": "medium",
                "description": "Use of weak cryptographic methods",
                "fix_suggestion": "Use modern cryptography with strong algorithms",
            },
        }

        # Scan each file
        for file_path, tree in self._ast_cache.items():
            relative_path = str(file_path.relative_to(self.project_path))

            # Run each security check
            for check_name, check_info in security_patterns.items():
                check_results = check_info["pattern"](tree)

                for result in check_results:
                    vulnerability = {
                        "type": "code",
                        "issue_type": check_name,
                        "issue_name": check_name.replace("_", " ").title(),
                        "description": check_info["description"],
                        "severity": check_info["severity"],
                        "confidence": result.get("confidence", "medium"),
                        "file": relative_path,
                        "line": result.get("line"),
                        "code": result.get("code"),
                        "fix_suggestion": check_info["fix_suggestion"],
                    }

                    vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _is_suspicious_password_variable(
        self, var_name: str, patterns: List[str]
    ) -> bool:
        """
        Check if a variable name matches any suspicious password pattern.

        Args:
            var_name: The variable name to check.
            patterns: List of regex patterns to match against.

        Returns:
            True if the variable name matches any pattern, False otherwise.
        """
        return any(re.search(pattern, var_name) for pattern in patterns)

    def _create_password_issue(self, node: ast.AST, var_name: str, value: str) -> Dict:
        """
        Create an issue dictionary for a hardcoded password.

        Args:
            node: The AST node containing the hardcoded password.
            var_name: The name of the variable containing the password.
            value: The hardcoded password value.

        Returns:
            Dictionary with issue details.
        """
        line = getattr(node, "lineno", 0)
        code = f"{var_name} = '{value}'"

        return {"line": line, "code": code, "confidence": "medium"}

    def _check_assignment_for_hardcoded_password(
        self, node: ast.Assign, password_patterns: List[str]
    ) -> Optional[Dict]:
        """
        Check if an assignment contains a hardcoded password.

        Args:
            node: The assignment node to check.
            password_patterns: List of regex patterns for password-like variable names.

        Returns:
            Issue dictionary if a hardcoded password is found, None otherwise.
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Check if variable name matches any pattern and value is a string literal
                if (
                    self._is_suspicious_password_variable(var_name, password_patterns)
                    and isinstance(node.value, ast.Str)
                    and len(node.value.s) > 3
                ):
                    return self._create_password_issue(node, var_name, node.value.s)
        return None

    def _check_hardcoded_password(self, tree: ast.Module) -> List[Dict]:
        """
        Check for hardcoded passwords or secrets.

        Args:
            tree: AST of the module to check.

        Returns:
            List of issue dictionaries.
        """
        issues = []

        # Define patterns for password-like variable names
        password_patterns = [
            r"password",
            r"passwd",
            r"pwd",
            r"secret",
            r"key",
            r"token",
            r"apikey",
            r"api_key",
        ]

        # Check all assignments in the AST
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                if issue := self._check_assignment_for_hardcoded_password(
                    node, password_patterns
                ):
                    issues.append(issue)

        return issues

    def _contains_sql_keywords(self, text: str, keywords: List[str]) -> bool:
        """
        Check if a text contains any SQL keywords.

        Args:
            text: The text to check.
            keywords: List of SQL keywords to check for.

        Returns:
            True if the text contains any SQL keyword, False otherwise.
        """
        return any(keyword in text.upper() for keyword in keywords)

    def _create_sql_injection_issue(self, node: ast.AST, node_str: str) -> Dict:
        """
        Create an issue dictionary for a potential SQL injection vulnerability.

        Args:
            node: The AST node containing the potential vulnerability.
            node_str: String representation of the node.

        Returns:
            Dictionary with issue details.
        """
        line = getattr(node, "lineno", 0)
        return {"line": line, "code": node_str, "confidence": "medium"}

    def _check_joined_str_for_sql_injection(
        self, node: ast.JoinedStr, sql_keywords: List[str]
    ) -> Optional[Dict]:
        """
        Check if a JoinedStr (f-string) contains potential SQL injection.

        Args:
            node: The JoinedStr node to check.
            sql_keywords: List of SQL keywords to check for.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        node_str = ast.unparse(node)
        if self._contains_sql_keywords(node_str, sql_keywords):
            return self._create_sql_injection_issue(node, node_str)
        return None

    def _check_binop_for_sql_injection(
        self, node: ast.BinOp, sql_keywords: List[str]
    ) -> Optional[Dict]:
        """
        Check if a binary operation contains potential SQL injection.

        Args:
            node: The BinOp node to check.
            sql_keywords: List of SQL keywords to check for.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if isinstance(node.op, ast.Add) and (
            isinstance(node.left, ast.Str) or isinstance(node.right, ast.Str)
        ):
            node_str = ast.unparse(node)
            if self._contains_sql_keywords(node_str, sql_keywords):
                return self._create_sql_injection_issue(node, node_str)
        return None

    def _check_format_for_sql_injection(
        self, node: ast.Call, sql_keywords: List[str]
    ) -> Optional[Dict]:
        """
        Check if a string format call contains potential SQL injection.

        Args:
            node: The Call node to check.
            sql_keywords: List of SQL keywords to check for.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
            and isinstance(node.func.value, ast.Str)
            and self._contains_sql_keywords(node.func.value.s, sql_keywords)
        ):
            node_str = ast.unparse(node)
            return self._create_sql_injection_issue(node, node_str)
        return None

    def _check_sql_injection(self, tree: ast.Module) -> List[Dict]:
        """
        Check for potential SQL injection vulnerabilities.

        Args:
            tree: AST of the module to check.

        Returns:
            List of issue dictionaries.
        """
        issues = []

        # Look for string formatting or concatenation with SQL keywords
        sql_keywords = [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "CREATE",
            "ALTER",
            "FROM",
            "WHERE",
            "JOIN",
        ]

        for node in ast.walk(tree):
            # Check for f-strings with SQL keywords
            if isinstance(node, ast.JoinedStr):
                if issue := self._check_joined_str_for_sql_injection(
                    node, sql_keywords
                ):
                    issues.append(issue)

            elif isinstance(node, ast.BinOp):
                if issue := self._check_binop_for_sql_injection(node, sql_keywords):
                    issues.append(issue)

            elif isinstance(node, ast.Call):
                if issue := self._check_format_for_sql_injection(node, sql_keywords):
                    issues.append(issue)

        return issues

    def _check_os_command_injection(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for command injection via os module functions.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr in ["system", "popen"]
        ):
            return self._create_security_issue(node)
        return None

    def _check_subprocess_command_injection(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for command injection via subprocess module functions with shell=True.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in ["call", "run", "Popen"]
        ):
            # Check for shell=True in kwargs
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    return self._create_security_issue(node)
        return None

    def _check_command_injection(self, tree: ast.Module) -> List[Dict]:
        """
        Check for potential command injection vulnerabilities.

        Args:
            tree: AST of the module to check.

        Returns:
            List of issue dictionaries.
        """
        issues = []

        # Look for os.system, os.popen, subprocess.call with shell=True
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if os_issue := self._check_os_command_injection(node):
                    issues.append(os_issue)

                if subprocess_issue := self._check_subprocess_command_injection(node):
                    issues.append(subprocess_issue)

        return issues

    def _check_pickle_deserialization(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for insecure pickle deserialization.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pickle"
            and node.func.attr in ["loads", "load"]
        ):
            return self._create_security_issue(node)
        return None

    def _is_safe_yaml_loader_used(self, node: ast.Call) -> bool:
        """
        Check if a safe YAML loader is used.

        Args:
            node: The AST call node to check.

        Returns:
            True if a safe loader is used, False otherwise.
        """
        return any(
            keyword.arg == "Loader"
            and isinstance(keyword.value, ast.Attribute)
            and hasattr(keyword.value, "attr")
            and keyword.value.attr in ["SafeLoader", "CSafeLoader"]
            for keyword in node.keywords
        )

    def _check_yaml_deserialization(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for insecure YAML deserialization.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
            and node.func.attr == "load"
        ) and not self._is_safe_yaml_loader_used(node):
            return self._create_security_issue(node)
        return None

    def _check_cryptography_usage(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for potentially insecure cryptography usage.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "cryptography"
        ):
            return self._create_security_issue(node)
        return None

    def _check_insecure_deserialization(self, tree: ast.Module) -> List[Dict]:
        """
        Check for insecure deserialization vulnerabilities.

        Args:
            tree: AST of the module to check.

        Returns:
            List of issue dictionaries.
        """
        issues = []

        # Look for pickle, marshal, yaml.load (without safe loader)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if pickle_issue := self._check_pickle_deserialization(node):
                    issues.append(pickle_issue)

                if yaml_issue := self._check_yaml_deserialization(node):
                    issues.append(yaml_issue)

                if crypto_issue := self._check_cryptography_usage(node):
                    issues.append(crypto_issue)

        return issues

    def _check_weak_hashlib(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for weak hash algorithms in hashlib.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "hashlib"
            and node.func.attr in ["md5", "sha1"]
        ):
            return self._create_security_issue(node)
        return None

    def _create_security_issue(self, node: ast.AST) -> Dict:
        """
        Create a security issue dictionary from an AST node.

        Args:
            node: The AST node to create an issue for.

        Returns:
            Dictionary with issue details.
        """
        line = getattr(node, "lineno", 0)
        node_str = ast.unparse(node)
        return {"line": line, "code": node_str, "confidence": "high"}

    def _contains_weak_crypto_algorithm(self, node_str: str) -> bool:
        """
        Check if a node contains weak cryptographic algorithms.

        Args:
            node_str: String representation of the node.

        Returns:
            True if weak algorithms are found, False otherwise.
        """
        weak_algos = ["DES", "RC4", "Blowfish", "ARC4"]
        return any(algo in node_str for algo in weak_algos)

    def _check_weak_cryptography_lib(self, node: ast.Call) -> Optional[Dict]:
        """
        Check for deprecated ciphers in cryptography library.

        Args:
            node: The AST call node to check.

        Returns:
            Issue dictionary if vulnerability found, None otherwise.
        """
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and hasattr(node.func.value, "value")
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "cryptography"
        ):
            node_str = ast.unparse(node)
            if self._contains_weak_crypto_algorithm(node_str):
                line = getattr(node, "lineno", 0)
                return {"line": line, "code": node_str, "confidence": "high"}
        return None

    def _check_weak_crypto(self, tree: ast.Module) -> List[Dict]:
        """
        Check for weak cryptographic methods.

        Args:
            tree: AST of the module to check.

        Returns:
            List of issue dictionaries.
        """
        issues = []

        # Look for weak hash algorithms and cryptographic methods
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if hashlib_issue := self._check_weak_hashlib(node):
                    issues.append(hashlib_issue)

                if crypto_issue := self._check_weak_cryptography_lib(node):
                    issues.append(crypto_issue)

        return issues

    def _filter_vulnerabilities_by_severity(
        self, vulnerabilities: List[Dict]
    ) -> List[Dict]:
        """
        Filter vulnerabilities by minimum severity level.

        Args:
            vulnerabilities: List of vulnerability dictionaries to filter.

        Returns:
            Filtered list of vulnerability dictionaries.
        """
        # Filter by minimum severity
        min_severity = self.settings.get("min_severity", "medium")
        severity_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        min_severity_level = severity_levels.get(min_severity, 0)
        return [
            v
            for v in vulnerabilities
            if severity_levels.get(v["severity"], 0) >= min_severity_level
        ]

    def _scan_specific_framework(self, framework: str) -> List[Dict]:
        """
        Scan security issues for a specific web framework.

        Args:
            framework: The framework to scan.

        Returns:
            List of vulnerability dictionaries for the specified framework.
        """
        if framework == "Django" and self._has_django_app():
            return self._scan_django_security()
        elif framework == "Flask" and self._has_flask_app():
            return self._scan_flask_security()
        elif framework == "FastAPI" and self._has_fastapi_app():
            return self._scan_fastapi_security()
        return []

    def _scan_all_frameworks(self) -> List[Dict]:
        """
        Scan security issues for all detected web frameworks.

        Returns:
            List of vulnerability dictionaries from all frameworks.
        """
        vulnerabilities = []

        # Check for common web frameworks
        frameworks_to_scan = [
            ("Django", self._has_django_app, self._scan_django_security),
            ("Flask", self._has_flask_app, self._scan_flask_security),
            ("FastAPI", self._has_fastapi_app, self._scan_fastapi_security),
        ]

        # Scan each detected framework
        for name, detector, scanner in frameworks_to_scan:
            if detector():
                self.logger.debug(
                    f"Detected {name} framework, scanning for vulnerabilities"
                )
                framework_vulnerabilities = scanner()
                vulnerabilities.extend(framework_vulnerabilities)

        # Add generic web security issues
        generic_vulnerabilities = self._scan_generic_web_security()
        vulnerabilities.extend(generic_vulnerabilities)

        return vulnerabilities

    def _scan_web_security(self, framework: str = None) -> List[Dict]:
        """
        Scan web application security issues.

        Args:
            framework: Optional framework name to scan. If None, scans all detected frameworks.

        Returns:
            List of vulnerability dictionaries.
        """
        self.logger.info(
            f"Scanning web application security for {framework or 'all frameworks'}"
        )

        # If a specific framework is provided, only scan that one
        if framework:
            vulnerabilities = self._scan_specific_framework(framework)
        else:
            vulnerabilities = self._scan_all_frameworks()

        # Filter and return vulnerabilities by severity
        return self._filter_vulnerabilities_by_severity(vulnerabilities)

    def _has_django_app(self) -> bool:
        """
        Check if the project is a Django application.

        Returns:
            True if Django app, False otherwise.
        """
        # Look for Django-specific files
        settings_py = list(self.project_path.glob("**/settings.py"))
        urls_py = list(self.project_path.glob("**/urls.py"))
        manage_py = list(self.project_path.glob("manage.py"))

        return bool(settings_py and urls_py and manage_py)

    def _has_flask_app(self) -> bool:
        """
        Check if the project is a Flask application.

        Returns:
            True if Flask app, False otherwise.
        """
        # Look for Flask imports in Python files
        return self._has_import_or_import_from("flask")

    def _has_fastapi_app(self) -> bool:
        """
        Check if the project is a FastAPI application.

        Returns:
            bool: True if the project is a FastAPI application, False otherwise.
        """
        # Look for FastAPI imports in Python files
        return self._has_import_or_import_from("fastapi")

    def _check_import_node(self, node: ast.AST, module_name: str) -> bool:
        """
        Check if an Import node imports the specified module.

        Args:
            node: The AST node to check
            module_name: Name of the module to check for

        Returns:
            bool: True if the module is imported, False otherwise
        """
        if not isinstance(node, ast.Import):
            return False

        return any(name.name == module_name for name in node.names)

    def _check_import_from_node(self, node: ast.AST, module_name: str) -> bool:
        """
        Check if an ImportFrom node imports from the specified module.

        Args:
            node: The AST node to check
            module_name: Name of the module to check for

        Returns:
            bool: True if the module is imported from, False otherwise
        """
        return isinstance(node, ast.ImportFrom) and node.module == module_name

    def _has_import_or_import_from(self, module_name: str) -> bool:
        """
        Check if any file imports the specified module.

        Args:
            module_name: Name of the module to check for.

        Returns:
            bool: True if the module is imported, False otherwise.
        """
        for file_path in self._ast_cache:
            tree = self._ast_cache[file_path]

            for node in ast.walk(tree):
                if self._check_import_node(
                    node, module_name
                ) or self._check_import_from_node(node, module_name):
                    return True

        return False

    def _scan_django_security(self) -> List[Dict]:
        """
                            "line": self._get_line_number(content,
                                secret_key_match.start())
                            "fix_suggestion": FIX_ENV_VARS  # TODO: Line too long, needs manual fixing
        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []

        # Find settings.py files
        settings_files = list(self.project_path.glob("**/settings.py"))

        for settings_file in settings_files:
            relative_path = str(settings_file.relative_to(self.project_path))

            # Check for common Django security issues
            with open(settings_file, "r", encoding="utf-8") as f:
                content = f.read()

                debug_match = re.search(r"DEBUG\s*=\s*True", content)
                if debug_match:
                    vulnerabilities.append(
                        {
                            "type": "web",
                            "issue_type": "django_debug_enabled",
                            "issue_name": "Django Debug Enabled in Production",
                            "description": "Debug mode should be disabled in production",
                            "severity": "high",
                            "confidence": "high",
                            "file": relative_path,
                            "code": "DEBUG = True",
                            "fix_suggestion": "Set DEBUG = False in production environments",
                        }
                    )

                if secret_key_match := re.search(
                    r'SECRET_KEY\s*=\s*[\'"]([^\'"]+)[\'"]', content
                ):
                    # Check if the secret key is hardcoded (not loaded from environment)
                    if OS_ENVIRON not in content[: secret_key_match.start()]:
                        vulnerabilities.append(
                            {
                                "type": "web",
                                "issue_type": "django_hardcoded_secret",
                                "fix_suggestion": FIX_ENV_VARS,
                                "description": SECRET_KEY_WARNING,
                                "severity": "high",
                                "confidence": "high",
                                "file": relative_path,
                                "line": self._get_line_number(
                                    content, secret_key_match.start()
                                ),
                                "code": secret_key_match[1],
                                "remediation": FIX_ENV_VARS,
                            }
                        )

        return vulnerabilities

    def _scan_flask_security(self) -> List[Dict]:
        """
        Scan Flask-specific security issues.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []

        # Find app.py files
        app_files = list(self.project_path.glob("**/app.py"))

        for app_file in app_files:
            relative_path = str(app_file.relative_to(self.project_path))

            # Check for common Flask security issues
            with open(app_file, "r", encoding="utf-8") as f:
                content = f.read()

                # Check for insecure secret key
                secret_key_match = re.search(
                    r'secret_key\s*=\s*[\'"]([^\'"]+)[\'"]', content
                )
                if (
                    secret_key_match
                    and "os.environ" not in content[: secret_key_match.start()]
                ):
                    vulnerabilities.append(
                        {
                            "type": "web",
                            "issue_type": "flask_hardcoded_secret",
                            "issue_name": "Flask Hardcoded Secret Key",
                            "description": SECRET_KEY_WARNING,
                            "severity": "high",
                            "confidence": "high",
                            "file": relative_path,
                            "code": secret_key_match[1],
                            "fix_suggestion": FIX_ENV_VARS,
                        }
                    )

        return vulnerabilities

    def _scan_fastapi_security(self) -> List[Dict]:
        """
        Scan FastAPI-specific security issues.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []

        # Find main.py files
        main_files = list(self.project_path.glob("**/main.py"))

        for main_file in main_files:
            relative_path = str(main_file.relative_to(self.project_path))

            # Check for common FastAPI security issues
            with open(main_file, "r", encoding="utf-8") as f:
                content = f.read()

                if secret_key_match := re.search(
                    r'secret_key\s*=\s*[\'"]([^\'"]+)[\'"]', content
                ):
                    # Check if the secret key is hardcoded (not loaded from environment)
                    if OS_ENVIRON not in content[: secret_key_match.start()]:
                        vulnerabilities.append(
                            {
                                "type": "web",
                                "issue_type": "fastapi_hardcoded_secret",
                                "issue_name": "FastAPI Hardcoded Secret Key",
                                "description": SECRET_KEY_WARNING,
                                "severity": "high",
                                "confidence": "high",
                                "file": relative_path,
                                "line": self._get_line_number(
                                    content, secret_key_match.start()
                                ),
                                "code": secret_key_match[1],
                                "fix_suggestion": FIX_ENV_VARS,
                            }
                        )

        return vulnerabilities

    def _scan_generic_web_security(self) -> List[Dict]:
        """
        Scan generic web application security issues.

        Returns:
            List of vulnerability dictionaries.
        """
        vulnerabilities = []

        # Look for common web frameworks
        frameworks = ["Django", "Flask", "FastAPI"]

        # Scan for common web security issues
        for framework in frameworks:
            framework_vulnerabilities = self._scan_web_security(framework)
            vulnerabilities.extend(framework_vulnerabilities)

        return vulnerabilities

    def _get_line_number(self, content: str, position: int) -> int:
        """
        Get the line number of a position in a string.

        Args:
            content: String content.
            position: Position in the string.

        Returns:
            Line number of the position.
        """
        return content[:position].count("\n") + 1
