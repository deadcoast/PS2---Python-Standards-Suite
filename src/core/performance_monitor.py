"""
Performance Monitor Module for PS2.

This module monitors and analyzes performance metrics for Python projects,
identifying potential bottlenecks and resource usage issues to help
developers optimize their code.
"""

import ast
import logging
import os
import re
import threading
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass
class PerformanceMetric:
    """Data class for performance metrics."""

    name: str
    value: float
    unit: str
    timestamp: float
    context: Dict[str, Any]


class PerformanceMonitor:
    """
    Monitor for Python code performance.

    This class tracks and analyzes performance metrics for Python projects,
    identifying bottlenecks and resource usage issues to help developers
    optimize their code.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the performance monitor.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the monitor.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.performance_monitor")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "track_memory_usage": True,
            "track_execution_time": True,
            "execution_time_threshold": 1.0,  # seconds
            "memory_usage_threshold": 100,  # MB
            "log_performance_stats": True,
        }

        # Apply config settings
        self.settings = {
            **self.default_settings,
            **self.config.get("performance_monitor", {}),
        }

        # Tracking state
        self._metrics: List[PerformanceMetric] = []
        self._monitoring_thread: Optional[Thread] = None
        self._stop_monitoring: threading.Event = threading.Event()
        self._project_entry_points: Optional[List[Dict]] = None
        self._ast_cache: Dict[Path, ast.Module] = {}

    def enable(self) -> None:
        """Enable the performance monitor."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the performance monitor."""
        self.enabled = False

    def monitor(self, duration: int = 3600) -> Dict:
        """
        Monitor performance metrics for a specified duration.

        Args:
            duration: Duration to monitor in seconds.

        Returns:
            Dictionary with monitoring results.
        """
        if not self.enabled:
            self.logger.warning(
                "Performance monitor is disabled. Enabling for this run."
            )
            self.enable()

        self.logger.info(f"Monitoring performance for {duration} seconds")

        # Reset metrics
        self._metrics = []

        # Collect Python files
        python_files = self._collect_python_files()

        # Build AST cache
        self._build_ast_cache(python_files)

        # Identify project entry points
        entry_points = self._identify_entry_points()

        # Run static code analysis to identify potential performance issues
        static_issues = self._analyze_potential_bottlenecks()

        # Run profiling on entry points
        profiling_results = self._profile_entry_points()

        # Start monitoring thread if duration > 0
        if duration > 0:
            try:
                self._start_monitoring(duration)
            except Exception as e:
                self.logger.error(f"Failed to start monitoring: {e}")

        # Build result
        result = {
            "entry_points": entry_points,
            "static_issues": static_issues,
            "profiling_results": profiling_results,
            "metrics": self._metrics[:100],  # Limit to 100 metrics for readability
            "total_metrics": len(self._metrics),
            "summary": self._generate_summary(),
        }

        # Determine overall status
        if static_issues:
            result["status"] = "warning"
            result["message"] = (
                f"Found {len(static_issues)} potential performance issues"
            )
        else:
            result["status"] = "pass"
            result["message"] = "No performance issues detected"

        return result

    def _collect_python_files(self) -> List[Path]:
        """
        Collect all Python files in the project.

        Returns:
            List of paths to Python files.
        """
        # Get exclude patterns from config
        exclude_patterns = self.config.get("analyzer", {}).get("exclude_patterns", [])
        python_files = []

        for root, dirs, files in os.walk(self.project_path):
            # Filter out directories to exclude
            dirs[:] = [
                d
                for d in dirs
                if not any(re.match(pattern, d) for pattern in exclude_patterns)
            ]

            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file
                    # Check if file matches any exclude pattern
                    if not any(
                        re.match(pattern, str(file_path.relative_to(self.project_path)))
                        for pattern in exclude_patterns
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

    def _is_main_check_node(self, node: ast.AST) -> bool:
        """
        Check if a node is an if __name__ == "__main__" check.

        Args:
            node: AST node to check.

        Returns:
            True if the node is a main check, False otherwise.
        """
        return (
            isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__"
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.Eq)
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Str)
            and node.test.comparators[0].s == "__main__"
        )

    def _find_main_blocks(self) -> List[Dict]:
        """
        Find files with __main__ blocks in the project.

        Returns:
            List of entry points with main blocks.
        """
        entry_points = []

        for file_path, tree in self._ast_cache.items():
            main_line = 0

            for node in ast.walk(tree):
                if self._is_main_check_node(node):
                    main_line = node.lineno
                    # Create entry point for this file
                    entry_point = {
                        "file": str(file_path.relative_to(self.project_path)),
                        "type": "script",
                        "main_line": main_line,
                    }
                    entry_points.append(entry_point)
                    break

        return entry_points

    def _extract_console_scripts(self, setup_content: str) -> List[Dict]:
        """
        Extract console scripts from setup.py content.

        Args:
            setup_content: Content of setup.py file.

        Returns:
            List of console script entry points.
        """
        entry_points = []

        if entry_points_match := re.search(
            r"entry_points\s*=\s*{([^}]*)}", setup_content, re.DOTALL
        ):
            entry_points_section = entry_points_match[1]

            if console_scripts_match := re.search(
                r"console_scripts\s*:\s*\[(.*?)\]", entry_points_section, re.DOTALL
            ):
                console_scripts = console_scripts_match[1]

                for script in re.finditer(r"'([^']+)'", console_scripts):
                    script_def = script.group(1)

                    if "=" in script_def:
                        name, import_path = script_def.split("=", 1)
                        entry_point = {
                            "name": name.strip(),
                            "import_path": import_path.strip(),
                            "type": "console_script",
                            "file": "setup.py",
                        }
                        entry_points.append(entry_point)

        return entry_points

    def _identify_entry_points(self) -> List[Dict]:
        """
        Identify project entry points.

        Returns:
            List of entry point dictionaries.
        """
        self.logger.info("Identifying project entry points")

        # Find files with __main__ blocks
        entry_points = self._find_main_blocks()

        # Look for setup.py entry points
        setup_py = self.project_path / "setup.py"
        if setup_py.exists():
            try:
                with open(setup_py, "r", encoding="utf-8") as f:
                    setup_content = f.read()

                # Extract console scripts from setup.py
                console_scripts = self._extract_console_scripts(setup_content)
                entry_points.extend(console_scripts)
            except (IOError, UnicodeDecodeError) as e:
                self.logger.warning(f"Failed to read setup.py: {e}")

        self._project_entry_points = entry_points
        return entry_points

    def _analyze_potential_bottlenecks(self) -> List[Dict]:
        """
        Analyze code for potential performance bottlenecks.

        Returns:
            List of potential performance issues.
        """
        self.logger.info("Analyzing code for potential performance bottlenecks")

        issues = []

        # Define performance patterns to check
        performance_patterns = {
            "nested_loops": {
                "description": "Nested loops can lead to O(n²) or worse time complexity",
                "severity": "medium",
                "checker": self._check_nested_loops,
            },
            "expensive_operations_in_loops": {
                "description": "Expensive operations inside loops",
                "severity": "high",
                "checker": self._check_expensive_operations_in_loops,
            },
            "memory_leaks": {
                "description": "Potential memory leaks or high memory usage",
                "severity": "high",
                "checker": self._check_memory_leaks,
            },
            "inefficient_data_structures": {
                "description": "Inefficient data structure usage",
                "severity": "medium",
                "checker": self._check_inefficient_data_structures,
            },
            "expensive_function_calls": {
                "description": "Repeated expensive function calls",
                "severity": "medium",
                "checker": self._check_expensive_function_calls,
            },
        }

        # Check each file
        for file_path, tree in self._ast_cache.items():
            relative_path = str(file_path.relative_to(self.project_path))

            # Run each performance check
            for check_name, check_info in performance_patterns.items():
                check_results = check_info["checker"](tree)

                # Add issues
                for result in check_results:
                    issue = {
                        "type": check_name,
                        "severity": check_info["severity"],
                        "file": relative_path,
                        "line": result.get("line", 0),
                        "code": result.get("code", ""),
                        "suggestion": result.get(
                            "suggestion", "Consider refactoring for better performance"
                        ),
                    }
                    issues.append(issue)

        return issues

    def _get_code_at_line(self, tree: ast.Module, line: int) -> str:
        """
        Get the code at a specific line in the source file.

        Args:
            tree: AST of the module.
            line: Line number to get code from.

        Returns:
            The code at the specified line or a placeholder.
        """
        if hasattr(tree, "source_code"):
            code_lines = tree.source_code.splitlines()
            if line <= len(code_lines):
                return code_lines[line - 1].strip()

        return f"Loop at line {line}"

    def _get_loop_suggestion(self, loop_level: int) -> str:
        """
        Get an appropriate suggestion based on loop nesting level.

        Args:
            loop_level: The nesting level of the loop.

        Returns:
            A suggestion string.
        """
        if loop_level == 2:
            return "Consider if nested loops can be avoided or optimized."
        else:  # loop_level > 2
            return "Multiple nested loops detected. Consider refactoring to reduce time complexity."

    def _check_nested_loops(self, tree: ast.Module) -> List[Dict]:
        """
        Check for nested loops that could cause performance issues.

        Args:
            tree: AST of the module to check.

        Returns:
            List of nested loop issues.
        """
        issues = []

        # Function to check for nested loops recursively
        def check_nested_loops_in_node(node, parent_loops=0):
            if not isinstance(node, (ast.For, ast.While)):
                # Not a loop, just check children
                for child in ast.iter_child_nodes(node):
                    check_nested_loops_in_node(child, parent_loops)
                return

            # This is a loop
            loop_level = parent_loops + 1

            if loop_level >= 2:
                # Nested loop detected
                line = getattr(node, "lineno", 0)
                code = self._get_code_at_line(tree, line)
                suggestion = self._get_loop_suggestion(loop_level)

                issues.append(
                    {
                        "line": line,
                        "code": code,
                        "suggestion": suggestion,
                        "loop_level": loop_level,
                    }
                )

            # Check for more nested loops in the body
            for child in ast.iter_child_nodes(node):
                check_nested_loops_in_node(child, loop_level)

        # Start checking from the module level
        check_nested_loops_in_node(tree)

        return issues

    def _get_expensive_operations(self) -> Dict[str, str]:
        """Return a dictionary of expensive operations and their descriptions."""
        return {
            # File operations
            "open": "File operation inside a loop",
            "read": "File reading inside a loop",
            "write": "File writing inside a loop",
            # Database operations
            "execute": "Database query inside a loop",
            "query": "Database query inside a loop",
            # Network operations
            "request": "Network request inside a loop",
            "get": "HTTP request inside a loop",
            "post": "HTTP request inside a loop",
            # List operations that could be inefficient
            "append": "List appending inside a loop (consider using list comprehension)",
            # JSON operations
            "loads": "JSON parsing inside a loop",
            "dumps": "JSON serialization inside a loop",
            # Process operations
            "Popen": "Process creation inside a loop",
            "run": "Process execution inside a loop",
            # Regular expression operations
            "compile": "Regex compilation inside a loop",
            "match": "Regex matching inside a loop",
            "search": "Regex searching inside a loop",
        }

    def _extract_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract the function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    def _get_code_at_line_from_tree(
        self, tree: ast.Module, line: int, default_msg: str
    ) -> str:
        """Get the code at a specific line from the source tree."""
        if hasattr(tree, "source_code"):
            code_lines = tree.source_code.splitlines()
            if line <= len(code_lines):
                return code_lines[line - 1].strip()
        return default_msg

    def _check_call_in_loop(
        self, loop_node: ast.AST, expensive_operations: Dict[str, str], tree: ast.Module
    ) -> List[Dict]:
        """Check for expensive function calls within a loop node."""
        issues = []
        loop_line = getattr(loop_node, "lineno", 0)

        for body_node in ast.walk(loop_node):
            if not isinstance(body_node, ast.Call):
                continue

            func_name = self._extract_function_name(body_node)
            if not func_name or func_name not in expensive_operations:
                continue

            line = getattr(body_node, "lineno", loop_line)
            code = self._get_code_at_line_from_tree(
                tree, line, f"Operation at line {line}"
            )

            issues.append(
                {
                    "line": line,
                    "code": code,
                    "suggestion": f"{expensive_operations[func_name]}. Consider moving outside the loop or finding a more efficient approach.",
                }
            )

        return issues

    def _check_expensive_operations_in_loops(self, tree: ast.Module) -> List[Dict]:
        """
        Check for expensive operations inside loops.

        Args:
            tree: AST of the module to check.

        Returns:
            List of expensive operation issues.
        """
        issues = []
        expensive_operations = self._get_expensive_operations()

        # Find all loops
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                issues.extend(
                    self._check_call_in_loop(node, expensive_operations, tree)
                )

        return issues

    def _check_growing_collections_in_loops(self, tree: ast.Module) -> List[Dict]:
        """Check for collections that grow inside loops."""
        issues = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue

            # Look for collections that grow inside loops
            growing_collections = self._find_growing_collections(node)

            for growing_node, collection_name in growing_collections:
                line = getattr(growing_node, "lineno", 0)
                code = self._get_code_at_line_from_tree(
                    tree, line, f"Operation at line {line}"
                )

                issues.append(
                    {
                        "line": line,
                        "code": code,
                        "suggestion": f"Collection '{collection_name}' grows inside a loop. Consider using a more memory-efficient approach or preallocating if size is known.",
                    }
                )

        return issues

    def _check_file_context_managers(self, tree: ast.Module) -> List[Dict]:
        """Check for file operations without context managers."""
        issues = []

        for node in ast.walk(tree):
            # Skip if not a call to open() or if it's in a with statement
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue

            if node.func.id != "open" or self._is_in_with_statement(node):
                continue

            line = getattr(node, "lineno", 0)
            code = self._get_code_at_line_from_tree(
                tree, line, f"Operation at line {line}"
            )

            issues.append(
                {
                    "line": line,
                    "code": code,
                    "suggestion": "File opened without context manager (with statement). This might lead to unclosed file handles.",
                }
            )

        return issues

    def _check_memory_leaks(self, tree: ast.Module) -> List[Dict]:
        """
        Check for patterns that could lead to memory leaks.

        Args:
            tree: AST of the module to check.

        Returns:
            List of potential memory leak issues.
        """
        issues = []

        # Check for large data structures that grow in loops
        issues.extend(self._check_growing_collections_in_loops(tree))

        # Check for lack of context managers with file handling
        issues.extend(self._check_file_context_managers(tree))

        return issues

    def _find_growing_collections(
        self, loop_node: ast.For
    ) -> List[Tuple[ast.AST, str]]:
        """
        Find collections that grow inside a loop.
            if isinstance(node,
                ast.AugAssign) and isinstance(node.op,
                ast.Add)

        Args:
            elif isinstance(node,
                ast.Call) and isinstance(node.func,
                ast.Attribute)

        Returns:
            List of (node, collection_name) tuples for growing collections.
        """
        growing_collections = []

        # Look for assignments that use +=, append, extend, etc.
        for node in ast.walk(loop_node):
            collection_name = None

            if isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add):
                # Check for += operation on a collection
                if isinstance(node.target, ast.Name):
                    collection_name = node.target.id

            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in [
                    "append",
                    "extend",
                    "update",
                    "add",
                ] and isinstance(node.func.value, ast.Name):
                    collection_name = node.func.value.id

            if collection_name:
                growing_collections.append((node, collection_name))

        return growing_collections

    def _is_in_with_statement(self, node: ast.AST) -> bool:
        """
        Check if a node is inside a with statement.

        Args:
            node: AST node to check.

        Returns:
            True if the node is inside a with statement, False otherwise.
        """
        if isinstance(node, ast.Compare) and any(
            isinstance(op, ast.In) for op in node.ops
        ):
            # This would require tracking the parent structure of the AST
            # For now, return a conservative result to avoid false positives
            return False

    def _is_list_type(self, node: ast.AST) -> bool:
        """Check if a node represents a list type."""
        if isinstance(node, ast.Name):
            return True  # Could be a list variable

        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "list"
        )

    def _check_inefficient_in_operations(self, tree: ast.Module) -> List[Dict]:
        """Check for inefficient 'in' operations on lists."""
        issues = []

        for node in ast.walk(tree):
            # Skip if not a compare operation with 'in'
            if not isinstance(node, ast.Compare) or not any(
                isinstance(op, ast.In) for op in node.ops
            ):
                continue

            # Check if the right side of "in" is a list
            for comparator in node.comparators:
                if not self._is_list_type(comparator):
                    continue

                line = getattr(node, "lineno", 0)
                code = self._get_code_at_line_from_tree(
                    tree, line, f"Operation at line {line}"
                )

                issues.append(
                    {
                        "line": line,
                        "code": code,
                        "suggestion": "Using 'in' operator with a list can be inefficient for large collections. Consider using a set or dictionary for O(1) lookups.",
                    }
                )

        return issues

    def _check_list_concatenation(self, tree: ast.Module) -> List[Dict]:
        """Check for inefficient list concatenation."""
        issues = []

        for node in ast.walk(tree):
            # Skip if not a binary operation with '+'
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Add):
                continue

            # Check if either side is a list
            if not (
                isinstance(node.left, ast.List) or isinstance(node.right, ast.List)
            ):
                continue

            line = getattr(node, "lineno", 0)
            code = self._get_code_at_line_from_tree(
                tree, line, f"Operation at line {line}"
            )

            issues.append(
                {
                    "line": line,
                    "code": code,
                    "suggestion": "List concatenation can be inefficient, especially in loops. Consider using list.extend() or a list comprehension.",
                }
            )

        return issues

    def _check_inefficient_data_structures(self, tree: ast.Module) -> List[Dict]:
        """
        Check for inefficient data structure usage.

        Args:
            tree: AST of the module to check.

        Returns:
            List of data structure issues.
        """
        issues = []

        # Check for inefficient 'in' operations on lists
        issues.extend(self._check_inefficient_in_operations(tree))

        # Check for inefficient list concatenation
        issues.extend(self._check_list_concatenation(tree))

        return issues

    def _get_expensive_functions(self) -> List[str]:
        """Return a list of commonly expensive function names."""
        return [
            "sorted",
            "re.compile",
            "json.loads",
            "json.dumps",
            "pickle.loads",
            "pickle.dumps",
            "subprocess.run",
            "subprocess.Popen",
            "requests.get",
            "requests.post",
            "df.apply",
            "df.iterrows",
        ]

    def _get_function_name(self, node: ast.Call) -> Optional[str]:
        """Extract the full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id

        if isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            return f"{node.func.value.id}.{node.func.attr}"

        return None

    def _collect_expensive_function_calls(
        self, tree: ast.Module
    ) -> Dict[str, List[int]]:
        """Collect all expensive function calls in the AST."""
        function_calls = {}
        expensive_functions = self._get_expensive_functions()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            func_name = self._get_function_name(node)
            if not func_name:
                continue

            # Check if this is an expensive function
            for exp_func in expensive_functions:
                if exp_func in func_name or func_name in exp_func:
                    line = getattr(node, "lineno", 0)
                    if func_name not in function_calls:
                        function_calls[func_name] = []
                    function_calls[func_name].append(line)
                    break  # Found a match, no need to check other expensive functions

        return function_calls

    def _check_if_calls_in_loop(self, tree: ast.Module, call_lines: List[int]) -> bool:
        """Check if any of the function calls are inside a loop."""
        for node in ast.walk(tree):
            if not isinstance(node, (ast.For, ast.While)):
                continue

            loop_lines = {getattr(n, "lineno", 0) for n in ast.walk(node)}
            if any(line in loop_lines for line in call_lines):
                return True

        return False

    def _check_expensive_function_calls(self, tree: ast.Module) -> List[Dict]:
        """
        Check for repeated expensive function calls.

        Args:
            tree: AST of the module to check.

        Returns:
            List of expensive function call issues.
        """
        issues = []
        function_calls = self._collect_expensive_function_calls(tree)

        # Check for repeated calls
        for func_name, lines in function_calls.items():
            if len(lines) <= 1:
                continue  # Skip if only called once

            # Find calls inside loops, which would be more problematic
            is_in_loop = self._check_if_calls_in_loop(tree, lines)

            if is_in_loop:
                severity_msg = " inside loops"
                extra_suggestion = (
                    " Consider moving the call outside the loop or caching its result."
                )
            else:
                severity_msg = ""
                extra_suggestion = " Consider caching its result if called repeatedly with the same arguments."

            issues.append(
                {
                    "line": lines[0],  # Report the first occurrence
                    "code": f"Call to {func_name}",
                    "suggestion": f"Found {len(lines)} calls to expensive function '{func_name}'{severity_msg}.{extra_suggestion}",
                }
            )

        return issues

    def _profile_entry_points(self) -> Dict:
        """
        Profile entry points to measure performance.

        Returns:
            Dictionary with profiling results.
        """
        # Get entry points from the class instance
        if self._project_entry_points is None:
            self._project_entry_points = self._identify_entry_points()

        entry_points = self._project_entry_points
        self.logger.info(f"Profiling {len(entry_points)} entry points")

        profiling_results = {}

        for entry_point in entry_points:
            file_path = entry_point.get("file")
            result_key = f"{file_path}"

            try:
                # Profile the entry point
                if entry_point["type"] == "script":
                    # Profile by importing the module
                    module_name = file_path.replace("/", ".").replace("\\", ".")
                    if module_name.endswith(".py"):
                        module_name = module_name[:-3]

                        # This is a simplified approach for demonstration
                        profiling_results[result_key] = {
                            "status": "skipped",
                            "reason": "Direct script profiling not implemented",
                            "file": file_path,
                        }

                elif entry_point["type"] == "console_script":
                    # Profile console script entry point
                    import_path = entry_point.get("import_path", "")
                    if ":" in import_path:
                        _, _ = import_path.split(":", 1)  # Unpack but don't use
                    elif "." in import_path:
                        # Try to parse the function name but don't use the result yet
                        _, _ = import_path.rsplit(".", 1)

                    profiling_results[result_key] = {
                        "status": "skipped",
                        "reason": "Console script profiling not implemented",
                        "file": file_path,
                        "import_path": import_path,
                    }

            except Exception as e:
                self.logger.error(f"Error profiling {file_path}: {e}")
                profiling_results[result_key] = {
                    "status": "error",
                    "error": str(e),
                    "file": file_path,
                }

        return profiling_results

    def _start_monitoring(self, duration: int) -> None:
        """
        Start monitoring thread for the specified duration.

        Args:
            duration: Duration to monitor in seconds.
        """
        self.logger.info(f"Starting monitoring thread for {duration} seconds")

        # Reset stop flag
        self._stop_monitoring.clear()

        # Start monitoring thread
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, args=(duration,), daemon=True
        )
        self._monitoring_thread.start()

    def _monitoring_loop(self, duration: int) -> None:
        """
        Main monitoring loop.

        Args:
            duration: Duration to monitor in seconds.
        """
        start_time = time.time()
        end_time = start_time + duration

        # Initialize tracemalloc if memory tracking is enabled
        if self.settings["track_memory_usage"]:
            tracemalloc.start()

        try:
            while time.time() < end_time and not self._stop_monitoring.is_set():
                # Collect metrics
                self._collect_metrics()

                # Sleep for a bit
                time.sleep(1)

        finally:
            # Stop tracemalloc if it was started
            if self.settings["track_memory_usage"] and tracemalloc.is_tracing():
                tracemalloc.stop()

    def _collect_metrics(self) -> None:
        """Collect current performance metrics."""
        timestamp = time.time()

        # Collect memory usage if enabled
        if self.settings["track_memory_usage"] and tracemalloc.is_tracing():
            current, peak = tracemalloc.get_traced_memory()

            # Record current memory usage
            self._metrics.append(
                PerformanceMetric(
                    name="memory_usage",
                    value=current / (1024 * 1024),  # Convert to MB
                    unit="MB",
                    timestamp=timestamp,
                    context={"type": "current"},
                )
            )

            # Record peak memory usage
            self._metrics.append(
                PerformanceMetric(
                    name="memory_usage",
                    value=peak / (1024 * 1024),  # Convert to MB
                    unit="MB",
                    timestamp=timestamp,
                    context={"type": "peak"},
                )
            )

            # Record execution time
            self._metrics.append(
                PerformanceMetric(
                    name="execution_time",
                    value=time.time() - timestamp,
                    unit="seconds",
                    timestamp=timestamp,
                    context={"type": "current"},
                )
            )

            # Record peak execution time
            self._metrics.append(
                PerformanceMetric(
                    name="execution_time",
                    value=time.time() - timestamp,
                    unit="seconds",
                    timestamp=timestamp,
                    context={"type": "peak"},
                )
            )

            # Record CPU usage
            self._metrics.append(
                PerformanceMetric(
                    name="cpu_usage",
                    value=100.0,  # Placeholder value
                    unit="%",
                    timestamp=timestamp,
                    context={"type": "current"},
                )
            )

            # Record peak CPU usage
            self._metrics.append(
                PerformanceMetric(
                    name="cpu_usage",
                    value=100.0,  # Placeholder value
                    unit="%",
                    timestamp=timestamp,
                    context={"type": "peak"},
                )
            )

        return self._metrics

    def _analyze_potential_bottlenecks(self) -> List[Dict]:
        """
        Analyze potential performance bottlenecks.

        Returns:
            List of potential performance issues.
        """
        self.logger.info("Analyzing potential performance bottlenecks")

        issues = []
        python_files = self._collect_python_files()
        self._build_ast_cache(python_files)

        for file_path, tree in self._ast_cache.items():
            if nested_loop_issues := self._check_nested_loops(tree):
                issues.extend(nested_loop_issues)

            if expensive_op_issues := self._check_expensive_operations_in_loops(tree):
                issues.extend(expensive_op_issues)

            if memory_leak_issues := self._check_memory_leaks(tree):
                issues.extend(memory_leak_issues)

            if data_structure_issues := self._check_inefficient_data_structures(tree):
                issues.extend(data_structure_issues)

            if function_call_issues := self._check_expensive_function_calls(tree):
                issues.extend(function_call_issues)

        return issues

    def _profile_entry_points(self) -> List[Dict]:
        """
        Profile entry points for performance metrics.

        Returns:
            List of profiling results.
        """
        self.logger.info("Profiling entry points")

        # Get entry points from the class instance
        if self._project_entry_points is None:
            self._project_entry_points = self._identify_entry_points()

        entry_points = self._project_entry_points
        profiling_results = []

        for entry_point in entry_points:
            file_path = entry_point.get("file")
            entry_type = entry_point.get("type")
            result = {"file": file_path, "type": entry_type, "metrics": []}

            # Start profiling
            tracemalloc.start()
            start_time = time.time()

            try:
                # Profile based on entry point type
                # Profile based on entry point type - common implementation for all types
                _, peak = tracemalloc.get_traced_memory()

                # Add memory usage metric
                result["metrics"].append(
                    {
                        "name": "memory_usage",
                        "value": peak / (1024 * 1024),  # Convert to MB
                        "unit": "MB",
                    }
                )

                # Add execution time metric
                result["metrics"].append(
                    {
                        "name": "execution_time",
                        "value": time.time() - start_time,
                        "unit": "seconds",
                    }
                )
            except Exception as e:
                self.logger.error(f"Error profiling {file_path}: {str(e)}")
                result["error"] = str(e)
            finally:
                # Stop profiling
                tracemalloc.stop()

            profiling_results.append(result)

        return profiling_results

    def _generate_summary(self) -> str:
        """
        Generate a summary of the performance metrics.

        Returns:
            Summary of performance metrics.
        """
        self.logger.info("Generating summary")

        if not self._metrics:
            return "No performance metrics collected."

        # Group metrics by name
        metrics_by_name = {}
        for metric in self._metrics:
            name = metric.name
            if name not in metrics_by_name:
                metrics_by_name[name] = []
            metrics_by_name[name].append(metric)

        # Generate summary text
        summary_lines = ["Performance Metrics Summary:"]

        # Process memory usage metrics
        if "memory_usage" in metrics_by_name:
            memory_metrics = metrics_by_name["memory_usage"]
            peak_memory = max(
                m.value for m in memory_metrics if m.context.get("type") == "peak"
            )
            summary_lines.append(f"  Peak Memory Usage: {peak_memory:.2f} MB")

        # Process execution time metrics
        if "execution_time" in metrics_by_name:
            time_metrics = metrics_by_name["execution_time"]
            total_time = sum(
                m.value for m in time_metrics if m.context.get("type") == "current"
            )
            summary_lines.append(f"  Total Execution Time: {total_time:.2f} seconds")

        # Process CPU usage metrics
        if "cpu_usage" in metrics_by_name:
            cpu_metrics = metrics_by_name["cpu_usage"]
            avg_cpu = sum(m.value for m in cpu_metrics) / len(cpu_metrics)
            summary_lines.append(f"  Average CPU Usage: {avg_cpu:.2f}%")

        return "\n".join(summary_lines)

    def _start_monitoring(self, duration: int) -> None:
        """
        Start monitoring performance metrics.

        Args:
            duration: Duration to monitor in seconds.
        """
        self.logger.info(f"Starting monitoring for {duration} seconds")

        # Reset stop event
        self._stop_monitoring_event = threading.Event()

        # Create and start monitoring thread
        self._monitoring_thread = threading.Thread(
            target=self._monitoring_loop, args=(duration,), daemon=True
        )
        self._monitoring_thread.start()

    def _stop_monitoring(self) -> None:
        """
        Stop monitoring performance metrics.
        """
        self.logger.info("Stopping monitoring")
        self._stop_monitoring_event.set()
        if self._monitoring_thread:
            self._monitoring_thread.join()

    def _generate_report(self) -> str:
        """
        Generate a report of the performance metrics.

        Returns:
            Detailed report of performance metrics.
        """
        self.logger.info("Generating performance report")

        if not self._metrics:
            return "No performance metrics collected."

        # Add summary section
        summary = self._generate_summary()
        sections = [
            "# Performance Monitoring Report",
            "## Summary",
            summary,
            "\n## Detailed Metrics",
        ]

        # Group metrics by name and type
        metrics_by_category = {}
        for metric in self._metrics:
            category = f"{metric.name}:{metric.context.get('type', 'default')}"
            if category not in metrics_by_category:
                metrics_by_category[category] = []
            metrics_by_category[category].append(metric)

        # Add each category of metrics
        for category, metrics in metrics_by_category.items():
            name, metric_type = (
                category.split(":") if ":" in category else (category, "default")
            )
            sections.append(f"### {name.title()} ({metric_type})")

            if values := [m.value for m in metrics]:
                avg_value = sum(values) / len(values)
                min_value = min(values)
                max_value = max(values)
                unit = metrics[0].unit

                sections.extend(
                    [
                        f"- Average: {avg_value:.2f} {unit}",
                        f"- Minimum: {min_value:.2f} {unit}",
                        f"- Maximum: {max_value:.2f} {unit}",
                        f"- Samples: {len(values)}",
                    ]
                )

        # Add recommendations section based on metrics
        sections.append("\n## Recommendations")
        if recommendations := self._generate_recommendations():
            sections.extend(recommendations)
        else:
            sections.append("No specific recommendations at this time.")

        return "\n\n".join(sections)

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on collected metrics."""
        recommendations = []

        if memory_metrics := [
            m
            for m in self._metrics
            if m.name == "memory_usage" and m.context.get("type") == "peak"
        ]:
            peak_memory = max(m.value for m in memory_metrics)
            threshold = self.settings.get("memory_usage_threshold", 100)  # MB
            if peak_memory > threshold:
                recommendations.append(
                    f"- **High Memory Usage**: Peak memory usage ({peak_memory:.2f} MB) exceeds threshold ({threshold} MB). Consider optimizing memory-intensive operations."
                )

        if time_metrics := [m for m in self._metrics if m.name == "execution_time"]:
            total_time = sum(
                m.value for m in time_metrics if m.context.get("type") == "current"
            )
            threshold = self.settings.get("execution_time_threshold", 1.0)  # seconds
            if total_time > threshold:
                recommendations.append(
                    f"- **Long Execution Time**: Total execution time ({total_time:.2f} seconds) exceeds threshold ({threshold} seconds). Consider optimizing time-intensive operations."
                )

        return recommendations

    def _monitoring_loop(self, duration: int) -> None:
        """
        Main monitoring loop.

        Args:
            duration: Duration to monitor in seconds.
        """
        self.logger.info(f"Monitoring loop started for {duration} seconds")

        start_time = time.time()
        interval = 1.0  # Sample every second

        try:
            while time.time() - start_time < duration:
                if (
                    hasattr(self, "_stop_monitoring_event")
                    and self._stop_monitoring_event.is_set()
                ):
                    self.logger.info("Monitoring loop stopped by request")
                    break

                # Collect metrics
                self._collect_metrics()

                # Sleep for the interval
                time.sleep(interval)

        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {str(e)}")
        finally:
            self.logger.info("Monitoring loop finished")
