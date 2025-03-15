"""
Import Enforcer Module for PS2.

This module enforces consistent import patterns in Python projects,
preventing issues like circular imports and ensuring proper organization
of imports according to project standards.
"""


import ast
import contextlib
import os
import re
import logging
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional, Union

import networkx as nx


class ImportEnforcer:
    """
    Enforcer for Python import standards.

    This class analyzes and enforces consistent import patterns, prevents
    circular imports, and ensures proper organization of imports according
    to project standards.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the import enforcer.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the enforcer.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.import_enforcer")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "prefer_absolute_imports": True,
            "enforce_import_order": True,
            "enforce_import_grouping": True,
            "disallow_star_imports": True,
            "max_import_line_length": 79,
        }

        # Apply config settings
        self.settings = {
            **self.default_settings,
            **self.config.get("import_enforcer", {}),
        }

        # Cache for module graph
        self._module_graph = None
        self._ast_cache = {}

    def enable(self) -> None:
        """Enable the import enforcer."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the import enforcer."""
        self.enabled = False

    def enforce(self, fix: bool = False) -> Dict:
        """
        Enforce import standards.

        Args:
            fix: Whether to automatically fix import issues.

        Returns:
            Dictionary with enforcement results.
        """
        if not self.enabled:
            self.logger.warning("Import enforcer is disabled. Enabling for this run.")
            self.enable()

        self.logger.info(f"Enforcing import standards (fix: {fix})")

        # Collect Python files
        python_files = self._collect_python_files()

        # Build AST cache
        self._build_ast_cache(python_files)

        # Build module graph
        self._build_module_graph()

        # Check for circular imports
        circular_imports = self._detect_circular_imports()

        # Check for import standards compliance
        import_issues = self._check_import_standards()

        # Fix import issues if requested
        fixed_files = []
        if fix and import_issues:
            fixed_files = self._fix_import_issues(import_issues)

        # Build result
        result = {
            "files_checked": len(python_files),
            "circular_imports": circular_imports,
            "import_issues": import_issues,
            "fixed_files": fixed_files,
        }

        # Determine overall status
        if circular_imports or (import_issues and not fix):
            result["status"] = "fail"
        elif import_issues:
            result["status"] = "fixed"
        else:
            result["status"] = "pass"

        return result

    def _collect_python_files(self) -> List[Path]:
        """
        Collect all Python files in the project.

        Returns:
            List of paths to Python files.
        """
        python_files = []
        exclude_patterns = self.config.get("analyzer", {}).get("exclude_patterns", [])

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

    def _build_module_graph(self) -> None:
        """
        Build a directed graph of module dependencies.
        """
        self.logger.info("Building module dependency graph")

        # Create a directed graph
        G = nx.DiGraph()

        # Add nodes and edges for each module and its imports
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)
            G.add_node(module_name)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        imported_name = name.name
                        if self._is_internal_module(imported_name):
                            G.add_edge(module_name, imported_name)

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        module_source = node.module
                        if self._is_internal_module(module_source):
                            G.add_edge(module_name, module_source)

        self._module_graph = G

    def _detect_circular_imports(self) -> List[List[str]]:
        """
        Detect circular import dependencies.

        Returns:
            List of circular import chains.
        """
        self.logger.info("Detecting circular imports")

        if not self._module_graph:
            self._build_module_graph()

        # Find all simple cycles in the graph
        try:
            cycles = list(nx.simple_cycles(self._module_graph))

            # Sort cycles for consistent output
            sorted_cycles = []
            for cycle in cycles:
                # Rotate cycle to start with alphabetically earliest module
                min_idx = cycle.index(min(cycle))
                sorted_cycle = cycle[min_idx:] + cycle[:min_idx]
                sorted_cycles.append(sorted_cycle)

            # Sort the list of cycles
            sorted_cycles.sort(key=lambda x: (len(x), x[0]))

            return sorted_cycles
        except nx.NetworkXNoCycle:
            return []

    def _check_import_standards(self) -> Dict[str, List[Dict]]:
        """
        Check compliance with import standards.

        Returns:
            Dictionary mapping file paths to lists of import issues.
        """
        self.logger.info("Checking import standards compliance")

        issues = {}

        for file_path, tree in self._ast_cache.items():
            file_issues = []

            # Check for star imports
            if self.settings["disallow_star_imports"]:
                file_issues.extend(
                    {
                        "type": "star_import",
                        "line": node.lineno,
                        "message": f"Star import from {node.module}",
                        "node": node,
                    }
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                    and any(name.name == "*" for name in node.names)
                )
            # Check for relative vs absolute imports
            if self.settings["prefer_absolute_imports"]:
                file_issues.extend(
                    {
                        "type": "relative_import",
                        "line": node.lineno,
                        "message": f"Relative import: {'.' * node.level}{node.module or ''}",
                        "node": node,
                    }
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom) and node.level > 0
                )
            # Check for import order and grouping
            if (
                self.settings["enforce_import_order"]
                or self.settings["enforce_import_grouping"]
            ):
                order_issues = self._check_import_order(tree)
                file_issues.extend(order_issues)

            # Check for long import lines
            if self.settings["max_import_line_length"] > 0:
                for node in ast.walk(tree):
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        # Get the line of code
                        with contextlib.suppress(AttributeError, IndexError):
                            if hasattr(tree, "source_code"):
                                lines = tree.source_code.splitlines()
                                line_number = (
                                    node.lineno - 1
                                )  # ast is 1-indexed, list is 0-indexed
                                if line_number < len(lines):
                                    line = lines[line_number]
                                    if (
                                        len(line)
                                        > self.settings["max_import_line_length"]
                                    ):
                                        file_issues.append(
                                            {
                                                "type": "long_import",
                                                "line": node.lineno,
                                                "message": f"Import line too long: {len(line)} > {self.settings['max_import_line_length']}",
                                                "node": node,
                                            }
                                        )
            if file_issues:
                issues[str(file_path)] = file_issues

        return issues

    def _check_import_order(self, tree: ast.Module) -> List[Dict]:
        """
        Check if imports are properly ordered and grouped.

        Args:
            tree: AST of the module to check.

        Returns:
            List of import order issues.
        """
        issues = []

        import_nodes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        # Sort import nodes by line number
        import_nodes.sort(key=lambda x: x.lineno)

        # Group imports by type
        std_lib_imports = []
        third_party_imports = []
        local_imports = []
        relative_imports = []

        for node in import_nodes:
            if isinstance(node, ast.Import):
                module_name = node.names[0].name.split(".")[0]
                if self._is_stdlib_module(module_name):
                    std_lib_imports.append(node)
                elif self._is_internal_module(module_name):
                    local_imports.append(node)
                else:
                    third_party_imports.append(node)
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    relative_imports.append(node)
                else:
                    module_name = node.module.split(".")[0] if node.module else ""
                    if self._is_stdlib_module(module_name):
                        std_lib_imports.append(node)
                    elif self._is_internal_module(module_name):
                        local_imports.append(node)
                    else:
                        third_party_imports.append(node)

        if self.settings["enforce_import_grouping"]:
            if expected_order := (
                std_lib_imports
                + third_party_imports
                + local_imports
                + relative_imports
            ):
                for i in range(1, len(expected_order)):
                    if expected_order[i].lineno - expected_order[i - 1].lineno > 1:
                        # This is a gap, which is fine
                        continue

                    # Check if this node is from a different group than the previous
                    prev_group = self._get_import_group(expected_order[i - 1])
                    curr_group = self._get_import_group(expected_order[i])

                    if prev_group != curr_group:
                        issues.append(
                            {
                                "type": "missing_group_separation",
                                "line": expected_order[i].lineno,
                                "message": f"Missing empty line between {prev_group} and {curr_group} imports",
                                "node": expected_order[i],
                            }
                        )

        # Check if imports are properly ordered
        if self.settings["enforce_import_order"]:
            # Check order within each group
            for group in [
                std_lib_imports,
                third_party_imports,
                local_imports,
                relative_imports,
            ]:
                sorted_group = sorted(group, key=self._get_import_sort_key)

                for i, node in enumerate(group):
                    sorted_node = sorted_group[i]
                    if self._get_import_sort_key(node) != self._get_import_sort_key(
                        sorted_node
                    ):
                        issues.append(
                            {
                                "type": "improper_import_order",
                                "line": node.lineno,
                                "message": "Import not in alphabetical order",
                                "node": node,
                            }
                        )

        return issues

    def _fix_import_issues(self, issues: Dict[str, List[Dict]]) -> List[str]:
        """
        Fix import issues in the codebase.

        Args:
            issues: Dictionary mapping file paths to lists of import issues.

        Returns:
            List of fixed file paths.
        """
        self.logger.info("Fixing import issues")

        fixed_files = []

        for file_path_str, file_issues in issues.items():
            file_path = Path(file_path_str)

            # Skip files that don't exist
            if not file_path.exists():
                continue

            # Read file content
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # This would be a complex operation that requires careful handling
            # of the source code. For now, we'll use isort which is a specialized
            # tool for this purpose.

            # Use isort to fix import issues
            try:
                import isort

                # Configure isort settings based on project preferences
                isort_config = {
                    "line_length": self.settings["max_import_line_length"],
                    "use_parentheses": True,
                    "multi_line_output": 3,  # Vertical hanging indent
                    "include_trailing_comma": True,
                }

                # Apply fixes
                sorted_content = isort.code(content, **isort_config)

                # Write back to file if changes were made
                if sorted_content != content:
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(sorted_content)

                    fixed_files.append(str(file_path))
                    self.logger.info(f"Fixed imports in {file_path}")
            except ImportError:
                self.logger.warning("isort not available for fixing imports")
                # We could implement a basic fix here, but isort handles edge cases better
            except Exception as e:
                self.logger.error(f"Error fixing imports in {file_path}: {e}")

        return fixed_files

    def _get_module_name(self, file_path: Path) -> str:
        """
        Get the Python module name from a file path.

        Args:
            file_path: Path to a Python file.

        Returns:
            Module name as a string.
        """
        relative_path = file_path.relative_to(self.project_path)
        parts = list(relative_path.parts)
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]

        # Skip __init__.py files for package names
        if parts[-1] == "__init__":
            parts.pop()

        return ".".join(parts)

    def _is_internal_module(self, module_name: str) -> bool:
        """
        Check if a module name refers to an internal project module.

        Args:
            module_name: Name of the module.

        Returns:
            True if internal, False if external.
        """
        # First check obvious external modules
        if self._is_stdlib_module(module_name):
            return False

        # Check if the module exists in our project
        module_path = self.project_path / module_name.replace(".", os.sep)
        return bool(
            (
                module_path.exists()
                or (module_path.parent / f"{module_path.name}.py").exists()
            )
        )

    def _is_stdlib_module(self, module_name: str) -> bool:
        """
        Check if a module name refers to a standard library module.

        Args:
            module_name: Name of the module.

        Returns:
            True if stdlib, False otherwise.
        """
        # This is a simplified check, could be more comprehensive
        stdlib_modules = {
            "abc",
            "argparse",
            "ast",
            "asyncio",
            "base64",
            "collections",
            "contextlib",
            "copy",
            "csv",
            "datetime",
            "decimal",
            "difflib",
            "enum",
            "functools",
            "glob",
            "hashlib",
            "http",
            "importlib",
            "inspect",
            "io",
            "itertools",
            "json",
            "logging",
            "math",
            "os",
            "pathlib",
            "pickle",
            "random",
            "re",
            "shutil",
            "socket",
            "sqlite3",
            "statistics",
            "string",
            "subprocess",
            "sys",
            "tempfile",
            "threading",
            "time",
            "timeit",
            "tkinter",
            "traceback",
            "typing",
            "unittest",
            "urllib",
            "uuid",
            "warnings",
            "xml",
            "zipfile",
        }

        return module_name in stdlib_modules

    def _get_import_group(self, node: Union[ast.Import, ast.ImportFrom]) -> str:
        """
        Get the group name for an import node.

        Args:
            node: Import node to categorize.

        Returns:
            Group name ('stdlib', 'third-party', 'local', or 'relative').
        """
        if isinstance(node, ast.Import):
            module_name = node.names[0].name.split(".")[0]
            if self._is_stdlib_module(module_name):
                return "stdlib"
            elif self._is_internal_module(module_name):
                return "local"
            else:
                return "third-party"
        elif isinstance(node, ast.ImportFrom):
            if node.level > 0:
                return "relative"
            module_name = node.module.split(".")[0] if node.module else ""
            if self._is_stdlib_module(module_name):
                return "stdlib"
            elif self._is_internal_module(module_name):
                return "local"
            else:
                return "third-party"

        return "unknown"

    def _get_import_sort_key(self, node: Union[ast.Import, ast.ImportFrom]) -> Tuple:
        """
        Get a sort key for an import node.

        Args:
            node: Import node to get sort key for.

        Returns:
            Tuple that can be used for sorting imports.
        """
        if isinstance(node, ast.Import):
            return (0, node.names[0].name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            return (1, node.level, module, node.names[0].name)
        else:
            return (99, "circular_imports")