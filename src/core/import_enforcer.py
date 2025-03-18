"""
Import Enforcer Module for PS2.

This module enforces consistent import patterns in Python projects,
preventing issues like circular imports and ensuring proper organization
of imports according to project standards.
"""

import ast
import contextlib
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Union, Any

import isort
import networkx as nx


class ImportEnforcer:
    """
    Enforcer for Python import standards.
from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
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
        exclude_patterns = self.config.get("analyzer",
            {}).get("exclude_patterns",
            [])

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

    def _process_import_node(self, graph: nx.DiGraph, module_name: str, node: ast.Import) -> None:
        """Process an Import node and add edges to the graph."""
        for name in node.names:
            imported_name = name.name
            if self._is_internal_module(imported_name):
                graph.add_edge(module_name, imported_name)
                
    def _process_import_from_node(self, graph: nx.DiGraph, module_name: str, node: ast.ImportFrom) -> None:
        """Process an ImportFrom node and add edges to the graph."""
        if not node.module:
            return
            
        if self._is_internal_module(node.module):
            graph.add_edge(module_name, node.module)
    
    def _build_module_graph(self) -> None:
        """
        Build a directed graph of module dependencies.
        """
        self.logger.info("Building module dependency graph")

        # Create a directed graph
        graph = nx.DiGraph()

        # Add nodes and edges for each module and its imports
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)
            graph.add_node(module_name)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    self._process_import_node(graph, module_name, node)
                elif isinstance(node, ast.ImportFrom):
                    self._process_import_from_node(graph, module_name, node)

        self._module_graph = graph

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

    def _check_star_imports(self, tree: ast.Module) -> List[Dict]:
        """Check for star imports in the AST."""
        if not self.settings["disallow_star_imports"]:
            return []
            
        return [
            {
                "type": "star_import",
                "line": node.lineno,
                "message": f"Star import from {node.module}",
                "node": node,
            }
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and any(name.name == "*" for name in node.names)
        ]
    
    def _check_relative_imports(self, tree: ast.Module) -> List[Dict]:
        """Check for relative imports in the AST."""
        if not self.settings["prefer_absolute_imports"]:
            return []
            
        return [
            {
                "type": "relative_import",
                "line": node.lineno,
                "message": f"Relative import: {'.' * node.level}{node.module or ''}",
                "node": node,
            }
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level > 0
        ]
    
    def _check_long_import_lines(self, tree: ast.Module) -> List[Dict]:
        """Check for import lines that exceed the maximum length."""
        issues = []
        
        if self.settings["max_import_line_length"] <= 0:
            return issues
            
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
                
            # Get the line of code
            if not hasattr(tree, "source_code"):
                continue
                
            with contextlib.suppress(AttributeError, IndexError):
                lines = tree.source_code.splitlines()
                line_number = node.lineno - 1  # ast is 1-indexed, list is 0-indexed
                
                if line_number >= len(lines):
                    continue
                    
                line = lines[line_number]
                if len(line) > self.settings["max_import_line_length"]:
                    issues.append({
                        "type": "long_import",
                        "line": node.lineno,
                        "message": f"Import line too long: {len(line)} > {self.settings['max_import_line_length']}",
                        "node": node,
                    })
                    
        return issues
    
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

            # Check for various import issues
            file_issues.extend(self._check_star_imports(tree))
            file_issues.extend(self._check_relative_imports(tree))
            
            # Check for import order and grouping
            if (self.settings["enforce_import_order"] or 
                self.settings["enforce_import_grouping"]):
                file_issues.extend(self._check_import_order(tree))

            # Check for long import lines
            file_issues.extend(self._check_long_import_lines(tree))
            
            if file_issues:
                issues[str(file_path)] = file_issues

        return issues

    def _categorize_stdlib_or_internal(self, module_name: str) -> str:
        """Determine if a module is stdlib, internal, or third-party."""
        if self._is_stdlib_module(module_name):
            return "stdlib"
        return "local" if self._is_internal_module(module_name) else "third_party"
    
    def _categorize_import_node(self, node: ast.AST) -> str:
        """Categorize an import node into one of the import groups."""
        if isinstance(node, ast.Import):
            module_name = node.names[0].name.split(".")[0]
            return self._categorize_stdlib_or_internal(module_name)
            
        if isinstance(node, ast.ImportFrom):
            if node.level > 0:
                return "relative"
            
            # If we reach here, it's a non-relative import from
            module_name = node.module.split(".")[0] if node.module else ""
            return self._categorize_stdlib_or_internal(module_name)
            
        return "unknown"
    
    def _group_imports(self, import_nodes: List[ast.AST]) -> Dict[str, List[ast.AST]]:
        """Group import nodes by their category."""
        groups = {
            "stdlib": [],
            "third_party": [],
            "local": [],
            "relative": []
        }
        
        for node in import_nodes:
            category = self._categorize_import_node(node)
            if category in groups:
                groups[category].append(node)
                
        return groups
    
    def _check_group_separation(self, ordered_imports: List[ast.AST]) -> List[Dict]:
        """Check if import groups are properly separated by empty lines."""
        issues = []
        
        if not self.settings["enforce_import_grouping"] or not ordered_imports:
            return issues
            
        for i in range(1, len(ordered_imports)):
            # Skip if there's already a gap
            if ordered_imports[i].lineno - ordered_imports[i - 1].lineno > 1:
                continue

            # Check if this node is from a different group than the previous
            prev_group = self._get_import_group(ordered_imports[i - 1])
            curr_group = self._get_import_group(ordered_imports[i])

            if prev_group != curr_group:
                issues.append({
                    "type": "missing_group_separation",
                    "line": ordered_imports[i].lineno,
                    "message": f"Missing empty line between {prev_group} and {curr_group} imports",
                    "node": ordered_imports[i],
                })
                
        return issues
    
    def _check_alphabetical_order(self, import_groups: Dict[str, List[ast.AST]]) -> List[Dict]:
        """Check if imports within each group are in alphabetical order."""
        issues = []
        
        if not self.settings["enforce_import_order"]:
            return issues
            
        for group in import_groups.values():
            sorted_group = sorted(group, key=self._get_import_sort_key)
            
            for i, node in enumerate(group):
                sorted_node = sorted_group[i]
                if self._get_import_sort_key(node) != self._get_import_sort_key(sorted_node):
                    issues.append({
                        "type": "improper_import_order",
                        "line": node.lineno,
                        "message": "Import not in alphabetical order",
                        "node": node,
                    })
                    
        return issues
    
    def _check_import_order(self, tree: ast.Module) -> List[Dict]:
        """
        Check if imports are properly ordered and grouped.

        Args:
            tree: AST of the module to check.

        Returns:
            List of import order issues.
        """
        # Get all import nodes sorted by line number
        import_nodes = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        import_nodes.sort(key=lambda x: x.lineno)
        
        # Group imports by type
        import_groups = self._group_imports(import_nodes)
        
        # Create the expected order of all imports
        ordered_imports = (
            import_groups["stdlib"] +
            import_groups["third_party"] +
            import_groups["local"] +
            import_groups["relative"]
        )
        
        # Check for issues
        issues = []
        issues.extend(self._check_group_separation(ordered_imports))
        issues.extend(self._check_alphabetical_order(import_groups))
        
        return issues

    def _configure_isort_settings(self) -> Dict[str, Any]:
        """Configure isort settings based on project preferences."""
        return {
            "line_length": self.settings["max_import_line_length"],
            "use_parentheses": True,
            "multi_line_output": 3,  # Vertical hanging indent
            "include_trailing_comma": True,
        }
        
    def _apply_isort_to_file(self, file_path: Path, content: str) -> Tuple[bool, str]:
        """Apply isort to file content and return whether changes were made."""
        try:
            isort_config = self._configure_isort_settings()
            sorted_content = isort.code(content, **isort_config)
            return sorted_content != content, sorted_content
        except ImportError:
            self.logger.warning("isort not available for fixing imports")
            return False, content
        except Exception as e:
            self.logger.error(f"Error applying isort to {file_path}: {e}")
            return False, content
    
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
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception as e:
                self.logger.error(f"Error reading file {file_path}: {e}")
                continue

            # Apply isort to fix import issues
            changes_made, sorted_content = self._apply_isort_to_file(file_path, content)
            
            if not changes_made:
                continue
                
            # Write back to file if changes were made
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(sorted_content)
                fixed_files.append(str(file_path))
                self.logger.info(f"Fixed imports in {file_path}")
            except Exception as e:
                self.logger.error(f"Error writing to file {file_path}: {e}")

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
        return "third-party"

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