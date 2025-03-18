"""
Code Analyzer Module for PS2.

This module provides comprehensive code analysis capabilities, allowing
PS2 to understand the codebase structure, identify patterns, and generate
insights that power other PS2 features.
"""

import ast
import logging
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple, Union

import networkx as nx


class CodeAnalyzer:
    """
    Analyzer for Python codebases.

    This class provides tools to analyze Python code structure, dependencies,
    and complexity, enabling PS2 to make informed decisions about code quality
    improvements and best practices enforcement.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the code analyzer.

        Args:
            project_path: Path to the Python project to analyze.
            config: Configuration dictionary for the analyzer.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.analyzer")
        self.enabled = False

        # Analysis results cache
        self._module_graph = None
        self._complexity_metrics = None
        self._ast_cache = {}
        self._import_structure = None
        self._name_registry = None

    def enable(self) -> None:
        """Enable the analyzer."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the analyzer."""
        self.enabled = False

    def analyze(self) -> Dict:
        """
        Perform a comprehensive analysis of the codebase.

        Returns:
            Dictionary containing analysis results.
        """
        if not self.enabled:
            self.logger.warning("Analyzer is disabled. Enabling for this run.")
            self.enable()

        self.logger.info(f"Analyzing codebase at: {self.project_path}")

        # Collect all Python files
        python_files = self._collect_python_files()

        # Build AST for each file
        self._build_ast_cache(python_files)

        # Analyze imports and dependencies
        import_structure = self._analyze_imports()

        # Analyze code complexity
        complexity_metrics = self._analyze_complexity()

        # Analyze naming patterns
        name_registry = self._analyze_naming()

        # Analyze module structure
        module_structure = self._analyze_module_structure()

        # Analyze code patterns
        code_patterns = self._analyze_code_patterns()

        # Analyze test coverage (if available)
        test_coverage = self._analyze_test_coverage()

        # Assemble and return results
        return {
            "files_analyzed": len(python_files),
            "import_structure": import_structure,
            "complexity_metrics": complexity_metrics,
            "naming": name_registry,
            "module_structure": module_structure,
            "code_patterns": code_patterns,
            "test_coverage": test_coverage,
            "summary": self._generate_summary(
                python_files,
                import_structure,
                complexity_metrics,
                name_registry,
                module_structure,
                test_coverage,
            ),
        }

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
                self._ast_cache[file_path] = ast.parse(source, filename=str(file_path))
            except (SyntaxError, UnicodeDecodeError) as e:
                self.logger.warning(f"Failed to parse {file_path}: {e}")

    def _analyze_imports(self) -> Dict:
        """
        Analyze import patterns in the codebase.

        Returns:
            Dictionary with import analysis results.
        """
        self.logger.info("Analyzing import patterns")

        result = {
            "module_dependencies": defaultdict(set),
            "external_dependencies": defaultdict(set),
            "import_counts": Counter(),
            "circular_dependencies": [],
        }

        # Create a directed graph for module dependencies
        graph = nx.DiGraph()

        # Process each file's imports
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)
            graph.add_node(module_name)
            self._process_file_imports(tree, module_name, result, graph)

        # Store module graph for other analyses
        self._module_graph = graph

        # Find circular dependencies
        self._find_circular_dependencies(result, graph)

        # Convert sets to lists for JSON serialization
        return result

    def _process_file_imports(
        self, tree: ast.AST, module_name: str, result: Dict, graph: nx.DiGraph
    ) -> None:
        """
        Process imports in a single file.

        Args:
            tree: AST of the file
            module_name: Name of the module being processed
            result: Dictionary to store results
            graph: Dependency graph
        """
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._process_import_node(node, module_name, result, graph)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self._process_importfrom_node(node, module_name, result, graph)

    def _process_import_node(
        self, node: ast.Import, module_name: str, result: Dict, graph: nx.DiGraph
    ) -> None:
        """
        Process an Import node.

        Args:
            node: Import node
            module_name: Name of the module being processed
            result: Dictionary to store results
            graph: Dependency graph
        """
        for name in node.names:
            imported_name = name.name
            result["import_counts"][imported_name] += 1
            self._add_dependency(module_name, imported_name, result, graph)

    def _process_importfrom_node(
        self, node: ast.ImportFrom, module_name: str, result: Dict, graph: nx.DiGraph
    ) -> None:
        """
        Process an ImportFrom node.

        Args:
            node: ImportFrom node
            module_name: Name of the module being processed
            result: Dictionary to store results
            graph: Dependency graph
        """
        module_source = node.module
        result["import_counts"][module_source] += 1
        self._add_dependency(module_name, module_source, result, graph)

    def _add_dependency(
        self, module_name: str, imported_name: str, result: Dict, graph: nx.DiGraph
    ) -> None:
        """
        Add a dependency between modules.

        Args:
            module_name: Name of the importing module
            imported_name: Name of the imported module
            result: Dictionary to store results
            graph: Dependency graph
        """
        if self._is_internal_module(imported_name):
            result["module_dependencies"][module_name].add(imported_name)
            graph.add_edge(module_name, imported_name)
        else:
            result["external_dependencies"][module_name].add(imported_name)

    def _find_circular_dependencies(self, result: Dict, graph: nx.DiGraph) -> None:
        """
        Find circular dependencies in the module graph.

        Args:
            result: Dictionary to store results
            graph: Dependency graph
        """
        try:
            result["circular_dependencies"] = list(nx.simple_cycles(graph))
        except nx.NetworkXNoCycle:
            result["circular_dependencies"] = []

    def _prepare_result_for_serialization(self, result: Dict) -> None:
        """
        Convert sets to lists for JSON serialization.

        Args:
            result: Dictionary to prepare
        """
        result["module_dependencies"] = {
            k: list(v) for k, v in result["module_dependencies"].items()
        }
        result["external_dependencies"] = {
            k: list(v) for k, v in result["external_dependencies"].items()
        }

        self._import_structure = result
        return result

    def _analyze_complexity(self) -> Dict:
        """
        Analyze code complexity metrics.

        Returns:
            Dictionary with complexity analysis results.
        """
        self.logger.info("Analyzing code complexity")

        result = {
            "cyclomatic_complexity": {},
            "function_lengths": {},
            "class_counts": {},
            "function_counts": {},
            "line_counts": {},
            "comment_ratios": {},
        }

        for file_path, tree in self._ast_cache.items():
            relative_path = file_path.relative_to(self.project_path)
            str_path = str(relative_path)

            # Process classes and functions
            self._process_classes_and_functions(tree, result, str_path)

            # Process line counts and comments
            self._process_line_counts(file_path, result, str_path)

        self._complexity_metrics = result
        return result

    def _process_classes_and_functions(
        self, tree: ast.AST, result: Dict, path_str: str
    ) -> None:
        """
        Count classes and functions and calculate complexity metrics.

        Args:
            tree: AST of the file
            result: Dictionary to store results
            path_str: String representation of the relative path
        """
        # Count classes and functions
        classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        functions = [
            node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
        ]

        result["class_counts"][path_str] = len(classes)
        result["function_counts"][path_str] = len(functions)

        # Calculate complexity metrics for functions
        file_complexity, function_lengths = self._calculate_function_metrics(functions)

        result["cyclomatic_complexity"].update(file_complexity)
        result["function_lengths"].update(function_lengths)

    def _calculate_function_metrics(
        self, functions: List[ast.FunctionDef]
    ) -> Tuple[Dict[str, int], Dict[str, int]]:
        """
        Calculate cyclomatic complexity and length for each function.

        Args:
            functions: List of function nodes

        Returns:
            Tuple of (complexity_dict, length_dict)
        """
        file_complexity = {}
        function_lengths = {}

        for func in functions:
            func_name = self._get_qualified_function_name(func)
            complexity = self._calculate_cyclomatic_complexity(func)

            file_complexity[func_name] = complexity
            function_lengths[func_name] = len(func.body)

        return file_complexity, function_lengths

    def _get_qualified_function_name(self, func: ast.FunctionDef) -> str:
        """
        Get the qualified name of a function (including class name if applicable).

        Args:
            func: Function node

        Returns:
            Qualified function name
        """
        return func.name

    def _count_control_structures(self, node: ast.AST) -> int:
        """
        Count control structures that add to cyclomatic complexity.

        Args:
            node: AST node to check

        Returns:
            Complexity increment for this node
        """
        if isinstance(
            node, (ast.If, ast.While, ast.For, ast.And, ast.Or, ast.ExceptHandler)
        ):
            return 1
        return 0

    def _count_boolean_operations(self, node: ast.AST) -> int:
        """
        Count boolean operations that add to cyclomatic complexity.

        Args:
            node: AST node to check

        Returns:
            Complexity increment for boolean operations
        """
        return len(node.values) - 1 if isinstance(node, ast.BoolOp) else 0

    def _calculate_cyclomatic_complexity(self, func: ast.FunctionDef) -> int:
        """
        Calculate cyclomatic complexity for a function.

        Args:
            func: Function node

        Returns:
            Cyclomatic complexity score
        """
        complexity = 1  # Base complexity

        # Increment for each control structure and boolean operation
        for node in ast.walk(func):
            complexity += self._count_control_structures(node)
            complexity += self._count_boolean_operations(node)

        return complexity

    def _count_file_lines(self, file_path: Path) -> tuple[int, int]:
        """
        Count total lines and comment lines in a file.

        Args:
            file_path: Path to the file

        Returns:
            Tuple of (total_lines, comment_lines)

        Raises:
            IOError: If the file cannot be read
            UnicodeDecodeError: If the file encoding is invalid
        """
        with open(file_path, "r", encoding="utf-8") as f:
            source_lines = f.readlines()

        total_lines = len(source_lines)
        comment_lines = sum(bool(line.strip().startswith("#")) for line in source_lines)

        return total_lines, comment_lines

    def _calculate_comment_ratio(self, total_lines: int, comment_lines: int) -> float:
        """
        Calculate the ratio of comment lines to total lines.

        Args:
            total_lines: Total number of lines in the file
            comment_lines: Number of comment lines in the file

        Returns:
            Comment ratio as a float between 0 and 1
        """
        return round(comment_lines / total_lines, 2) if total_lines > 0 else 0

    def _process_line_counts(
        self, file_path: Path, result: Dict, path_str: str
    ) -> None:
        """
        Count total lines and comment lines in a file.

        Args:
            file_path: Path to the file
            result: Dictionary to store results
            path_str: String representation of the relative path
        """
        try:
            total_lines, comment_lines = self._count_file_lines(file_path)

            result["line_counts"][path_str] = total_lines
            result["comment_ratios"][path_str] = self._calculate_comment_ratio(
                total_lines, comment_lines
            )
        except (IOError, UnicodeDecodeError) as e:
            self.logger.warning(f"Failed to count lines in {file_path}: {e}")

    def _create_naming_patterns(self) -> Dict[str, re.Pattern]:
        """
        Create regex patterns for different naming conventions.

        Returns:
            Dictionary of naming convention patterns
        """
        return {
            "snake_case": re.compile(r"^[a-z][a-z0-9_]*$"),
            "camel_case": re.compile(r"^[a-z][a-zA-Z0-9]*$"),
            "pascal_case": re.compile(r"^[A-Z][a-zA-Z0-9]*$"),
            "screaming_snake_case": re.compile(r"^[A-Z][A-Z0-9_]*$"),
        }

    def _analyze_module_naming(
        self, file_path: Path, patterns: Dict[str, re.Pattern], result: Dict
    ) -> None:
        """
        Analyze the naming convention of a module.

        Args:
            file_path: Path to the module file
            patterns: Dictionary of naming convention patterns
            result: Dictionary to store results
        """
        module_name = self._get_module_name(file_path)
        module_basename = os.path.basename(file_path).replace(".py", "")
        result["modules"][module_name] = self._determine_naming_convention(
            module_basename, patterns
        )

    def _analyze_class_naming(
        self,
        node: ast.ClassDef,
        module_name: str,
        patterns: Dict[str, re.Pattern],
        result: Dict,
    ) -> None:
        """
        Analyze the naming convention of a class.

        Args:
            node: Class definition node
            module_name: Name of the module containing the class
            patterns: Dictionary of naming convention patterns
            result: Dictionary to store results
        """
        class_name = node.name
        result["classes"][f"{module_name}.{class_name}"] = (
            self._determine_naming_convention(class_name, patterns)
        )

    def _analyze_function_naming(
        self,
        node: ast.FunctionDef,
        module_name: str,
        patterns: Dict[str, re.Pattern],
        result: Dict,
    ) -> None:
        """
        Analyze the naming convention of a function.

        Args:
            node: Function definition node
            module_name: Name of the module containing the function
            patterns: Dictionary of naming convention patterns
            result: Dictionary to store results
        """
        func_name = node.name
        if hasattr(node, "parent") and isinstance(node.parent, ast.ClassDef):
            func_name = f"{node.parent.name}.{func_name}"
        result["functions"][f"{module_name}.{func_name}"] = (
            self._determine_naming_convention(func_name, patterns)
        )

    def _analyze_variable_naming(
        self,
        node: ast.Assign,
        module_name: str,
        patterns: Dict[str, re.Pattern],
        result: Dict,
    ) -> None:
        """
        Analyze the naming convention of variables in an assignment.

        Args:
            node: Assignment node
            module_name: Name of the module containing the variable
            patterns: Dictionary of naming convention patterns
            result: Dictionary to store results
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                result["variables"][f"{module_name}.{var_name}"] = (
                    self._determine_naming_convention(var_name, patterns)
                )

    def _analyze_naming(self) -> Dict:
        """
        Analyze naming patterns in the codebase.

        Returns:
            Dictionary with naming analysis results.
        """
        self.logger.info("Analyzing naming patterns")

        result = {
            "classes": {},
            "functions": {},
            "variables": {},
            "modules": {},
            "inconsistencies": [],
        }

        # Create patterns for different naming conventions
        patterns = self._create_naming_patterns()

        # For each AST, extract all named elements
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)

            # Analyze module naming
            self._analyze_module_naming(file_path, patterns, result)

            # Extract and analyze named elements
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    self._analyze_class_naming(node, module_name, patterns, result)
                elif isinstance(node, ast.FunctionDef):
                    self._analyze_function_naming(node, module_name, patterns, result)
                elif isinstance(node, ast.Assign):
                    self._analyze_variable_naming(node, module_name, patterns, result)

        # Detect inconsistencies in naming conventions
        result["inconsistencies"] = self._detect_naming_inconsistencies(result)

        self._name_registry = result
        return result

    def _is_main_check_node(self, node: ast.AST) -> bool:
        """
        Check if a node is an if __name__ == "__main__" check.

        Args:
            node: AST node to check

        Returns:
            True if the node is a main check, False otherwise
        """
        # Check if it's an if statement with a compare expression
        if (
            not isinstance(node, ast.If)
            or not hasattr(node, "test")
            or not isinstance(node.test, ast.Compare)
        ):
            return False

        # Check if the left side is __name__
        if (
            not hasattr(node.test, "left")
            or not isinstance(node.test.left, ast.Name)
            or node.test.left.id != "__name__"
        ):
            return False

        # Check if it's an equality comparison
        if not isinstance(node.test.ops[0], ast.Eq):
            return False

        # Check if the right side is a string
        return isinstance(node.test.comparators[0], ast.Str)

    def _is_main_entry_point(self, node: ast.AST) -> bool:
        """
        Check if a node is an if __name__ == "__main__" entry point.

        Args:
            node: AST node to check

        Returns:
            True if the node is a main entry point, False otherwise
        """
        if not self._is_main_check_node(node):
            return False

        # Additional check for "__main__" string value
        return (
            len(node.test.ops) == 1
            and len(node.test.comparators) == 1
            and node.test.comparators[0].s == "__main__"
        )

    def _process_package_structure(self, file_path: Path) -> tuple[str, str]:
        """
        Process the package structure for a file.

        Args:
            file_path: Path to the file
            tree: AST of the file

        Returns:
            Tuple of (package_path, module_name)
        """
        relative_path = file_path.relative_to(self.project_path)
        package_path = (
            str(relative_path.parent) if relative_path.parent != Path(".") else ""
        )
        module_name = relative_path.stem

        return package_path, module_name

    def _collect_packages(self) -> defaultdict:
        """
        Collect package structure information.

        Returns:
            Dictionary of packages and their modules
        """
        packages = defaultdict(list)

        for file_path, tree in self._ast_cache.items():
            for node in ast.walk(tree):
                if self._is_main_check_node(node):
                    package_path, module_name = self._process_package_structure(
                        file_path
                    )

                    if package_path:
                        packages[package_path].append(module_name)
                    else:
                        packages["root"].append(module_name)

        return packages

    def _calculate_module_sizes(self, result: Dict) -> None:
        """
        Calculate the size of each module.

        Args:
            result: Dictionary to store results
        """
        for file_path in self._ast_cache.keys():
            relative_path = file_path.relative_to(self.project_path)
            if file_path.exists():
                result["module_sizes"][str(relative_path)] = file_path.stat().st_size

    def _identify_entry_points(self, result: Dict) -> None:
        """
        Identify potential entry points in the codebase.

        Args:
            result: Dictionary to store results
        """
        for file_path, tree in self._ast_cache.items():
            relative_path = file_path.relative_to(self.project_path)

            for node in ast.walk(tree):
                if self._is_main_entry_point(node):
                    result["entry_points"].append(str(relative_path))

    def _is_module_level_function(self, node: ast.FunctionDef, tree: ast.AST) -> bool:
        """
        Check if a function is at module level (not a method).

        Args:
            node: Function node to check
            tree: AST of the file

        Returns:
            True if the function is at module level, False otherwise
        """
        return not any(
            isinstance(parent, ast.ClassDef)
            for parent in ast.iter_child_nodes(tree)
            if hasattr(parent, "body") and node in parent.body
        )

    def _is_public_node(self, node: ast.AST) -> bool:
        """
        Check if a node represents a public class or function.

        Args:
            node: AST node to check

        Returns:
            True if the node is public, False otherwise
        """
        return not node.name.startswith("_") if hasattr(node, "name") else False

    def _collect_public_classes(self, tree: ast.AST) -> List[str]:
        """
        Collect names of public classes in an AST.

        Args:
            tree: AST to analyze

        Returns:
            List of public class names
        """
        return [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and self._is_public_node(node)
        ]

    def _collect_public_functions(self, tree: ast.AST) -> List[str]:
        """
        Collect names of public module-level functions in an AST.

        Args:
            tree: AST to analyze

        Returns:
            List of public function names
        """
        return [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and self._is_public_node(node)
            and self._is_module_level_function(node, tree)
        ]

    def _identify_api_surface(self, result: Dict) -> None:
        """
        Identify the public API surface of the codebase.

        Args:
            result: Dictionary to store results
        """
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)

            # Collect public classes and functions
            classes = self._collect_public_classes(tree)
            functions = self._collect_public_functions(tree)

            # Only add to results if there are public classes or functions
            if classes or functions:
                result["api_surface"][module_name] = {
                    "classes": classes,
                    "functions": functions,
                }

    def _analyze_module_structure(self) -> Dict:
        """
        Analyze the module structure of the codebase.

        Returns:
            Dictionary with module structure analysis.
        """
        self.logger.info("Analyzing module structure")

        # Collect package structure information - not used directly in this method
        self._collect_packages()

        # Initialize result dictionary
        result = {"module_sizes": {}, "entry_points": [], "api_surface": {}}

        # Calculate module sizes
        self._calculate_module_sizes(result)

        # Identify potential entry points
        self._identify_entry_points(result)

        # Identify API surface (public functions and classes)
        self._identify_api_surface(result)

        return result

    def _create_pattern_definitions(self) -> tuple[Dict, Dict, Dict]:
        """
        Create definitions for design patterns, anti-patterns, and idioms.

        Returns:
            Tuple of (design_patterns, anti_patterns, idioms) dictionaries
        """
        # Design pattern definitions
        design_patterns = {
            "singleton": [
                # Look for class with _instance class variable and __new__ method
                (
                    ast.ClassDef,
                    lambda node: any(
                        isinstance(n, ast.Assign)
                        and isinstance(n.targets[0], ast.Name)
                        and n.targets[0].id == "_instance"
                        for n in node.body
                    )
                    and any(
                        isinstance(n, ast.FunctionDef) and n.name == "__new__"
                        for n in node.body
                    ),
                )
            ],
            "factory": [
                # Look for method that returns instances of different classes based on parameters
                (
                    ast.FunctionDef,
                    lambda node: any(
                        isinstance(n, ast.Return) and isinstance(n.value, ast.Call)
                        for n in ast.walk(node)
                    ),
                )
            ],
        }

        # Anti-pattern definitions
        anti_patterns = {
            "god_class": [
                # Classes with too many methods and attributes
                (
                    ast.ClassDef,
                    lambda node: len(
                        [n for n in node.body if isinstance(n, ast.FunctionDef)]
                    )
                    > self.config.get("analyzer", {}).get("max_methods_per_class", 20),
                )
            ],
            "global_state": [
                # Use of global variables
                (ast.Global, lambda node: True)
            ],
        }

        # Common idiom definitions
        idioms = {
            "list_comprehension": [(ast.ListComp, lambda node: True)],
            "dict_comprehension": [(ast.DictComp, lambda node: True)],
            "context_manager": [(ast.With, lambda node: True)],
        }

        return design_patterns, anti_patterns, idioms

    def _create_pattern_result_structure(self) -> Dict:
        """
        Create the initial result structure for pattern analysis.

        Returns:
            Dictionary with pattern analysis structure
        """
        return {
            "design_patterns": defaultdict(list),
            "anti_patterns": defaultdict(list),
            "common_idioms": defaultdict(int),
            "pattern_locations": [],  # Store detailed location information
        }

    def _create_pattern_info(
        self, pattern_name: str, pattern_type: str, node: ast.AST, file_path: str
    ) -> Dict:
        """
        Create pattern information dictionary for a detected pattern.

        Args:
            pattern_name: Name of the pattern
            pattern_type: Type of pattern (design_pattern or anti_pattern)
            node: AST node where pattern was detected
            file_path: Path to the file containing the pattern

        Returns:
            Dictionary with pattern information
        """
        return {
            "file": file_path,
            "type": pattern_type,
            "name": pattern_name,
            "line": getattr(node, "lineno", 0),
            "col": getattr(node, "col_offset", 0),
        }

    def _analyze_design_patterns(
        self, tree: ast.AST, relative_path: str, design_patterns: Dict, result: Dict
    ) -> None:
        """
        Analyze design patterns in an AST.

        Args:
            tree: AST to analyze
            relative_path: Relative path to the file
            design_patterns: Dictionary of design pattern definitions
            result: Dictionary to store results
        """
        for pattern_name, pattern_defs in design_patterns.items():
            for node_type, condition in pattern_defs:
                for node in ast.walk(tree):
                    try:
                        if isinstance(node, node_type) and condition(node):
                            # Store pattern information
                            pattern_info = self._create_pattern_info(
                                pattern_name, "design_pattern", node, relative_path
                            )
                            result["pattern_locations"].append(pattern_info)
                            result["design_patterns"][pattern_name].append(
                                relative_path
                            )
                    except Exception as e:
                        self.logger.warning(
                            f"Error analyzing pattern {pattern_name} in {relative_path}: {e}"
                        )

    def _analyze_anti_patterns(
        self, tree: ast.AST, relative_path: str, anti_patterns: Dict, result: Dict
    ) -> None:
        """
        Analyze anti-patterns in an AST.

        Args:
            tree: AST to analyze
            relative_path: Relative path to the file
            anti_patterns: Dictionary of anti-pattern definitions
            result: Dictionary to store results
        """
        for pattern_name, pattern_defs in anti_patterns.items():
            for node_type, condition in pattern_defs:
                for node in ast.walk(tree):
                    try:
                        if isinstance(node, node_type) and condition(node):
                            # Store pattern information
                            pattern_info = self._create_pattern_info(
                                pattern_name, "anti_pattern", node, relative_path
                            )
                            result["pattern_locations"].append(pattern_info)
                            result["anti_patterns"][pattern_name].append(relative_path)
                    except Exception as e:
                        self.logger.warning(
                            f"Error analyzing anti-pattern {pattern_name} in {relative_path}: {e}"
                        )

    def _analyze_idioms(
        self, tree: ast.AST, relative_path: str, idioms: Dict, result: Dict
    ) -> None:
        """
        Analyze common idioms in an AST.

        Args:
            tree: AST to analyze
            relative_path: Relative path to the file
            idioms: Dictionary of idiom definitions
            result: Dictionary to store results
        """
        for idiom_name, idiom_defs in idioms.items():
            for node_type, condition in idiom_defs:
                try:
                    count = sum(
                        bool(isinstance(node, node_type) and condition(node))
                        for node in ast.walk(tree)
                    )
                    result["common_idioms"][idiom_name] += count
                except Exception as e:
                    self.logger.warning(
                        f"Error analyzing idiom {idiom_name} in {relative_path}: {e}"
                    )

    def _prepare_pattern_results_for_serialization(self, result: Dict) -> None:
        """
        Convert defaultdicts to regular dicts for serialization.

        Args:
            result: Dictionary to prepare for serialization
        """
        result["design_patterns"] = dict(result["design_patterns"])
        result["anti_patterns"] = dict(result["anti_patterns"])
        result["common_idioms"] = dict(result["common_idioms"])

    def _analyze_code_patterns(self) -> Dict:
        """
        Analyze common code patterns and anti-patterns.

        Returns:
            Dictionary with code pattern analysis.
        """
        self.logger.info("Analyzing code patterns")

        # Create pattern definitions
        design_patterns, anti_patterns, idioms = self._create_pattern_definitions()

        # Initialize result structure
        result = self._create_pattern_result_structure()

        # Scan for patterns in each file
        for file_path, tree in self._ast_cache.items():
            try:
                # Use relative path for reporting
                relative_path = str(file_path.relative_to(self.project_path))

                # Analyze different pattern types
                self._analyze_design_patterns(
                    tree, relative_path, design_patterns, result
                )
                self._analyze_anti_patterns(tree, relative_path, anti_patterns, result)
                self._analyze_idioms(tree, relative_path, idioms, result)

            except Exception as e:
                self.logger.error(f"Error analyzing patterns in {file_path}: {e}")

        # Prepare results for serialization
        self._prepare_pattern_results_for_serialization(result)

        return result

    def _analyze_test_coverage(self) -> Dict:
        """
        Analyze test coverage if coverage data is available.

        Returns:
        Returns:
            Dictionary with test coverage analysis.
        """
        self.logger.info("Analyzing test coverage")

        result = {
            "coverage_available": False,
            "total_coverage": 0.0,
            "untested_functions": [],
        }

        # Check if coverage data is available
        coverage_path = self.project_path / ".coverage"
        if not coverage_path.exists():
            self.logger.info("No coverage data found")
            return result

        # Coverage analysis implementation
        # This would parse coverage.py's data format if available
        # For projects with coverage data, we would:
        # 1. Parse the coverage data file
        # 2. Identify untested functions and modules
        # 3. Calculate overall coverage statistics

        # For now, just provide a placeholder
        result["coverage_available"] = False
        return result

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

    def _is_entry_point(self, tree: ast.AST) -> bool:
        """
        Check if an AST contains a __main__ block, indicating it's an entry point.

        Args:
            tree: AST of a Python file

        Returns:
            True if the file has a __main__ block, False otherwise
        """
        for node in ast.walk(tree):
            # Check for if __name__ == "__main__" pattern
            if not isinstance(node, ast.If):
                continue

            # Check for Compare node with __name__ as left operand
            if not (hasattr(node, "test") and isinstance(node.test, ast.Compare)):
                continue

            # Verify left side is __name__
            if not (
                hasattr(node.test, "left")
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
            ):
                continue

            # Check for == operator and "__main__" string
            if (
                len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Str)
                and node.test.comparators[0].s == "__main__"
            ):
                return True

        return False

    def _is_internal_module(self, module_name: str) -> bool:
        """
        Check if a module name refers to an internal project module.

        Args:
            module_name: Name of the module.

        Returns:
            True if internal, False if external.
        """
        # First check obvious external modules
        if module_name in [
            "os",
            "sys",
            "re",
            "json",
            "datetime",
            "collections",
            "numpy",
            "pandas",
            "django",
            "flask",
            "requests",
        ]:
            return False

        # Check if the module exists in our project
        for file_path in self._ast_cache.keys():
            if self._get_module_name(file_path) == module_name:
                return True

            # Check for parent package
            parts = self._get_module_name(file_path).split(".")
            for i in range(1, len(parts) + 1):
                if ".".join(parts[:i]) == module_name:
                    return True

        return False

    def _determine_naming_convention(
        self, name: str, patterns: Dict[str, re.Pattern]
    ) -> str:
        """
        Determine the naming convention used for a name.

        Args:
            name: The name to check.
            patterns: Dictionary of regex patterns for conventions.

        Returns:
            Name of the convention or "unknown".
        """
        return next(
            (
                convention
                for convention, pattern in patterns.items()
                if pattern.match(name)
            ),
            "unknown",
        )

    def _detect_naming_inconsistencies(self, naming_data: Dict) -> List[Dict]:
        """
        Detect inconsistencies in naming conventions.
                        "recommendation": "Use snake_case for variables and SCREAMING_SNAKE_CASE for constants",  # TODO: Line too long, needs manual fixing
        Args:
            naming_data: Dictionary with naming analysis.

        Returns:
            List of detected inconsistencies.
        """
        inconsistencies = []

        # Check class naming consistency
        class_conventions = Counter(naming_data["classes"].values())
        if len(class_conventions) > 1:
            inconsistencies.append(
                {
                    "type": "class_naming",
                    "conventions": dict(class_conventions),
                    "recommendation": "Use PascalCase for all class names",
                }
            )

        # Check function naming consistency
        function_conventions = Counter(naming_data["functions"].values())
        if len(function_conventions) > 1:
            inconsistencies.append(
                {
                    "type": "function_naming",
                    "conventions": dict(function_conventions),
                    "recommendation": "Use snake_case for all function names",
                }
            )

        # Check variable naming consistency
        variable_conventions = Counter(naming_data["variables"].values())
        if (
            len(variable_conventions) > 1
            and "screaming_snake_case" in variable_conventions
        ):
            # Check if there are conventions other than snake_case and screaming_snake_case
            has_other_conventions = any(
                k not in ["snake_case", "screaming_snake_case"]
                for k in variable_conventions
            )
            if has_other_conventions:
                inconsistencies.append(
                    {
                        "type": "variable_naming",
                        "conventions": dict(variable_conventions),
                        "recommendation": "Use snake_case for variables and SCREAMING_SNAKE_CASE for constants",
                    }
                )

        # Check module naming consistency
        module_conventions = Counter(naming_data["modules"].values())
        if len(module_conventions) > 1:
            inconsistencies.append(
                {
                    "type": "module_naming",
                    "conventions": dict(module_conventions),
                    "recommendation": "Use snake_case for all module names",
                }
            )

        return inconsistencies

    def _generate_summary(
        self,
        python_files: List[Path],
        import_structure: Dict,
        complexity_metrics: Dict,
        name_registry: Dict,
        module_structure: Dict,
        test_coverage: Dict,
    ) -> Dict:
        """
        Generate a summary of the analysis results.

        Args:
            python_files: List of Python files analyzed.
            import_structure: Import analysis results.
            complexity_metrics: Complexity analysis results.
            name_registry: Naming analysis results.
            module_structure: Module structure analysis results.
            test_coverage: Test coverage analysis results.

        Returns:
            Dictionary with analysis summary.
        """
        summary = {
            "total_files": len(python_files),
            "total_lines": sum(complexity_metrics.get("line_counts", {}).values()),
            "avg_complexity": 0,
            "max_complexity": 0,
            "circular_imports": len(import_structure.get("circular_dependencies", [])),
            "external_dependencies": len(
                set().union(
                    *[
                        set(deps)
                        for deps in import_structure.get(
                            "external_dependencies", {}
                        ).values()
                    ]
                )
            ),
            "naming_consistency": len(name_registry.get("inconsistencies", [])) == 0,
            "entry_points": len(module_structure.get("entry_points", [])),
            "api_surface_size": sum(
                len(api.get("classes", [])) + len(api.get("functions", []))
                for api in module_structure.get("api_surface", {}).values()
            ),
        }

        # Calculate average and maximum complexity
        all_complexities = []
        for file_complexities in complexity_metrics.get(
            "cyclomatic_complexity", {}
        ).values():
            all_complexities.extend(file_complexities.values())

        if all_complexities:
            summary["avg_complexity"] = sum(all_complexities) / len(all_complexities)
            summary["max_complexity"] = max(all_complexities)

        # Add test coverage if available
        if test_coverage.get("coverage_available", False):
            summary["test_coverage"] = test_coverage.get("total_coverage", 0.0)

        return summary
