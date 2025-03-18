"""
Conflict Resolver Module for PS2.

This module detects and resolves naming conflicts in Python projects,
ensuring consistent naming conventions and preventing collisions that
could lead to unexpected behavior or bugs.
"""

import ast
import builtins
import logging
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Union


class ConflictResolver:
    """
        Resolver for naming conflicts in Python projects.
    from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
        This class identifies and resolves naming conflicts in Python projects,
        enforcing consistent naming conventions and preventing collisions that
        could lead to unexpected behavior or bugs.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the conflict resolver.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the resolver.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.conflict_resolver")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "auto_rename": False,
            "protected_names": ["main", "app", "run", "test"],
            "class_name_convention": "PascalCase",
            "function_name_convention": "snake_case",
            "variable_name_convention": "snake_case",
            "constant_name_convention": "UPPER_SNAKE_CASE",
        }

        # Apply config settings
        self.settings = {
            **self.default_settings,
            **self.config.get("conflict_resolver", {}),
        }

        # Caches
        self._ast_cache = {}
        self._naming_registry = None

    def enable(self) -> None:
        """Enable the conflict resolver."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the conflict resolver."""
        self.enabled = False

    def detect_conflicts(self, fix: bool = False) -> Dict:
        """
        Detect naming conflicts in the project.

        Args:
            fix: Whether to automatically fix conflicts where possible.

        Returns:
            Dictionary with conflict detection results.
        """
        if not self.enabled:
            self.logger.warning("Conflict resolver is disabled. Enabling for this run.")
            self.enable()

        self.logger.info(f"Detecting naming conflicts (fix: {fix})")

        # Collect Python files
        python_files = self._collect_python_files()

        # Build AST cache
        self._build_ast_cache(python_files)

        # Build naming registry
        naming_registry = self._build_naming_registry()

        # Check for conflicts
        conflicts = self._check_for_conflicts(naming_registry)

        # Check for naming convention violations
        naming_violations = self._check_naming_conventions(naming_registry)

        # Fix conflicts if requested
        fixed_conflicts = []
        if fix and (conflicts or naming_violations):
            fixed_conflicts = self._fix_conflicts(conflicts, naming_violations)

        # Build result
        result = {
            "files_analyzed": len(python_files),
            "conflicts": conflicts,
            "naming_violations": naming_violations,
            "fixed_conflicts": fixed_conflicts,
        }

        # Determine overall status
        if not conflicts and not naming_violations:
            result["status"] = "pass"
            result["message"] = "No naming conflicts found"
        elif fix and fixed_conflicts:
            result["status"] = "fixed"
            result["message"] = (
                f"Fixed {len(fixed_conflicts)} naming conflicts/violations"
            )
        else:
            result["status"] = "fail"
            result["message"] = (
                f"Found {len(conflicts)} conflicts and {len(naming_violations)} naming violations"
            )

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

    def _build_naming_registry(self) -> Dict:
        """
        Build a registry of all names defined in the project.

        Returns:
            Dictionary with naming registry information.
        """
        self.logger.info("Building naming registry")

        registry = {
            "modules": {},
            "classes": {},
            "functions": {},
            "methods": {},
            "variables": {},
            "constants": {},
            "imports": {},
        }

        # Process each file
        for file_path, tree in self._ast_cache.items():
            module_name = self._get_module_name(file_path)

            # Register module
            registry["modules"][module_name] = {
                "file": file_path,
                "name": module_name,
                "type": "module",
                "convention": self._check_naming_convention(
                    module_name.split(".")[-1]
                ),
            }

            # Process AST nodes to extract names
            self._extract_names_from_ast(tree, module_name, registry)

        self._naming_registry = registry
        return registry

    def _create_class_entry(self, class_name: str, module_name: str, node: ast.ClassDef, tree: ast.Module) -> Dict:
        """Create a class entry for the registry."""
        qualified_name = f"{module_name}.{class_name}"
        return {
            "name": class_name,
            "qualified_name": qualified_name,
            "module": module_name,
            "file": tree.source_file,
            "line": node.lineno,
            "type": "class",
            "convention": self._check_naming_convention(class_name),
        }
    
    def _create_method_entry(self, func_name: str, class_name: str, module_name: str, node: ast.FunctionDef, tree: ast.Module) -> Dict:
        """Create a method entry for the registry."""
        qualified_name = f"{module_name}.{class_name}.{func_name}"
        return {
            "name": func_name,
            "qualified_name": qualified_name,
            "class": class_name,
            "module": module_name,
            "file": tree.source_file,
            "line": node.lineno,
            "type": "method",
            "convention": self._check_naming_convention(func_name),
        }
    
    def _create_function_entry(self, func_name: str, module_name: str, node: ast.FunctionDef, tree: ast.Module) -> Dict:
        """Create a function entry for the registry."""
        qualified_name = f"{module_name}.{func_name}"
        return {
            "name": func_name,
            "qualified_name": qualified_name,
            "module": module_name,
            "file": tree.source_file,
            "line": node.lineno,
            "type": "function",
            "convention": self._check_naming_convention(func_name),
        }
    
    def _create_variable_entry(self, var_name: str, module_name: str, scope: str, node: ast.Assign, is_constant: bool) -> Dict:
        """Create a variable or constant entry for the registry."""
        qualified_name = f"{module_name}.{scope}.{var_name}" if scope else f"{module_name}.{var_name}"
        entry_type = "constant" if is_constant else "variable"
        return {
            "name": var_name,
            "qualified_name": qualified_name,
            "module": module_name,
            "scope": scope,
            "convention": self._check_naming_convention(var_name),
            "line": node.lineno,
            "type": entry_type,
        }
    
    def _create_import_entry(self, name: str, asname: str, module_name: str, imported_from: str, node: ast.AST, tree: ast.Module) -> Dict:
        """Create an import entry for the registry."""
        qualified_name = f"{module_name}.{asname}"
        return {
            "name": asname,
            "qualified_name": qualified_name,
            "module": module_name,
            "imported_from": imported_from,
            "file": tree.source_file,
            "line": node.lineno,
            "type": "import",
            "convention": self._check_naming_convention(asname),
        }
    
    def _extract_names_from_ast(
        self, tree: ast.Module, module_name: str, registry: Dict
    ) -> None:
        """
        Extract all names from an AST.

        Args:
            tree: AST of the module.
            module_name: Name of the module.
            registry: Naming registry to update.
        """
        class_stack = []

        # Define visitor
        class NameExtractor(ast.NodeVisitor):
            def __init__(self, parent):
                self.parent = parent

            def visit_ClassDef(self, node):
                class_name = node.name
                qualified_name = f"{module_name}.{class_name}"

                # Register class
                registry["classes"][qualified_name] = self.parent._create_class_entry(
                    class_name, module_name, node, tree
                )

                # Process class body with class context
                class_stack.append(class_name)
                self.generic_visit(node)
                class_stack.pop()

            def visit_FunctionDef(self, node):
                func_name = node.name

                if class_stack:
                    # This is a method
                    class_name = class_stack[-1]
                    qualified_name = f"{module_name}.{class_name}.{func_name}"

                    registry["methods"][qualified_name] = self.parent._create_method_entry(
                        func_name, class_name, module_name, node, tree
                    )
                else:
                    # This is a function
                    qualified_name = f"{module_name}.{func_name}"

                    registry["functions"][qualified_name] = self.parent._create_function_entry(
                        func_name, module_name, node, tree
                    )

                # Visit function body
                self.generic_visit(node)

            def _process_name_target(self, target, node):
                """Process a name target in an assignment."""
                if not isinstance(target, ast.Name):
                    return
                    
                var_name = target.id
                scope = class_stack[-1] if class_stack else None
                is_constant = var_name.isupper()
                entry = self.parent._create_variable_entry(
                    var_name, module_name, scope, node, is_constant
                )
                
                registry_key = "constants" if is_constant else "variables"
                registry[registry_key][entry["qualified_name"]] = entry
            
            def visit_Assign(self, node):
                for target in node.targets:
                    self._process_name_target(target, node)
                self.generic_visit(node)

            def visit_Import(self, node):
                for alias in node.names:
                    name = alias.name
                    asname = alias.asname or name
                    
                    entry = self.parent._create_import_entry(
                        name, asname, module_name, name, node, tree
                    )
                    registry["imports"][entry["qualified_name"]] = entry

                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module:
                    for alias in node.names:
                        name = alias.name
                        asname = alias.asname or name
                        imported_from = f"{node.module}.{name}"
                        
                        entry = self.parent._create_import_entry(
                            name, asname, module_name, imported_from, node, tree
                        )
                        registry["imports"][entry["qualified_name"]] = entry

                self.generic_visit(node)

        # Run visitor
        visitor = NameExtractor(self)
        visitor.visit(tree)

    def _find_builtin_conflicts(self, registry: Dict) -> List[Dict]:
        """Find conflicts with built-in names."""
        return [
            {
                "type": "builtin_conflict",
                "name": module_name,
                "conflict_with": "built-in",
                "item_type": "module",
                "severity": "medium",
                "fix_suggestion": "Rename module to avoid conflict with built-in",
            }
            for module_name, module_info in registry["modules"].items()
            if self._is_builtin(module_name.split(".")[-1])
        ]
    
    def _create_conflict_item(self, item: Dict, scope: str, name: str) -> Dict:
        """Create a conflict item entry."""
        return {
            "name": item["name"],
            "qualified_name": item.get(
                "qualified_name", f"{scope}.{name}"
            ),
            "type": item["type"],
            "file": (
                str(item["file"].relative_to(self.project_path))
                if "file" in item
                else "unknown"
            ),
            "line": item.get("line", 0),
        }
    
    def _create_name_conflict_entry(self, name: str, scope: str, items: List[Dict], is_protected: bool) -> Dict:
        """Create a name conflict entry."""
        return {
            "type": "name_conflict",
            "name": name,
            "scope": scope,
            "items": [self._create_conflict_item(item, scope, name) for item in items],
            "severity": "high" if is_protected else "medium",
            "fix_suggestion": f"Rename conflicting {'protected ' if is_protected else ''}name",
        }
    
    def _should_create_conflict_entry(self, items: List[Dict], is_protected: bool) -> bool:
        """Determine if a conflict entry should be created."""
        if len(items) <= 1:
            return False
            
        return (
            is_protected
            or any(item["type"] != items[0]["type"] for item in items)
            or items[0]["type"] in ["method", "function"]
        )
    
    def _find_scope_conflicts(self, scope_registry: Dict) -> List[Dict]:
        """Find conflicts within scopes."""
        conflicts = []
        
        for scope, names in scope_registry.items():
            # Group by name
            names_by_name = defaultdict(list)
            for name_info in names:
                names_by_name[name_info["name"]].append(name_info)

            # Check for conflicts
            for name, items in names_by_name.items():
                is_protected = name in self.settings["protected_names"]
                
                if self._should_create_conflict_entry(items, is_protected):
                    conflicts.append(
                        self._create_name_conflict_entry(name, scope, items, is_protected)
                    )
        
        return conflicts
    
    def _check_for_conflicts(self, registry: Dict) -> List[Dict]:
        """
        Check for naming conflicts in the registry.

        Args:
            registry: Naming registry to check.

        Returns:
            List of conflict dictionaries.
        """
        self.logger.info("Checking for naming conflicts")

        # Find conflicts with built-ins
        conflicts = self._find_builtin_conflicts(registry)
        
        # Build name registry by scope
        scope_registry = self._build_scope_registry(registry)

        # Find conflicts within scopes
        scope_conflicts = self._find_scope_conflicts(scope_registry)
        conflicts.extend(scope_conflicts)

        # Check for conflicts with imports
        import_conflicts = self._check_import_conflicts(registry, scope_registry)
        conflicts.extend(import_conflicts)

        return conflicts


    def _create_import_conflict_entry(self, import_name: str, module: str, qualified_name: str, import_info: Dict, item: Dict) -> Dict:
        """Create an import conflict entry."""
        return {
            "type": "import_conflict",
            "name": import_name,
            "scope": module,
            "items": [
                self._create_import_item(import_name, qualified_name, import_info),
                self._create_conflicting_item(item, module)
            ],
            "severity": "medium",
            "fix_suggestion": "Rename import using 'as' or rename the conflicting name",
        }

    def _create_import_item(self, import_name: str, qualified_name: str, import_info: Dict) -> Dict:
        """Create an import item for conflict entry."""
        return {
            "name": import_name,
            "qualified_name": qualified_name,
            "type": "import",
            "file": str(import_info["file"].relative_to(self.project_path)),
            "line": import_info["line"],
            "imported_from": import_info["imported_from"],
        }

    def _create_conflicting_item(self, item: Dict, module: str) -> Dict:
        """Create a conflicting item for import conflict entry."""
        return {
            "name": item["name"],
            "qualified_name": item.get(
                "qualified_name", f"{module}.{item['name']}"
            ),
            "type": item["type"],
            "file": (
                str(item["file"].relative_to(self.project_path))
                if "file" in item
                else "unknown"
            ),
            "fix_suggestion": "Rename import using 'as' or rename the conflicting name",
        }

    def _find_conflicting_items(self, module: str, import_name: str, scope_registry: Dict) -> List[Dict]:
        """Find items that conflict with an import."""
        if module not in scope_registry:
            return []
            
        return [
            item for item in scope_registry[module]
            if item["name"] == import_name and item["type"] != "import"
        ]

    def _check_import_conflicts(self, registry: Dict, scope_registry: Dict) -> List[Dict]:
        """
        Check for conflicts between imports and other names.

        Args:
            registry: Complete naming registry.
            scope_registry: Registry organized by scope.

        Returns:
            List of import conflict dictionaries.
        """
        conflicts = []

        for qualified_name, import_info in registry["imports"].items():
            module = import_info["module"]
            import_name = import_info["name"]
            
            # Find conflicting items
            conflicting_items = self._find_conflicting_items(module, import_name, scope_registry)
            
            # Create conflict entries
            conflicts.extend([
                self._create_import_conflict_entry(import_name, module, qualified_name, import_info, item)
                for item in conflicting_items
            ])
                
        return conflicts


def _check_naming_conventions(self, registry: Dict) -> List[Dict]:
    """
    Check for naming convention violations.

    Args:
        registry: Naming registry to check.

    Returns:
        List of naming violation dictionaries.
    """
    self.logger.info("Checking naming conventions")

    violations = [
        {
            "type": "naming_convention",
            "name": class_info["name"],
            "qualified_name": qualified_name,
            "item_type": "class",
            "expected_convention": self.settings["class_name_convention"],
            "actual_convention": class_info["convention"],
            "file": str(class_info["file"].relative_to(self.project_path)),
            "line": class_info["line"],
            "severity": "low",
            "fix_suggestion": f"Rename class to follow {self.settings['class_name_convention']} convention",
        }
        for qualified_name, class_info in registry["classes"].items()
        if class_info["convention"] != self.settings["class_name_convention"]
    ]
    # Check functions
    violations.extend(
        {
            "type": "naming_convention",
            "name": func_info["name"],
            "qualified_name": qualified_name,
            "item_type": "function",
            "expected_convention": self.settings["function_name_convention"],
            "actual_convention": func_info["convention"],
            "file": str(func_info["file"].relative_to(self.project_path)),
            "line": func_info["line"],
            "severity": "low",
            "fix_suggestion": f"Rename function to follow {self.settings['function_name_convention']} convention",
        }
        for qualified_name, func_info in registry["functions"].items()
        if func_info["convention"] != self.settings["function_name_convention"]
    )
    # Check methods
    violations.extend(
        {
            "type": "naming_convention",
            "name": method_info["name"],
            "qualified_name": qualified_name,
            "item_type": "method",
            "expected_convention": self.settings["function_name_convention"],
            "actual_convention": method_info["convention"],
            "file": str(method_info["file"].relative_to(self.project_path)),
            "line": method_info["line"],
            "severity": "low",
            "fix_suggestion": f"Rename method to follow {self.settings['function_name_convention']} convention",
        }
        for qualified_name, method_info in registry["methods"].items()
        if method_info["convention"] != self.settings["function_name_convention"]
    )
    # Check variables
    violations.extend(
        {
            "type": "naming_convention",
            "name": var_info["name"],
            "qualified_name": qualified_name,
            "item_type": "variable",
            "expected_convention": self.settings["variable_name_convention"],
            "actual_convention": var_info["convention"],
            "file": str(var_info["file"].relative_to(self.project_path)),
            "line": var_info["line"],
            "severity": "low",
            "fix_suggestion": f"Rename variable to follow {self.settings['variable_name_convention']} convention",
        }
        for qualified_name, var_info in registry["variables"].items()
        if var_info["convention"] != self.settings["variable_name_convention"]
    )
    # Check constants
    violations.extend(
        {
            "type": "naming_convention",
            "name": const_info["name"],
            "qualified_name": qualified_name,
            "item_type": "constant",
            "expected_convention": self.settings["constant_name_convention"],
            "actual_convention": const_info["convention"],
            "file": str(const_info["file"].relative_to(self.project_path)),
            "line": const_info["line"],
            "severity": "low",
            "fix_suggestion": f"Rename constant to follow {self.settings['constant_name_convention']} convention",
        }
        for qualified_name, const_info in registry["constants"].items()
        if const_info["convention"] != self.settings["constant_name_convention"]
    )
    return violations


def _fix_conflicts(
    self, conflicts: List[Dict], naming_violations: List[Dict]
) -> List[Dict]:
    """
    Fix naming conflicts and violations.

    Args:
        conflicts: List of conflict dictionaries.
        naming_violations: List of naming violation dictionaries.

    Returns:
        List of fixed conflict dictionaries.
    """
    self.logger.info(
        f"Fixing conflicts: {len(conflicts)}, violations: {len(naming_violations)}"
    )

    fixed_items = []

    # Only auto-rename if configured
    if not self.settings["auto_rename"]:
        self.logger.info("Auto-rename is disabled, skipping fixes")
        return fixed_items

    # This is a placeholder for a complete implementation
    # In a real implementation, we would:
    # 1. Determine which names to rename
    # 2. Generate replacement names
    # 3. Apply renames to the source files
    # 4. Track what was fixed

    # For now, we just log that fixes would be applied
    for conflict in conflicts:
        self.logger.info(
            f"Would fix conflict: {conflict['name']} in {conflict['scope']}"
        )
        fixed_items.append(
            {
                "type": "fixed_conflict",
                "conflict_type": conflict["type"],
                "name": conflict["name"],
                "scope": conflict.get("scope", ""),
                "file": conflict["items"][0]["file"] if "items" in conflict else "",
                "fix_applied": "simulation",
            }
        )

    for violation in naming_violations:
        self.logger.info(
            f"Would fix naming violation: {violation['name']} in {violation['file']}"
        )
        fixed_items.append(
            {
                "type": "fixed_violation",
                "violation_type": "naming_convention",
                "name": violation["name"],
                "qualified_name": violation["qualified_name"],
                "file": violation["file"],
                "fix_applied": "simulation",
            }
        )

    return fixed_items


def _build_scope_registry(self, registry: Dict) -> Dict[str, List[Dict]]:
    """
    Build a registry organized by scope.

    Args:
        registry: Complete naming registry.

    Returns:
        Dictionary mapping scopes to lists of name info dictionaries.
    """
    scope_registry = defaultdict(list)

    # Add classes
    for qualified_name, class_info in registry["classes"].items():
        module = class_info["module"]
        scope_registry[module].append(class_info)

    # Add functions
    for qualified_name, func_info in registry["functions"].items():
        module = func_info["module"]
        scope_registry[module].append(func_info)

    # Add methods
    for qualified_name, method_info in registry["methods"].items():
        class_scope = f"{method_info['module']}.{method_info['class']}"
        scope_registry[class_scope].append(method_info)

    # Add variables
    for qualified_name, var_info in registry["variables"].items():
        if var_info["scope"]:
            # Class variable
            scope = f"{var_info['module']}.{var_info['scope']}"
        else:
            # Module variable
            scope = var_info["module"]

        scope_registry[scope].append(var_info)

    # Add constants
    for qualified_name, const_info in registry["constants"].items():
        if const_info["scope"]:
            # Class constant
            scope = f"{const_info['module']}.{const_info['scope']}"
        else:
            # Module constant
            scope = const_info["module"]

        scope_registry[scope].append(const_info)

    # Add imports
    for qualified_name, import_info in registry["imports"].items():
        module = import_info["module"]
        scope_registry[module].append(import_info)

    return dict(scope_registry)


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


def _check_naming_convention(self, name: str) -> str:
    """
    Check the naming convention of a name.

    Args:
        name: Name to check.

    Returns:
        Name of the convention used.
    """
    # PascalCase check
    if re.match(r"^[A-Z][a-zA-Z0-9]*$", name):
        return "PascalCase"

    # camelCase check
    if re.match(r"^[a-z][a-zA-Z0-9]*$", name):
        return "camelCase"

    # snake_case check
    if re.match(r"^[a-z][a-z0-9_]*$", name):
        return "snake_case"

    # UPPER_SNAKE_CASE check
    if re.match(r"^[A-Z][A-Z0-9_]*$", name):
        return "UPPER_SNAKE_CASE"

    # kebab-case check
    return "kebab-case" if re.match(r"^[a-z][a-z0-9\-]*$", name) else "unknown"


def _is_builtin(self, name: str) -> bool:
    """
    Check if a name is a Python built-in.

    Args:
        name: Name to check.

    Returns:
        True if the name is a built-in, False otherwise.
    """

    return name in dir(builtins)
