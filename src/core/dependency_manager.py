"""
Dependency Manager Module for PS2.

This module manages Python project dependencies, handling requirements.txt
generation, virtual environment management, and dependency conflict resolution.
"""


import contextlib
import os
import re
import subprocess
import logging
import tempfile
import json
from pathlib import Path
import pkg_resources
from typing import Dict, List, Set, Tuple, Any, Optional, Union


class DependencyManager:
    """
    Manager for Python project dependencies.

    This class handles requirements.txt generation, virtual environment
    management, and dependency conflict resolution, ensuring consistent
    and reproducible dependencies for Python projects.
    """

    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the dependency manager.

        Args:
            project_path: Path to the Python project.
            config: Configuration dictionary for the manager.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.dependency_manager")
        self.enabled = False

        # Default settings
        self.default_settings = {
            "auto_update_requirements": True,
            "track_dev_dependencies": True,
            "pin_versions": True,
            "check_vulnerabilities": True,
        }

        # Apply config settings
        self.settings = {
            **self.default_settings,
            **self.config.get("dependency_manager", {}),
        }

    def enable(self) -> None:
        """Enable the dependency manager."""
        self.enabled = True

    def disable(self) -> None:
        """Disable the dependency manager."""
        self.enabled = False

    def manage(self, update: bool = False) -> Dict:
        """
        Manage project dependencies.

        Args:
            update: Whether to update dependencies to compatible versions.

        Returns:
            Dictionary with dependency management results.
        """
        if not self.enabled:
            self.logger.warning(
                "Dependency manager is disabled. Enabling for this run."
            )
            self.enable()

        self.logger.info(f"Managing dependencies (update: {update})")

        # Detect project dependencies
        imports = self._detect_imports()

        # Detect existing requirements files
        requirements_files = self._find_requirements_files()

        # Parse existing requirements
        current_requirements = self._parse_requirements(requirements_files)

        # Check for unused dependencies
        unused_dependencies = self._find_unused_dependencies(
            imports, current_requirements
        )

        # Check for missing dependencies
        missing_dependencies = self._find_missing_dependencies(
            imports, current_requirements
        )

        # Check for outdated dependencies
        outdated_dependencies = self._find_outdated_dependencies(current_requirements)

        # Check for dependency conflicts
        conflicts = self._check_dependency_conflicts(current_requirements)

        # Check for security vulnerabilities
        vulnerabilities = self._check_vulnerabilities(current_requirements)

        # Update requirements.txt if needed
        updated_files = []
        if update and (missing_dependencies or outdated_dependencies):
            updated_files = self._update_requirements(
                current_requirements, missing_dependencies, outdated_dependencies
            )

        # Build result
        result = {
            "detected_imports": imports,
            "requirements_files": [str(path) for path in requirements_files],
            "current_requirements": current_requirements,
            "unused_dependencies": unused_dependencies,
            "missing_dependencies": missing_dependencies,
            "outdated_dependencies": outdated_dependencies,
            "conflicts": conflicts,
            "vulnerabilities": vulnerabilities,
            "updated_files": updated_files,
        }

        # Determine overall status
        if conflicts or vulnerabilities:
            result["status"] = "fail"
            result["message"] = (
                f"Found {len(conflicts)} conflicts and {len(vulnerabilities)} vulnerabilities"
            )
        elif missing_dependencies and not update:
            result["status"] = "fail"
            result["message"] = (
                f"Found {len(missing_dependencies)} missing dependencies"
            )
        elif update and updated_files:
            result["status"] = "fixed"
            result["message"] = f"Updated {len(updated_files)} requirements files"
        else:
            result["status"] = "pass"
            result["message"] = "Dependencies are properly managed"

        return result

    def _detect_imports(self) -> Dict[str, Set[str]]:
        """
        Detect third-party imports in the project.

        Returns:
            Dictionary mapping module names to sets of files using them.
        """
        self.logger.info("Detecting imports")

        imports = {}
        std_libs = self._get_stdlib_modules()

        for root, _, files in os.walk(self.project_path):
            for file in files:
                if file.endswith(".py"):
                    file_path = Path(root) / file

                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = f.read()

                        # Find import statements
                        for match in re.finditer(
                            r"(?m)^import\s+([\w\.]+)(?:\s+as\s+\w+)?(?:\s*,\s*([\w\.]+)(?:\s+as\s+\w+)?)*$",
                            content,
                        ):
                            for group in match.groups():
                                if group:
                                    module_name = group.split(".")[0]
                                    if module_name not in std_libs:
                                        if module_name not in imports:
                                            imports[module_name] = set()
                                        imports[module_name].add(
                                            str(
                                                file_path.relative_to(self.project_path)
                                            )
                                        )

                        # Find from import statements
                        for match in re.finditer(
                            r"(?m)^from\s+([\w\.]+)\s+import", content
                        ):
                            module_name = match.group(1).split(".")[0]
                            if module_name not in std_libs:
                                if module_name not in imports:
                                    imports[module_name] = set()
                                imports[module_name].add(
                                    str(file_path.relative_to(self.project_path))
                                )

                    except (UnicodeDecodeError, PermissionError) as e:
                        self.logger.warning(f"Could not read {file_path}: {e}")

        return imports

    def _find_requirements_files(self) -> List[Path]:
        """
        Find requirements files in the project.

        Returns:
            List of paths to requirements files.
        """
        self.logger.info("Finding requirements files")

        requirements_files = []

        # Common requirements file patterns
        patterns = [
            "requirements.txt",
            "requirements-*.txt",
            "requirements/*.txt",
            "requirements/**.txt",
        ]

        for pattern in patterns:
            paths = list(self.project_path.glob(pattern))
            requirements_files.extend(paths)

        # Also check for setup.py, pyproject.toml, and Pipfile
        setup_py = self.project_path / "setup.py"
        if setup_py.exists():
            requirements_files.append(setup_py)

        pyproject_toml = self.project_path / "pyproject.toml"
        if pyproject_toml.exists():
            requirements_files.append(pyproject_toml)

        pipfile = self.project_path / "Pipfile"
        if pipfile.exists():
            requirements_files.append(pipfile)

        self.logger.info(f"Found {len(requirements_files)} requirements files")
        return requirements_files

    def _parse_requirements(self, requirements_files: List[Path]) -> Dict[str, Dict]:
        """
        Parse requirements from files.

        Args:
            requirements_files: List of paths to requirements files.

        Returns:
            Dictionary mapping package names to requirement info.
        """
        self.logger.info("Parsing requirements")

        requirements = {}

        for file_path in requirements_files:
            self.logger.debug(f"Parsing {file_path}")

            if file_path.name == "setup.py":
                self._parse_setup_py(file_path, requirements)
            elif file_path.name == "pyproject.toml":
                self._parse_pyproject_toml(file_path, requirements)
            elif file_path.name == "Pipfile":
                self._parse_pipfile(file_path, requirements)
            elif file_path.suffix == ".txt":
                self._parse_requirements_txt(file_path, requirements)

        return requirements

    def _parse_requirements_txt(self, file_path: Path, requirements: Dict) -> None:
        """
        Parse a requirements.txt file.

        Args:
            file_path: Path to requirements file.
            requirements: Dictionary to update with parsed requirements.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith("#"):
                        continue

                    # Skip options (lines starting with -)
                    if line.startswith("-"):
                        continue

                    # Parse requirement
                    try:
                        req = pkg_resources.Requirement.parse(line)
                        package_name = req.name

                        if package_name not in requirements:
                            requirements[package_name] = {
                                "sources": [],
                                "specs": [],
                                "extras": [],
                            }

                        requirements[package_name]["sources"].append(
                            str(file_path.relative_to(self.project_path))
                        )
                        requirements[package_name]["specs"].extend(req.specs)
                        requirements[package_name]["extras"].extend(req.extras)

                    except (ValueError, pkg_resources.RequirementParseError) as e:
                        self.logger.warning(
                            f"Could not parse requirement '{line}' in {file_path}: {e}"
                        )

        except (UnicodeDecodeError, PermissionError) as e:
            self.logger.warning(f"Could not read {file_path}: {e}")

    def _parse_setup_py(self, file_path: Path, requirements: Dict) -> None:
        """
        Parse a setup.py file.

        Args:
            file_path: Path to setup.py file.
            requirements: Dictionary to update with parsed requirements.
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            if install_requires_match := re.search(
                r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL
            ):
                install_requires = install_requires_match.group(1)

                # Parse package names
                for package in re.finditer(r"['\"]([^'\"]+)['\"]", install_requires):
                    package_str = package.group(1)

                    try:
                        req = pkg_resources.Requirement.parse(package_str)
                        package_name = req.name

                        if package_name not in requirements:
                            requirements[package_name] = {
                                "sources": [],
                                "specs": [],
                                "extras": [],
                            }

                        requirements[package_name]["sources"].append(
                            str(file_path.relative_to(self.project_path))
                        )
                        requirements[package_name]["specs"].extend(req.specs)
                        requirements[package_name]["extras"].extend(req.extras)

                    except (ValueError, pkg_resources.RequirementParseError) as e:
                        self.logger.warning(
                            f"Could not parse requirement '{package_str}' in {file_path}: {e}"
                        )

        except (UnicodeDecodeError, PermissionError) as e:
            self.logger.warning(f"Could not read {file_path}: {e}")

    def _parse_pyproject_toml(self, file_path: Path, requirements: Dict) -> None:
        """
        Parse a pyproject.toml file.

        Args:
            file_path: Path to pyproject.toml file.
            requirements: Dictionary to update with parsed requirements.
        """
        try:
            import tomli

            with open(file_path, "rb") as f:
                data = tomli.load(f)

            # Check for dependencies in different possible locations
            dependency_sources = [
                data.get("project", {}).get("dependencies", []),
                data.get("tool", {}).get("poetry", {}).get("dependencies", {}),
                data.get("build-system", {}).get("requires", []),
            ]

            for source in dependency_sources:
                if isinstance(source, list):
                    for package_str in source:
                        try:
                            req = pkg_resources.Requirement.parse(package_str)
                            package_name = req.name

                            if package_name not in requirements:
                                requirements[package_name] = {
                                    "sources": [],
                                    "specs": [],
                                    "extras": [],
                                }

                            requirements[package_name]["sources"].append(
                                str(file_path.relative_to(self.project_path))
                            )
                            requirements[package_name]["specs"].extend(req.specs)
                            requirements[package_name]["extras"].extend(req.extras)

                        except (ValueError, pkg_resources.RequirementParseError) as e:
                            self.logger.warning(
                                f"Could not parse requirement '{package_str}' in {file_path}: {e}"
                            )

                elif isinstance(source, dict):
                    for package_name, version in source.items():
                        if package_name != "python":  # Skip python itself
                            if package_name not in requirements:
                                requirements[package_name] = {
                                    "sources": [],
                                    "specs": [],
                                    "extras": [],
                                }

                            requirements[package_name]["sources"].append(
                                str(file_path.relative_to(self.project_path))
                            )

                            # Parse version constraint
                            if isinstance(version, str):
                                if version == "*":
                                    pass  # No version constraint
                                elif version.startswith("^"):
                                    requirements[package_name]["specs"].append(
                                        (">=", version[1:])
                                    )
                                elif version.startswith("~"):
                                    requirements[package_name]["specs"].append(
                                        ("~=", version[1:])
                                    )
                                else:
                                    requirements[package_name]["specs"].append(
                                        ("==", version)
                                    )

        except ImportError:
            self.logger.warning(
                "tomli module not available, skipping pyproject.toml parsing"
            )
        except (UnicodeDecodeError, PermissionError, json.JSONDecodeError) as e:
            self.logger.warning(f"Could not read {file_path}: {e}")

    def _parse_pipfile(self, file_path: Path, requirements: Dict) -> None:
        """
        Parse a Pipfile.

        Args:
            file_path: Path to Pipfile.
            requirements: Dictionary to update with parsed requirements.
        """
        try:
            import toml

            with open(file_path, "r", encoding="utf-8") as f:
                data = toml.load(f)

            # Parse packages
            packages = data.get("packages", {})
            for package_name, constraint in packages.items():
                if package_name not in requirements:
                    requirements[package_name] = {
                        "sources": [],
                        "specs": [],
                        "extras": [],
                    }

                requirements[package_name]["sources"].append(
                    str(file_path.relative_to(self.project_path))
                )

                # Parse version constraint
                if isinstance(constraint, str):
                    if constraint != "*":
                        requirements[package_name]["specs"].append(("==", constraint))
                elif isinstance(constraint, dict) and "version" in constraint:
                    requirements[package_name]["specs"].append(
                        ("==", constraint["version"])
                    )

            # Parse dev-packages if configured to track them
            if self.settings["track_dev_dependencies"]:
                dev_packages = data.get("dev-packages", {})
                for package_name, constraint in dev_packages.items():
                    if package_name not in requirements:
                        requirements[package_name] = {
                            "sources": [],
                            "specs": [],
                            "extras": [],
                            "dev": True,
                        }
                    else:
                        requirements[package_name]["dev"] = True

                    requirements[package_name]["sources"].append(
                        str(file_path.relative_to(self.project_path))
                    )

                    # Parse version constraint
                    if isinstance(constraint, str):
                        if constraint != "*":
                            requirements[package_name]["specs"].append(
                                ("==", constraint)
                            )
                    elif isinstance(constraint, dict) and "version" in constraint:
                        requirements[package_name]["specs"].append(
                            ("==", constraint["version"])
                        )

        except ImportError:
            self.logger.warning("toml module not available, skipping Pipfile parsing")
        except (UnicodeDecodeError, PermissionError, toml.TomlDecodeError) as e:
            self.logger.warning(f"Could not read {file_path}: {e}")

    def _find_unused_dependencies(
        self, imports: Dict[str, Set[str]], requirements: Dict
    ) -> List[Dict]:
        """
        Find unused dependencies.

        Args:
            imports: Dictionary mapping module names to sets of files using them.
            requirements: Dictionary mapping package names to requirement info.

        Returns:
            List of unused dependencies.
        """
        self.logger.info("Finding unused dependencies")

        unused = []

        # Get package to import name mapping
        package_to_import = self._get_package_import_mapping()

        for package_name, package_info in requirements.items():
            # Skip if this is a dev dependency
            if package_info.get("dev", False):
                continue

            # Get possible import names for this package
            import_names = package_to_import.get(
                package_name.lower(), [package_name.lower()]
            )

            # Check if any import name is used
            if all(import_name not in imports for import_name in import_names):
                unused.append(
                    {
                        "package": package_name,
                        "sources": package_info["sources"],
                        "specs": package_info["specs"],
                    }
                )

        return unused

    def _find_missing_dependencies(
        self, imports: Dict[str, Set[str]], requirements: Dict
    ) -> List[Dict]:
        """
        Find missing dependencies.

        Args:
            imports: Dictionary mapping module names to sets of files using them.
            requirements: Dictionary mapping package names to requirement info.

        Returns:
            List of missing dependencies.
        """
        self.logger.info("Finding missing dependencies")

        missing = []

        # Get import name to package mapping
        import_to_package = self._get_import_package_mapping()

        for import_name, files in imports.items():
            # Get possible package names for this import
            package_names = import_to_package.get(
                import_name.lower(), [import_name.lower()]
            )

            # Check if any package name is in requirements
            if all(
                package_name not in requirements for package_name in package_names
            ):
                package_name = next(iter(package_names), import_name)
                missing.append(
                    {
                        "import": import_name,
                        "package": package_name,
                        "files": list(files),
                    }
                )

        return missing

    def _find_outdated_dependencies(self, requirements: Dict) -> List[Dict]:
        """
        Find outdated dependencies.

        Args:
            requirements: Dictionary mapping package names to requirement info.

        Returns:
            List of outdated dependencies.
        """
        self.logger.info("Finding outdated dependencies")

        outdated = []

        # Use pip list --outdated if available
        try:
            cmd = ["pip", "list", "--outdated", "--format=json"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            if result.returncode == 0:
                pip_outdated = json.loads(result.stdout)

                for package in pip_outdated:
                    package_name = package["name"]
                    if package_name in requirements:
                        outdated.append(
                            {
                                "package": package_name,
                                "current_version": package["version"],
                                "latest_version": package["latest_version"],
                                "sources": requirements[package_name]["sources"],
                            }
                        )
        except (subprocess.SubprocessError, json.JSONDecodeError) as e:
            self.logger.warning(f"Could not check for outdated packages: {e}")

        return outdated

    def _check_dependency_conflicts(self, requirements: Dict) -> List[Dict]:
        """
        Check for dependency conflicts.

        Args:
            requirements: Dictionary mapping package names to requirement info.

        Returns:
            List of dependency conflicts.
        """
        self.logger.info("Checking for dependency conflicts")

        conflicts = []

        for package_name, package_info in requirements.items():
            specs = package_info["specs"]

            # Check for conflicting specs
            if len(specs) > 1:
                # Group specs by operator
                spec_groups = {}
                for op, version in specs:
                    if op not in spec_groups:
                        spec_groups[op] = []
                    spec_groups[op].append(version)

                # Check for conflicts
                if "==" in spec_groups and len(spec_groups["=="]) > 1:
                    conflicts.append(
                        {
                            "package": package_name,
                            "conflicting_specs": specs,
                            "sources": package_info["sources"],
                        }
                    )
                # More complex version conflicts would need a SAT solver

        return conflicts

    def _check_vulnerabilities(self, requirements: Dict) -> List[Dict]:
        """
        Check for security vulnerabilities.

        Args:
            requirements: Dictionary mapping package names to requirement info.

        Returns:
            List of vulnerability reports.
        """
        self.logger.info("Checking for vulnerabilities")

        vulnerabilities = []

        if not self.settings["check_vulnerabilities"]:
            return vulnerabilities

        # Try using safety if available
        try:
            # Create a temporary requirements file
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp:
                for package_name, package_info in requirements.items():
                    if specs := package_info["specs"]:
                        # Use the first spec as an example
                        op, version = specs[0]
                        temp.write(f"{package_name}{op}{version}\n")
                    else:
                        temp.write(f"{package_name}\n")

                temp_path = temp.name

            # Run safety check
            cmd = ["safety", "check", "--json", "-r", temp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # Clean up temp file
            os.unlink(temp_path)

            if result.returncode == 0:
                safety_result = json.loads(result.stdout)

                for vuln in safety_result["vulnerabilities"]:
                    package_name = vuln["package_name"]
                    vulnerabilities.append(
                        {
                            "package": package_name,
                            "vulnerable_version": vuln["vulnerable_version"],
                            "safe_version": vuln.get("fixed_version", "unknown"),
                            "vulnerability_id": vuln["vulnerability_id"],
                            "description": vuln.get("description", ""),
                            "sources": requirements.get(package_name, {}).get(
                                "sources", []
                            ),
                        }
                    )

        except (
            subprocess.SubprocessError,
            json.JSONDecodeError,
            FileNotFoundError,
        ) as e:
            self.logger.warning(f"Could not check for vulnerabilities: {e}")

        return vulnerabilities

    def _update_requirements(
        self, current_requirements: Dict, missing: List[Dict], outdated: List[Dict]
    ) -> List[str]:
        """
        Update requirements files.

        Args:
            current_requirements: Dictionary mapping package names to requirement info.
            missing: List of missing dependencies.
            outdated: List of outdated dependencies.

        Returns:
            List of updated file paths.
        """
        self.logger.info("Updating requirements files")

        updated_files = []

        # Determine which files to update
        main_requirements = self.project_path / "requirements.txt"
        dev_requirements = self.project_path / "requirements-dev.txt"

        # Create main requirements file if it doesn't exist
        if not main_requirements.exists() and (missing or outdated):
            with open(main_requirements, "w", encoding="utf-8") as f:
                f.write("# Generated by PS2 Dependency Manager\n\n")

            updated_files.append(str(main_requirements))

        # Update existing requirements files
        if main_requirements.exists():
            self._update_requirements_txt(
                main_requirements, missing, outdated, dev=False
            )
            updated_files.append(str(main_requirements))

        # Create/update dev requirements if tracking dev dependencies
        if self.settings["track_dev_dependencies"] and dev_requirements.exists():
            self._update_requirements_txt(dev_requirements, missing, outdated, dev=True)
            updated_files.append(str(dev_requirements))

        return updated_files

    def _update_requirements_txt(
        self,
        file_path: Path,
        missing: List[Dict],
        outdated: List[Dict],
        dev: bool = False,
    ) -> None:
        """
        Update a requirements.txt file.

        Args:
            file_path: Path to requirements.txt file.
            missing: List of missing dependencies.
            outdated: List of outdated dependencies.
            dev: Whether this is a dev requirements file.
        """
        try:
            # Read existing requirements
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Extract existing packages
            existing_packages = {}
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    with contextlib.suppress(ValueError, pkg_resources.RequirementParseError):
                        req = pkg_resources.Requirement.parse(line)
                        existing_packages[req.name] = line
            # Update with missing packages
            for missing_dep in missing:
                package_name = missing_dep["package"]
                if package_name not in existing_packages:
                    # Get latest version if available
                    version = self._get_latest_version(package_name)
                    if version and self.settings["pin_versions"]:
                        existing_packages[package_name] = f"{package_name}=={version}"
                    else:
                        existing_packages[package_name] = package_name

            # Update outdated packages
            for outdated_dep in outdated:
                package_name = outdated_dep["package"]
                if package_name in existing_packages and self.settings["pin_versions"]:
                    latest_version = outdated_dep["latest_version"]
                    existing_packages[package_name] = (
                        f"{package_name}=={latest_version}"
                    )

            # Write updated requirements
            with open(file_path, "w", encoding="utf-8") as f:
                # Write header
                f.write("# Updated by PS2 Dependency Manager\n")
                f.write(f"# Last updated: {self._get_current_datetime()}" + "\n\n")

                # Write packages
                for package_name in sorted(existing_packages.keys()):
                    f.write(existing_packages[package_name] + "\n")

        except (UnicodeDecodeError, PermissionError) as e:
            self.logger.warning(f"Could not update {file_path}: {e}")

    def _get_latest_version(self, package_name: str) -> Optional[str]:
        """
        Get the latest version of a package.

        Args:
            package_name: Name of the package.

        Returns:
            Latest version string or None if unavailable.
        """
        try:
            cmd = ["pip", "index", "versions", package_name]
            result = subprocess.run(
                cmd, capture_output=True, text=True, check=False, timeout=10
            )

            if result.returncode == 0:
                # Parse output to find the latest version
                output = result.stdout
                if version_match := re.search(
                    r"Available versions: ([\d\.]+)", output
                ):
                    return version_match[1]

        except (subprocess.SubprocessError, TimeoutError) as e:
            self.logger.warning(f"Could not get latest version for {package_name}: {e}")

        return None

    def _get_current_datetime(self) -> str:
        """
        Get current datetime as string.

        Returns:
            Current datetime string.
        """
        from datetime import datetime

        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _get_stdlib_modules(self) -> Set[str]:
        """
        Get list of standard library modules.

        Returns:
            Set of standard library module names.
        """
        # This is a simplified list, a complete list would be much longer
        return {
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

    def _get_package_import_mapping(self) -> Dict[str, List[str]]:
        """
        Get mapping from package names to import names.

        Returns:
            Dictionary mapping package names to lists of import names.
        """
        # This is a mapping for common packages that have different import names
        return {
            "beautifulsoup4": ["bs4"],
            "python-dateutil": ["dateutil"],
            "pillow": ["PIL"],
            "pyyaml": ["yaml"],
            "scikit-learn": ["sklearn"],
            "pyjwt": ["jwt"],
            "psycopg2-binary": ["psycopg2"],
            "setuptools": ["pkg_resources", "setuptools"],
            "python-dotenv": ["dotenv"],
            "greenlet": ["_greenlet"],
            "importlib-metadata": ["importlib_metadata", "importlib.metadata"],
        }

    def _get_import_package_mapping(self) -> Dict[str, List[str]]:
        """
        Get mapping from import names to package names.

        Returns:
            Dictionary mapping import names to lists of package names.
        """
        # Reverse the package_to_import mapping
        import_to_package = {}
        for package, imports in self._get_package_import_mapping().items():
            for import_name in imports:
                if import_name not in import_to_package:
                    import_to_package[import_name] = []
                import_to_package[import_name].append(package)

        return import_to_package
