#!/usr/bin/env python3
"""
Python Standards Suite (PS2) - Main Controller Module.

This module serves as the central orchestrator for the PS2 system,
providing a unified interface to access all PS2 functionality.
"""

import os
import sys
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from ps2.config import default_settings
from ps2.core.analyzer import CodeAnalyzer
from ps2.core.code_quality import CodeQualityEnforcer
from ps2.core.conflict_resolver import ConflictResolver
from ps2.core.dependency_manager import DependencyManager
from ps2.core.duplication_detector import DuplicationDetector
from ps2.core.import_enforcer import ImportEnforcer
from ps2.core.performance_monitor import PerformanceMonitor
from ps2.core.project_generator import ProjectGenerator
from ps2.core.security_scanner import SecurityScanner
from ps2.core.task_manager import TaskManager
from ps2.utils.logging_utils import setup_logging
from ps2.utils.file_operations import get_project_root


class PS2:
    """
    Main controller class for the Python Standards Suite.

    This class provides a unified interface to access all functionality
    of the PS2 system, allowing seamless integration into development
    workflows and enforcing consistent Python coding standards.
    """

    def __init__(
        self,
        project_path: Optional[str] = None,
        config_path: Optional[str] = None,
        log_level: int = logging.INFO,
        enable_all: bool = True,
    ):
        """
        Initialize the PS2 controller.

        Args:
            project_path: Path to the target Python project. If None, attempts to detect.
            config_path: Path to custom configuration. If None, uses default.
            log_level: Logging level for PS2 operations.
            enable_all: Whether to enable all PS2 features by default.
        """
        # Setup logging
        self.logger = setup_logging(log_level)
        self.logger.info("Initializing Python Standards Suite (PS2)")

        # Determine project path
        self.project_path = self._determine_project_path(project_path)
        self.logger.info(f"Using project path: {self.project_path}")

        # Load configuration
        self.config = self._load_configuration(config_path)

        # Initialize core components
        self.project_generator = ProjectGenerator(self.project_path, self.config)
        self.code_analyzer = CodeAnalyzer(self.project_path, self.config)
        self.code_quality = CodeQualityEnforcer(self.project_path, self.config)
        self.conflict_resolver = ConflictResolver(self.project_path, self.config)
        self.dependency_manager = DependencyManager(self.project_path, self.config)
        self.duplication_detector = DuplicationDetector(self.project_path, self.config)
        self.import_enforcer = ImportEnforcer(self.project_path, self.config)
        self.performance_monitor = PerformanceMonitor(self.project_path, self.config)
        self.security_scanner = SecurityScanner(self.project_path, self.config)
        self.task_manager = TaskManager(self.project_path, self.config)

        # Apply initial configuration
        if enable_all:
            self.enable_all_features()

    def _determine_project_path(self, provided_path: Optional[str]) -> Path:
        """
        Determine the target project path.

        Args:
            provided_path: User-provided path or None.

        Returns:
            Path object representing the project root.
        """
        if provided_path:
            path = Path(provided_path).absolute()
            if not path.exists():
                self.logger.warning(f"Provided path does not exist: {path}")
                self.logger.info("Creating directory")
                path.mkdir(parents=True, exist_ok=True)
            return path

        # Try to auto-detect project root
        return get_project_root()

    def _load_configuration(self, config_path: Optional[str]) -> Dict:
        """
        Load PS2 configuration from file or use defaults.

        Args:
            config_path: Path to configuration file or None.

        Returns:
            Configuration dictionary.
        """
        if config_path:
            # TODO: Implement custom configuration loading
            self.logger.info(f"Loading configuration from: {config_path}")
            # For now, just use default settings
            return default_settings.get_default_config()

        self.logger.info("Using default configuration")
        return default_settings.get_default_config()

    def enable_all_features(self) -> None:
        """Enable all PS2 features and enforcements."""
        self.logger.info("Enabling all PS2 features")
        # Configure each component to be active
        for component in self._get_components():
            component.enable()

    def _get_components(self) -> List:
        """Return a list of all core components."""
        return [
            self.project_generator,
            self.code_analyzer,
            self.code_quality,
            self.conflict_resolver,
            self.dependency_manager,
            self.duplication_detector,
            self.import_enforcer,
            self.performance_monitor,
            self.security_scanner,
            self.task_manager,
        ]

    def generate_project(
        self, project_name: str, project_type: str = "standard"
    ) -> Path:
        """
        Generate a new Python project with PS2 standards.

        Args:
            project_name: Name of the new project.
            project_type: Type of project template to use.

        Returns:
            Path to the generated project.
        """
        self.logger.info(
            f"Generating new project: {project_name} (type: {project_type})"
        )
        return self.project_generator.generate_project(project_name, project_type)

    def check_code_quality(self, fix: bool = False) -> Dict:
        """
        Check code quality against PS2 standards.

        Args:
            fix: Whether to automatically fix issues where possible.

        Returns:
            Dictionary with check results.
        """
        self.logger.info(f"Checking code quality (auto-fix: {fix})")
        return self.code_quality.check(fix=fix)

    def detect_conflicts(self, fix: bool = False) -> Dict:
        """
        Detect naming conflicts and other issues.

        Args:
            fix: Whether to automatically fix conflicts where possible.

        Returns:
            Dictionary with detected conflicts.
        """
        self.logger.info(f"Detecting conflicts (auto-fix: {fix})")
        return self.conflict_resolver.detect_conflicts(fix=fix)

    def manage_dependencies(self, update: bool = False) -> Dict:
        """
        Manage project dependencies.

        Args:
            update: Whether to update dependencies to latest compatible versions.

        Returns:
            Dictionary with dependency information.
        """
        self.logger.info(f"Managing dependencies (update: {update})")
        return self.dependency_manager.manage(update=update)

    def detect_duplications(self, fix: bool = False) -> Dict:
        """
        Detect code duplications.

        Args:
            fix: Whether to automatically fix duplications where possible.

        Returns:
            Dictionary with duplication information.
        """
        self.logger.info(f"Detecting code duplications (auto-fix: {fix})")
        return self.duplication_detector.detect(fix=fix)

    def enforce_imports(self, fix: bool = False) -> Dict:
        """
        Enforce import standards.

        Args:
            fix: Whether to automatically fix import issues.

        Returns:
            Dictionary with import check results.
        """
        self.logger.info(f"Enforcing import standards (auto-fix: {fix})")
        return self.import_enforcer.enforce(fix=fix)

    def monitor_performance(self, duration: int = 3600) -> Dict:
        """
        Monitor code performance.

        Args:
            duration: How long to monitor performance (in seconds).

        Returns:
            Dictionary with performance metrics.
        """
        self.logger.info(f"Monitoring performance (duration: {duration}s)")
        return self.performance_monitor.monitor(duration=duration)

    def scan_security(self, fix: bool = False) -> Dict:
        """
        Scan for security issues.

        Args:
            fix: Whether to automatically fix security issues where possible.

        Returns:
            Dictionary with security scan results.
        """
        self.logger.info(f"Scanning for security issues (auto-fix: {fix})")
        return self.security_scanner.scan(fix=fix)

    def generate_tasks(self) -> Dict:
        """
        Generate task list for manual intervention.

        Returns:
            Dictionary with tasks that require manual attention.
        """
        self.logger.info("Generating task list")
        return self.task_manager.generate_tasks()

    def analyze_codebase(self) -> Dict:
        """
        Perform comprehensive codebase analysis.

        Returns:
            Dictionary with analysis results.
        """
        self.logger.info("Analyzing codebase")
        return self.code_analyzer.analyze()

    def run_all_checks(self, fix: bool = False) -> Dict:
        """
        Run all PS2 checks on the project.

        Args:
            fix: Whether to automatically fix issues where possible.

        Returns:
            Dictionary with comprehensive check results.
        """
        self.logger.info(f"Running all PS2 checks (auto-fix: {fix})")
        results = {"code_quality": self.check_code_quality(fix=fix)}

        results["conflicts"] = self.detect_conflicts(fix=fix)
        results["dependencies"] = self.manage_dependencies(update=False)
        results["duplications"] = self.detect_duplications(fix=fix)
        results["imports"] = self.enforce_imports(fix=fix)
        results["security"] = self.scan_security(fix=fix)

        # Generate tasks for unresolved issues
        results["tasks"] = self.generate_tasks()

        return results

    def install_git_hooks(self) -> bool:
        """
        Install PS2 git hooks for the project.

        Returns:
            True if successful, False otherwise.
        """
        self.logger.info("Installing git hooks")
        # TODO: Implement git hook installation
        return True

    def setup_ci_pipeline(self, ci_type: str = "github") -> bool:
        """
        Set up CI pipeline for the project.

        Args:
            ci_type: Type of CI system to configure.

        Returns:
            True if successful, False otherwise.
        """
        self.logger.info(f"Setting up CI pipeline (type: {ci_type})")
        # TODO: Implement CI pipeline setup
        return True


def initialize_ps2(
    project_path: Optional[str] = None,
    config_path: Optional[str] = None,
    log_level: int = logging.INFO,
) -> PS2:
    """
    Initialize a new PS2 instance with given parameters.

    Args:
        project_path: Path to the target Python project.
        config_path: Path to custom configuration.
        log_level: Logging level for PS2 operations.

    Returns:
        Configured PS2 instance.
    """
    return PS2(project_path, config_path, log_level)


# Allow direct execution
if __name__ == "__main__":
    # If executed directly, pass control to CLI
    from ps2.cli.main import main

    sys.exit(main())
