"""
Issue Trackers Integration Package for PS2.

This package provides integration with external issue tracking systems,
allowing PS2 to create, update, and query issues in systems like GitHub,
Jira, and others.
"""

import importlib
import logging
from typing import Dict, List, Any, Optional, Union

_configured_trackers = {}

# Logger for issue trackers package
logger = logging.getLogger("src.integrations.issue_trackers")


def register_issue_tracker(
    tracker_type: str, config: Dict[str, Any]
) -> Optional[object]:
    """
    Register and configure an issue tracker integration.

    Args:
        tracker_type: Type of issue tracker (e.g., 'github', 'jira').
        config: Configuration dictionary for the issue tracker.

    Returns:
        Configured issue tracker instance or None if registration fails.

    Raises:
        ValueError: If the tracker type is not supported.
        ImportError: If the tracker module cannot be imported.
    """
    # Check if tracker type is supported
    if tracker_type not in supported_issue_trackers():
        raise ValueError(f"Unsupported issue tracker type: {tracker_type}")

    try:
        return _import_and_configure_tracker(tracker_type, config)
    except ImportError:
        logger.error(f"Failed to import {tracker_type} issue tracker adapter")
        raise
    except Exception as e:
        logger.error(f"Failed to configure {tracker_type} issue tracker: {e}")
        raise


def _import_and_configure_tracker(tracker_type: str, config: Dict[str, Any]) -> object:
    """
    Import the issue tracker module and configure the adapter.

    Args:
        tracker_type: Type of issue tracker to import and configure.
        config: Configuration dictionary for the issue tracker.

    Returns:
        Configured issue tracker instance.

    Raises:
        ImportError: If the tracker module cannot be imported.
    """
    # Import the appropriate adapter module
    module_name = f"ps2.integrations.issue_trackers.{tracker_type}"
    adapter_module = importlib.import_module(module_name)

    # Create and configure the tracker adapter
    tracker = adapter_module.configure(config)

    # Store in configured trackers
    _configured_trackers[tracker_type] = tracker

    logger.info(f"Successfully registered {tracker_type} issue tracker")
    return tracker


def create_issue(
    tracker_type: str,
    title: str,
    description: str,
    labels: Optional[List[str]] = None,
    assignees: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Create an issue in the specified issue tracker.

    Args:
        tracker_type: Type of issue tracker to use.
        title: Issue title.
        description: Issue description.
        labels: List of labels to apply to the issue.
        assignees: List of users to assign to the issue.
        **kwargs: Additional issue tracker-specific arguments.

    Returns:
        Dictionary with created issue information.

    Raises:
        ValueError: If the tracker type is not configured.
    """
    # Check if tracker is configured
    if tracker_type not in _configured_trackers:
        raise ValueError(f"Issue tracker {tracker_type} is not configured")

    tracker = _configured_trackers[tracker_type]

    # Create the issue
    return tracker.create_issue(
        title=title,
        description=description,
        labels=labels or [],
        assignees=assignees or [],
        **kwargs,
    )


def update_issue(
    tracker_type: str,
    issue_id: str,
    title: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    labels: Optional[List[str]] = None,
    assignees: Optional[List[str]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Update an existing issue in the specified issue tracker.

    Args:
        tracker_type: Type of issue tracker to use.
        issue_id: ID of the issue to update.
        title: New issue title (if changing).
        description: New issue description (if changing).
        status: New issue status (if changing).
        labels: New list of labels (if changing).
        assignees: New list of assignees (if changing).
        **kwargs: Additional issue tracker-specific arguments.

    Returns:
        Dictionary with updated issue information.

    Raises:
        ValueError: If the tracker type is not configured.
    """
    # Check if tracker is configured
    if tracker_type not in _configured_trackers:
        raise ValueError(f"Issue tracker {tracker_type} is not configured")

    tracker = _configured_trackers[tracker_type]

    # Update the issue
    return tracker.update_issue(
        issue_id=issue_id,
        title=title,
        description=description,
        status=status,
        labels=labels,
        assignees=assignees,
        **kwargs,
    )


def get_issues(
    tracker_type: str,
    project: Optional[str] = None,
    status: Optional[Union[str, List[str]]] = None,
    labels: Optional[List[str]] = None,
    assignee: Optional[str] = None,
    limit: Optional[int] = None,
    **kwargs,
) -> List[Dict[str, Any]]:
    """
    Get issues from the specified issue tracker with optional filtering.

    Args:
        tracker_type: Type of issue tracker to use.
        project: Project identifier to filter issues by.
        status: Issue status(es) to filter by.
        labels: Labels to filter issues by.
        assignee: Assignee to filter issues by.
        limit: Maximum number of issues to return.
        **kwargs: Additional issue tracker-specific filter arguments.

    Returns:
        List of issue dictionaries.

    Raises:
        ValueError: If the tracker type is not configured.
    """
    # Check if tracker is configured
    if tracker_type not in _configured_trackers:
        raise ValueError(f"Issue tracker {tracker_type} is not configured")

    tracker = _configured_trackers[tracker_type]

    # Get the issues
    return tracker.get_issues(
        project=project,
        status=status,
        labels=labels,
        assignee=assignee,
        limit=limit,
        **kwargs,
    )


def supported_issue_trackers() -> List[str]:
    """
    Get a list of supported issue tracker types.

    Returns:
        List of supported issue tracker type names.
    """
    return ["github", "jira"]


# Base class for issue tracker adapters
class IssueTrackerAdapter:
    """Base class for issue tracker adapters."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the issue tracker adapter.

        Args:
            config: Configuration dictionary for the adapter.
        """
        self.config = config
        self.logger = logging.getLogger(
            f"ps2.integrations.issue_trackers.{self.__class__.__name__}"
        )
        self.validate_config()

    def validate_config(self) -> None:
        """
        Validate the adapter configuration.

        Raises:
            ValueError: If the configuration is invalid.
        """
        raise NotImplementedError("Subclasses must implement validate_config()")

    def create_issue(
        self,
        title: str,
        description: str,
        labels: List[str],
        assignees: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create an issue in the issue tracker.

        Args:
            title: Issue title.
            description: Issue description.
            labels: List of labels to apply to the issue.
            assignees: List of users to assign to the issue.
            **kwargs: Additional issue-specific arguments.

        Returns:
            Dictionary with created issue information.
        """
        raise NotImplementedError("Subclasses must implement create_issue()")

    def update_issue(
        self,
        issue_id: str,
        title: Optional[str],
        description: Optional[str],
        status: Optional[str],
        labels: Optional[List[str]],
        assignees: Optional[List[str]],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Update an existing issue in the issue tracker.

        Args:
            issue_id: ID of the issue to update.
            title: New issue title (if changing).
            description: New issue description (if changing).
            status: New issue status (if changing).
            labels: New list of labels (if changing).
            assignees: New list of assignees (if changing).
            **kwargs: Additional issue-specific arguments.

        Returns:
            Dictionary with updated issue information.
        """
        raise NotImplementedError("Subclasses must implement update_issue()")

    def get_issues(
        self,
        project: Optional[str],
        status: Optional[Union[str, List[str]]],
        labels: Optional[List[str]],
        assignee: Optional[str],
        limit: Optional[int],
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """
        Get issues from the issue tracker with optional filtering.

        Args:
            project: Project identifier to filter issues by.
            status: Issue status(es) to filter by.
            labels: Labels to filter issues by.
            assignee: Assignee to filter issues by.
            limit: Maximum number of issues to return.
            **kwargs: Additional filter arguments.

        Returns:
            List of issue dictionaries.
        """
        raise NotImplementedError("Subclasses must implement get_issues()")
