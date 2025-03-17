"""
GitHub Issue Tracker Adapter for PS2.

This module provides integration with GitHub Issues, allowing PS2
to create, update, and query issues in GitHub repositories.
"""

import re
from typing import Any, Dict, List, Optional, Union

# Try to import GitHub API client
try:
    import requests
except ImportError:
    requests = None

# Import the base adapter class
from src.integrations.issue_trackers import IssueTrackerAdapter


class GitHubAdapter(IssueTrackerAdapter):
    """Adapter for GitHub Issues integration."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the GitHub issue tracker adapter.

        Args:
            config: Configuration dictionary for the adapter.
        """
        super().__init__(config)
        self.api_base_url = "https://api.github.com"
        self.repo_owner = config.get("owner")
        self.repo_name = config.get("repo")
        self.token = config.get("token")
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": f"token {self.token}",
            "User-Agent": "PS2-GitHub-Adapter",
        }

    def validate_config(self) -> None:
        """
        Validate the adapter configuration.

        Raises:
            ValueError: If the configuration is invalid.
            ImportError: If requests is not installed.
        """
        if requests is None:
            raise ImportError(
                "requests package is required for GitHub integration. "
                "Install it with 'pip install requests'"
            )

        if not self.repo_owner:
            raise ValueError("GitHub configuration missing 'owner'")

        if not self.repo_name:
            raise ValueError("GitHub configuration missing 'repo'")

        if not self.token:
            raise ValueError("GitHub configuration missing 'token'")

        # Validate repository owner/name format
        if not re.match(r"^[a-zA-Z0-9_.-]+$", self.repo_owner):
            raise ValueError(f"Invalid GitHub repository owner: {self.repo_owner}")

        if not re.match(r"^[a-zA-Z0-9_.-]+$", self.repo_name):
            raise ValueError(f"Invalid GitHub repository name: {self.repo_name}")

    def create_issue(
        self,
        title: str,
        description: str,
        labels: List[str],
        assignees: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create an issue in GitHub.

        Args:
            title: Issue title.
            description: Issue description.
            labels: List of labels to apply to the issue.
            assignees: List of users to assign to the issue.
            **kwargs: Additional GitHub-specific arguments.

        Returns:
            Dictionary with created issue information.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.api_base_url}/repos/{self.repo_owner}/{self.repo_name}/issues"

        data = {
            "title": title,
            "body": description,
            "labels": labels,
            "assignees": assignees,
        }

        # Add optional parameters
        if "milestone" in kwargs:
            data["milestone"] = kwargs["milestone"]

        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()

        return response.json()

    def update_issue(
        self,
        issue_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        labels: Optional[List[str]] = None,
        assignees: Optional[List[str]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Update an existing issue in GitHub.

        Args:
            issue_id: Number of the issue to update.
            title: New issue title (if changing).
            description: New issue description (if changing).
            status: New issue status (if changing, either "open" or "closed").
            labels: New list of labels (if changing).
            assignees: New list of assignees (if changing).
            **kwargs: Additional GitHub-specific arguments.

        Returns:
            Dictionary with updated issue information.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.api_base_url}/repos/{self.repo_owner}/{self.repo_name}/issues/{issue_id}"

        data = {}

        if title is not None:
            data["title"] = title

        if description is not None:
            data["body"] = description

        if status is not None:
            data["state"] = status.lower()

        if labels is not None:
            data["labels"] = labels

        if assignees is not None:
            data["assignees"] = assignees

        # Add optional parameters
        if "milestone" in kwargs:
            data["milestone"] = kwargs["milestone"]

        response = requests.patch(url, headers=self.headers, json=data)
        response.raise_for_status()

        return response.json()

    def _build_github_params(
        self,
        status: Optional[Union[str, List[str]]] = None,
        labels: Optional[List[str]] = None,
        assignee: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Build GitHub API request parameters from the provided filters.

        Args:
            status: Issue status(es) to filter by
            labels: Labels to filter issues by
            assignee: Assignee to filter issues by
            **kwargs: Additional GitHub-specific filter arguments

        Returns:
            Dictionary of request parameters
        """
        params = {}

        # GitHub state filter (open, closed, all)
        if status:
            params["state"] = "all" if isinstance(status, list) else status.lower()
        else:
            params["state"] = "open"  # Default to open issues

        # Labels filter
        if labels:
            params["labels"] = ",".join(labels)

        # Assignee filter
        if assignee:
            params["assignee"] = assignee

        # Add filter for creator if specified
        if "creator" in kwargs:
            params["creator"] = kwargs["creator"]

        # Add filter for mentioned user if specified
        if "mentioned" in kwargs:
            params["mentioned"] = kwargs["mentioned"]

        # Add sort and direction
        params["sort"] = kwargs.get("sort", "created")
        params["direction"] = kwargs.get("direction", "desc")

        return params

    def _fetch_paginated_issues(
        self, url: str, params: Dict[str, Any], limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch issues with pagination support.

        Args:
            url: API endpoint URL
            params: Request parameters
            limit: Maximum number of issues to return

        Returns:
            List of issue dictionaries

        Raises:
            requests.RequestException: If the API request fails
        """
        all_issues = []
        page = 1
        per_page = min(100, limit or 100)  # GitHub max per page is 100
        request_params = params.copy()

        while True:
            request_params["page"] = page
            request_params["per_page"] = per_page

            response = requests.get(url, headers=self.headers, params=request_params)
            response.raise_for_status()

            issues = response.json()

            if not issues:
                break

            all_issues.extend(issues)

            # Check if we've reached the limit
            if limit and len(all_issues) >= limit:
                return all_issues[:limit]

            # Check if there are more pages
            if len(issues) < per_page:
                break

            page += 1

        return all_issues

    def _filter_by_status_list(
        self, issues: List[Dict[str, Any]], status: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Filter issues by a list of status values.

        Args:
            issues: List of issue dictionaries
            status: List of status values to filter by

        Returns:
            Filtered list of issue dictionaries
        """
        status_values = [s.lower() for s in status]
        return [issue for issue in issues if issue.get("state") in status_values]

    def get_issues(
        self,
        project: Optional[str] = None,
        status: Optional[Union[str, List[str]]] = None,
        labels: Optional[List[str]] = None,
        assignee: Optional[str] = None,
        limit: Optional[int] = None,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """
        Get issues from GitHub with optional filtering.

        Args:
            project: Not used for GitHub (repository is specified in config).
            status: Issue status(es) to filter by ("open" or "closed").
            labels: Labels to filter issues by.
            assignee: Assignee to filter issues by.
            limit: Maximum number of issues to return.
            **kwargs: Additional GitHub-specific filter arguments.

        Returns:
            List of issue dictionaries.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.api_base_url}/repos/{self.repo_owner}/{self.repo_name}/issues"

        # Build request parameters
        params = self._build_github_params(status, labels, assignee, **kwargs)

        # Fetch issues with pagination
        all_issues = self._fetch_paginated_issues(url, params, limit)

        # Apply additional filtering for status if multiple statuses were provided
        if status and isinstance(status, list):
            all_issues = self._filter_by_status_list(all_issues, status)

            # Re-apply limit if needed after filtering
            if limit and len(all_issues) > limit:
                all_issues = all_issues[:limit]

        return all_issues


def configure(config: Dict[str, Any]) -> GitHubAdapter:
    """
    Configure and return a GitHub issue tracker adapter.

    Args:
        config: Configuration dictionary for the adapter.

    Returns:
        Configured GitHubAdapter instance.
    """
    return GitHubAdapter(config)
