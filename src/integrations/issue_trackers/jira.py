"""
Jira Issue Tracker Adapter for PS2.

This module provides integration with Jira, allowing PS2
to create, update, and query issues in Jira projects.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Union

from ps2.integrations.issue_trackers import IssueTrackerAdapter

# Try to import Jira client
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    requests = None


class JiraAdapter(IssueTrackerAdapter):
    """Adapter for Jira integration."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Jira issue tracker adapter.

        Args:
            config: Configuration dictionary for the adapter.
        """
        super().__init__(config)
        self.base_url = config.get("url")
        if self.base_url and not self.base_url.endswith("/"):
            self.base_url += "/"
        self.api_path = "rest/api/2"
        self.username = config.get("username")
        self.api_token = config.get("api_token")
        self.project_key = config.get("project_key")

        # Set up auth and headers
        self.auth = HTTPBasicAuth(self.username, self.api_token)
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
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
                "requests package is required for Jira integration. "
                "Install it with 'pip install requests'"
            )

        if not self.base_url:
            raise ValueError("Jira configuration missing 'url'")

        if not self.username:
            raise ValueError("Jira configuration missing 'username'")

        if not self.api_token:
            raise ValueError("Jira configuration missing 'api_token'")

        if not self.project_key:
            raise ValueError("Jira configuration missing 'project_key'")

        # Validate URL format
        if not re.match(r"^https?://", self.base_url):
            raise ValueError(f"Invalid Jira URL: {self.base_url}")

        # Validate project key format (typically uppercase letters and numbers)
        if not re.match(r"^[A-Z][A-Z0-9_]+$", self.project_key):
            raise ValueError(f"Invalid Jira project key: {self.project_key}")

    def create_issue(
        self,
        title: str,
        description: str,
        labels: List[str],
        assignees: List[str],
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Create an issue in Jira.

        Args:
            title: Issue title (summary in Jira).
            description: Issue description.
            labels: List of labels to apply to the issue.
            assignees: List of users to assign to the issue (only first is used in Jira).
            **kwargs: Additional Jira-specific arguments:
                - issue_type: Jira issue type (default: "Bug")
                - priority: Jira priority (default: "Medium")
                - components: List of component names
                - custom_fields: Dict of custom field ID to value

        Returns:
            Dictionary with created issue information.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.base_url}{self.api_path}/issue"

        # Set default issue type
        issue_type = kwargs.get("issue_type", "Bug")

        # Prepare fields
        fields = {
            "project": {"key": self.project_key},
            "summary": title,
            "description": description,
            "issuetype": {"name": issue_type},
            "labels": labels,
        }

        # Add priority if specified
        if "priority" in kwargs:
            fields["priority"] = {"name": kwargs["priority"]}

        # Add components if specified
        if "components" in kwargs and kwargs["components"]:
            fields["components"] = [{"name": c} for c in kwargs["components"]]

        # Add assignee if specified (Jira only supports one assignee)
        if assignees:
            fields["assignee"] = {"name": assignees[0]}

        # Add custom fields if specified
        if "custom_fields" in kwargs:
            for field_id, value in kwargs["custom_fields"].items():
                fields[field_id] = value

        data = {"fields": fields}

        response = requests.post(url, headers=self.headers, auth=self.auth, json=data)
        response.raise_for_status()

        # Get the created issue details
        issue_data = response.json()
        issue_key = issue_data.get("key")

        # Fetch the full issue details
        return self._get_issue_by_key(issue_key)

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
        Update an existing issue in Jira.

        Args:
            issue_id: Key of the issue to update (e.g., "PROJ-123").
            title: New issue title/summary (if changing).
            description: New issue description (if changing).
            status: New issue status (if changing).
            labels: New list of labels (if changing).
            assignees: New list of assignees (if changing, only first used).
            **kwargs: Additional Jira-specific arguments:
                - priority: New priority
                - components: New list of components
                - custom_fields: Dict of custom field ID to value

        Returns:
            Dictionary with updated issue information.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.base_url}{self.api_path}/issue/{issue_id}"

        fields = {}

        if title is not None:
            fields["summary"] = title

        if description is not None:
            fields["description"] = description

        if labels is not None:
            fields["labels"] = labels

        if assignees is not None and assignees:
            fields["assignee"] = {"name": assignees[0]}

        # Add priority if specified
        if "priority" in kwargs:
            fields["priority"] = {"name": kwargs["priority"]}

        # Add components if specified
        if "components" in kwargs:
            fields["components"] = [{"name": c} for c in kwargs["components"]]

        # Add custom fields if specified
        if "custom_fields" in kwargs:
            for field_id, value in kwargs["custom_fields"].items():
                fields[field_id] = value

        data = {"fields": fields}

        # Update the issue fields
        if fields:
            response = requests.put(
                url, headers=self.headers, auth=self.auth, json=data
            )
            response.raise_for_status()

        # Handle status change if specified
        if status is not None:
            self._transition_issue(issue_id, status)

        # Get the updated issue
        return self._get_issue_by_key(issue_id)

    def _transition_issue(self, issue_id: str, status: str) -> None:
        """
        Transition an issue to a new status.

        Args:
            issue_id: Key of the issue to transition.
            status: Target status name.

        Raises:
            ValueError: If the status transition is not available.
            requests.RequestException: If the API request fails.
        """
        # Get available transitions
        transitions_url = f"{self.base_url}{self.api_path}/issue/{issue_id}/transitions"
        response = requests.get(transitions_url, headers=self.headers, auth=self.auth)
        response.raise_for_status()

        transitions = response.json().get("transitions", [])

        # Find the transition ID for the target status
        transition_id = None
        for transition in transitions:
            if transition["to"]["name"].lower() == status.lower():
                transition_id = transition["id"]
                break

        if not transition_id:
            available_statuses = [t["to"]["name"] for t in transitions]
            raise ValueError(
                f"Status '{status}' is not available. Available statuses: {available_statuses}"
            )

        # Execute the transition
        data = {"transition": {"id": transition_id}}

        response = requests.post(
            transitions_url, headers=self.headers, auth=self.auth, json=data
        )
        response.raise_for_status()

    def _get_issue_by_key(self, issue_key: str) -> Dict[str, Any]:
        """
        Get issue details by key.

        Args:
            issue_key: Jira issue key.

        Returns:
            Issue details dictionary.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.base_url}{self.api_path}/issue/{issue_key}"

        response = requests.get(url, headers=self.headers, auth=self.auth)
        response.raise_for_status()

        return response.json()

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
        Get issues from Jira with optional filtering.

        Args:
            project: Project key to filter issues by (overrides config project_key).
            status: Issue status(es) to filter by.
            labels: Labels to filter issues by.
            assignee: Assignee to filter issues by.
            limit: Maximum number of issues to return.
            **kwargs: Additional Jira-specific filter arguments:
                - jql: Raw JQL query string (overrides other filters)
                - issue_type: Filter by issue type
                - components: Filter by components
                - priority: Filter by priority
                - text_search: Search in summary and description
                - created_after: Filter by creation date
                - updated_after: Filter by update date

        Returns:
            List of issue dictionaries.

        Raises:
            requests.RequestException: If the API request fails.
        """
        url = f"{self.base_url}{self.api_path}/search"

        # Use custom JQL if provided
        if "jql" in kwargs:
            jql = kwargs["jql"]
        else:
            # Build JQL query from parameters
            jql_parts = []

            # Project filter
            project_key = project or self.project_key
            jql_parts.append(f'project = "{project_key}"')

            # Status filter
            if status:
                if isinstance(status, list):
                    status_clause = " OR ".join(f'status = "{s}"' for s in status)
                    jql_parts.append(f"({status_clause})")
                else:
                    jql_parts.append(f'status = "{status}"')

            # Labels filter
            if labels:
                for label in labels:
                    jql_parts.append(f'labels = "{label}"')

            # Assignee filter
            if assignee:
                jql_parts.append(f'assignee = "{assignee}"')

            # Issue type filter
            if "issue_type" in kwargs:
                jql_parts.append(f'issuetype = "{kwargs["issue_type"]}"')

            # Components filter
            if "components" in kwargs and kwargs["components"]:
                components_clause = " OR ".join(
                    f'component = "{c}"' for c in kwargs["components"]
                )
                jql_parts.append(f"({components_clause})")

            # Priority filter
            if "priority" in kwargs:
                jql_parts.append(f'priority = "{kwargs["priority"]}"')

            # Text search filter
            if "text_search" in kwargs:
                jql_parts.append(f'text ~ "{kwargs["text_search"]}"')

            # Created after filter
            if "created_after" in kwargs:
                jql_parts.append(f'created >= "{kwargs["created_after"]}"')

            # Updated after filter
            if "updated_after" in kwargs:
                jql_parts.append(f'updated >= "{kwargs["updated_after"]}"')

            jql = " AND ".join(jql_parts)

        params = {"jql": jql, "maxResults": limit or 50, "startAt": 0}

        all_issues = []

        # Handle pagination
        while True:
            response = requests.get(
                url, headers=self.headers, auth=self.auth, params=params
            )
            response.raise_for_status()

            data = response.json()
            issues = data.get("issues", [])

            if not issues:
                break

            all_issues.extend(issues)

            # Check if we've reached the limit
            if limit and len(all_issues) >= limit:
                all_issues = all_issues[:limit]
                break

            # Check if there are more issues
            max_results = data.get("maxResults", 0)
            total = data.get("total", 0)
            start_at = data.get("startAt", 0)

            if start_at + max_results >= total:
                break

            # Update startAt for next page
            params["startAt"] = start_at + max_results

        return all_issues


def configure(config: Dict[str, Any]) -> JiraAdapter:
    """
    Configure and return a Jira issue tracker adapter.

    Args:
        config: Configuration dictionary for the adapter.

    Returns:
        Configured JiraAdapter instance.
    """
    return JiraAdapter(config)
