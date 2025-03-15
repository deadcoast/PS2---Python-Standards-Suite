"""
Integrations Package for PS2.

This package provides integration with external systems such as issue trackers
and notification services, allowing PS2 to interact with development workflows.
"""

from src.integrations.issue_trackers import (
    register_issue_tracker,
    get_issue_tracker,
    create_issue,
    update_issue,
    get_issue_status,
    list_issues,
)

from src.integrations.notifications import (
    send_notification,
    register_notification_service,
    get_notification_service,
)
