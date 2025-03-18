"""
Notifications Integration Package for PS2.

This package provides integration with external notification systems,
allowing PS2 to send notifications via email, Slack, and other
communication platforms.
"""

from typing import (  # TODO: Remove unused imports; TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
    Any,
    Dict,
    List,
    Optional,
    Union,
)

_configured_services = {}

# Logger
logger = logging.getLogger("ps2.integrations.notifications")


def register_notification_service(
    service_type: str, config: Dict[str, Any]
) -> Optional[object]:
    """
    Register and configure a notification service integration.

    Args:
        service_type: Type of notification service (e.g., 'email', 'slack').
        config: Configuration dictionary for the notification service.

    Returns:
        Configured notification service instance or None if registration fails.

    Raises:
        ValueError: If the service type is not supported.
        ImportError: If the service module cannot be imported.
    """
    # Check if service type is supported
    if service_type not in supported_notification_services():
        raise ValueError(f"Unsupported notification service type: {service_type}")

    try:
        # Import the appropriate adapter module
        module_name = f"ps2.integrations.notifications.{service_type}"
        adapter_module = importlib.import_module(module_name)

        # Create and configure the service adapter
        service = adapter_module.configure(config)

        # Store in configured services
        _configured_services[service_type] = service

        logger.info(f"Successfully registered {service_type} notification service")
        return service
    except ImportError:
        logger.error(f"Failed to import {service_type} notification service adapter")
        raise
    except Exception as e:
        logger.error(f"Failed to configure {service_type} notification service: {e}")
        raise


def send_notification(
    service_type: str,
    subject: str,
    message: str,
    recipients: List[str],
    importance: str = "normal",
    attachments: Optional[List[Dict[str, Any]]] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Send a notification using the specified service.

    Args:
        service_type: Type of notification service to use.
        subject: Notification subject or title.
        message: Notification message body.
        recipients: List of recipient identifiers (varies by service).
        importance: Importance level ("low", "normal", "high").
        attachments: List of attachment dictionaries.
        **kwargs: Additional service-specific arguments.

    Returns:
        Dictionary with notification result information.

    Raises:
        ValueError: If the service type is not configured.
    """
    # Check if service is configured
    if service_type not in _configured_services:
        raise ValueError(f"Notification service {service_type} is not configured")

    service = _configured_services[service_type]

    # Send the notification
    return service.send_notification(
        subject=subject,
        message=message,
        recipients=recipients,
        importance=importance,
        attachments=attachments or [],
        **kwargs,
    )


def supported_notification_services() -> List[str]:
    """
    Get a list of supported notification service types.

    Returns:
        List of supported notification service type names.
    """
    return ["email", "slack"]


# Base class for notification service adapters
class NotificationServiceAdapter:
    """Base class for notification service adapters."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the notification service adapter.

        Args:
            config: Configuration dictionary for the adapter.
        """
        self.config = config
        self.logger = logging.getLogger(
            f"ps2.integrations.notifications.{self.__class__.__name__}"
        )
        self.validate_config()

    def validate_config(self) -> None:
        """
        Validate the adapter configuration.

        Raises:
            ValueError: If the configuration is invalid.
        """
        raise NotImplementedError("Subclasses must implement validate_config()")

    def send_notification(
        self,
        subject: str,
        message: str,
        recipients: List[str],
        importance: str = "normal",
        attachments: Optional[List[Dict[str, Any]]] = None,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Send a notification using this service.

        Args:
            subject: Notification subject or title.
            message: Notification message body.
            recipients: List of recipient identifiers.
            importance: Importance level ("low", "normal", "high").
            attachments: List of attachment dictionaries.
            **kwargs: Additional service-specific arguments.

        Returns:
            Dictionary with notification result information.
        """
        raise NotImplementedError("Subclasses must implement send_notification()")
