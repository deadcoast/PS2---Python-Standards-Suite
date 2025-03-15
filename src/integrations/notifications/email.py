"""
Email Notification Adapter for PS2.

This module provides integration with SMTP email services, allowing
PS2 to send email notifications for code quality checks, security
scans, and other operations.
"""

import os
import re
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from typing import Dict, List, Any, Optional

from ps2.integrations.notifications import NotificationServiceAdapter


class EmailAdapter(NotificationServiceAdapter):
    """Adapter for Email notification integration."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the email notification adapter.

        Args:
            config: Configuration dictionary for the adapter.
        """
        super().__init__(config)
        self.smtp_server = config.get("smtp_server")
        self.smtp_port = config.get("smtp_port", 587)
        self.username = config.get("username")
        self.password = config.get("password")
        self.use_ssl = config.get("use_ssl", False)
        self.use_tls = config.get("use_tls", True)
        self.default_sender = config.get("default_sender")

    def validate_config(self) -> None:
        """
        Validate the adapter configuration.

        Raises:
            ValueError: If the configuration is invalid.
        """
        if not self.smtp_server:
            raise ValueError("Email configuration missing 'smtp_server'")

        if not isinstance(self.smtp_port, int):
            raise ValueError("Email configuration 'smtp_port' must be an integer")

        if not self.username:
            raise ValueError("Email configuration missing 'username'")

        if not self.password:
            raise ValueError("Email configuration missing 'password'")

        if not self.default_sender:
            raise ValueError("Email configuration missing 'default_sender'")

        # Validate email address format
        if not self._validate_email(self.default_sender):
            raise ValueError(f"Invalid default sender email: {self.default_sender}")

    def _validate_email(self, email: str) -> bool:
        """
        Validate an email address format.

        Args:
            email: Email address to validate.

        Returns:
            True if the email format is valid, False otherwise.
        """
        # Simple regex for basic email validation
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return bool(re.match(pattern, email))

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
        Send an email notification.

        Args:
            subject: Email subject.
            message: Email message body (can be HTML if html_message=True).
            recipients: List of recipient email addresses.
            importance: Importance level ("low", "normal", "high").
            attachments: List of attachment dictionaries, each with:
                - path: Path to the file
                - filename: Optional custom filename
            **kwargs: Additional email-specific arguments:
                - html_message: Whether message is HTML (default: False)
                - cc: List of CC email addresses
                - bcc: List of BCC email addresses
                - sender: Override default sender

        Returns:
            Dictionary with notification result information.

        Raises:
            ValueError: If any recipient email is invalid.
            smtplib.SMTPException: If the email could not be sent.
        """
        # Validate all recipient emails
        for recipient in recipients:
            if not self._validate_email(recipient):
                raise ValueError(f"Invalid recipient email: {recipient}")

        # Process kwargs
        html_message = kwargs.get("html_message", False)
        cc = kwargs.get("cc", [])
        bcc = kwargs.get("bcc", [])
        sender = kwargs.get("sender", self.default_sender)

        # Create message
        msg = MIMEMultipart("alternative" if html_message else "mixed")
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)

        if cc:
            msg["Cc"] = ", ".join(cc)

        if bcc:
            msg["Bcc"] = ", ".join(bcc)

        # Set importance
        if importance == "high":
            msg["Importance"] = "High"
            msg["X-Priority"] = "1"
        elif importance == "low":
            msg["Importance"] = "Low"
            msg["X-Priority"] = "5"

        # Add message body
        if html_message:
            msg.attach(MIMEText(message, "html"))
            # Also add plain text alternative
            plain_text = self._html_to_plain(message)
            msg.attach(MIMEText(plain_text, "plain"))
        else:
            msg.attach(MIMEText(message, "plain"))

        # Add attachments
        if attachments:
            for attachment in attachments:
                self._add_attachment(msg, attachment)

        # Include all recipients for SMTP sending
        all_recipients = recipients + cc + bcc

        # Send the email
        response = self._send_smtp_email(msg, all_recipients)

        return {
            "status": "success",
            "message": "Email sent successfully",
            "recipients": recipients,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "smtp_response": response,
        }

    def _html_to_plain(self, html: str) -> str:
        """
        Convert HTML to plain text (simple conversion).

        Args:
            html: HTML content.

        Returns:
            Plain text representation.
        """
        # Simple HTML to plaintext conversion
        # In a real implementation, use a proper HTML parser
        text = html
        text = re.sub(r"<br\s*/?>|</p>", "\n", text)
        text = re.sub(r"<[^>]*>", "", text)
        return text

    def _add_attachment(self, msg: MIMEMultipart, attachment: Dict[str, Any]) -> None:
        """
        Add an attachment to the email message.

        Args:
            msg: Email message to add attachment to.
            attachment: Attachment information dictionary.

        Raises:
            ValueError: If the attachment path is missing or invalid.
        """
        if "path" not in attachment:
            raise ValueError("Attachment missing required 'path' field")

        path = attachment["path"]
        if not os.path.exists(path):
            raise ValueError(f"Attachment file not found: {path}")

        # Get filename (use custom filename if provided, otherwise use the basename)
        filename = attachment.get("filename", os.path.basename(path))

        # Guess content type based on file extension
        with open(path, "rb") as f:
            attachment_data = f.read()

        part = MIMEApplication(attachment_data)
        part.add_header("Content-Disposition", f"attachment; filename={filename}")

        msg.attach(part)

    def _send_smtp_email(self, msg: MIMEMultipart, recipients: List[str]) -> str:
        """
        Send an email via SMTP.

        Args:
            msg: Email message to send.
            recipients: List of all recipients (to, cc, bcc).

        Returns:
            SMTP server response.

        Raises:
            smtplib.SMTPException: If the email could not be sent.
        """
        # Choose the appropriate SMTP class based on SSL setting
        smtp_class = smtplib.SMTP_SSL if self.use_ssl else smtplib.SMTP

        # Connect to the SMTP server
        with smtp_class(self.smtp_server, self.smtp_port) as server:
            if self.use_tls and not self.use_ssl:
                server.starttls()

            server.login(self.username, self.password)
            response = server.sendmail(msg["From"], recipients, msg.as_string())

            return "Email sent successfully"


def configure(config: Dict[str, Any]) -> EmailAdapter:
    """
    Configure and return an email notification adapter.

    Args:
        config: Configuration dictionary for the adapter.

    Returns:
        Configured EmailAdapter instance.
    """
    return EmailAdapter(config)
