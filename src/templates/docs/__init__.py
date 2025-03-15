"""
Documentation Templates Package for PS2.

This package provides templates for generating documentation for Python projects.
"""

import os
from pathlib import Path
from typing import Dict, List, Any

# Get the path to the templates directory
TEMPLATES_DIR = Path(__file__).parent


def get_template_path(template_name: str) -> Path:
    """
    Get the path to a template file.

    Args:
        template_name: Name of the template file.

    Returns:
        Path to the template file.
    """
    return TEMPLATES_DIR / template_name


def list_templates() -> List[str]:
    """
    List all available templates.

    Returns:
        List of template file names.
    """
    return [
        f
        for f in os.listdir(TEMPLATES_DIR)
        if not f.startswith("__") and not f.startswith(".")
    ]


def get_template_content(template_name: str) -> str:
    """
    Get the content of a template file.

    Args:
        template_name: Name of the template file.

    Returns:
        Content of the template file.
    """
    template_path = get_template_path(template_name)

    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


def render_template(template_name: str, context: Dict[str, Any]) -> str:
    """
    Render a template with context variables.

    Args:
        template_name: Name of the template file.
        context: Dictionary of context variables to render the template with.

    Returns:
        Rendered template content.
    """
    template_content = get_template_content(template_name)

    # Simple template rendering with string formatting
    # Replace {variable_name} with context values
    for key, value in context.items():
        placeholder = "{" + key + "}"
        template_content = template_content.replace(placeholder, str(value))

    return template_content
