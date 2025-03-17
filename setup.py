"""
Python Standards Suite (PS2) setup.py.

This setup script enables installation of the PS2 package.
"""

import os

from setuptools import find_packages, setup

# Read the long description from README.md if it exists
if os.path.exists("README.md"):
    with open("README.md", encoding="utf-8") as f:
        long_description = f.read()
else:
    long_description = "Python Standards Suite (PS2) - A comprehensive toolkit for enforcing Python code standards and best practices."

# Read version from package __init__.py if it exists
if os.path.exists("src/ps2/__init__.py"):
    with open("src/ps2/__init__.py", encoding="utf-8") as f:
        version = next(
            (
                line.split("=")[1].strip().strip("\"'")
                for line in f
                if line.startswith("__version__")
            ),
            "0.1.0",
        )
else:
    version = "0.1.0"

# Base dependencies
# Define dependencies variable to avoid F821 error
dependencies = [
    # List your dependencies here as strings
    # For example: 'requests>=2.25.1',
]

install_requires = [
    # Add your package dependencies here
    *dependencies
]

# Development dependencies
dev_requires = [
    "pytest>=7.3.1",
    "pytest-cov>=4.1.0",
    "black>=23.3.0",
    "isort>=5.12.0",
    "flake8>=6.0.0",
    "mypy>=1.2.0",
]

# Optional dependencies
extras_require = {
    "dev": dev_requires,
    "test": [
        "pytest>=7.3.1",
        "pytest-cov>=4.1.0",
    ],
    "docs": [
        "sphinx>=6.1.3",
        "sphinx-rtd-theme>=1.2.0",
    ],
}

setup(
    name="python-standards-suite",
    version=version,
    description="Python Standards Suite (PS2) - A comprehensive toolkit for enforcing Python code standards and best practices",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="PS2 Team",
    author_email="info@ps2.dev",
    url="https://github.com/deadcoast/python_standards_suite",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require=extras_require,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "ps2=src.cli.main:main",
        ],
    },
)
