"""
Setup script for Python Standards Suite (PS2).

This script configures the PS2 package for installation, defining dependencies
and entry points for the command-line interface.
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="python-standards-suite",
    version="0.1.0",
    author="PS2 Contributors",
    author_email="",
    description="Python Standards Suite - Enforce code structure, style, and development standards",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/python-standards-suite",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "astroid>=2.15.0",
        "toml>=0.10.2",
        "pyyaml>=6.0",
        "colorama>=0.4.6",
        "coloredlogs>=15.0.1",
        "networkx>=2.8.8",
    ],
    extras_require={
        "dev": [
            "black>=23.3.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
            "mypy>=1.2.0",
            "pytest>=7.3.1",
            "pytest-cov>=4.1.0",
        ],
        "full": [
            "black>=23.3.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "pylint>=2.17.0",
            "mypy>=1.2.0",
            "bandit>=1.7.5",
            "safety>=2.3.5",
            "pip-audit>=2.5.6",
            "radon>=5.1.0",
            "pydocstyle>=6.3.0",
            "interrogate>=1.5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ps2=ps2.cli.main:main",
        ],
    },
)
