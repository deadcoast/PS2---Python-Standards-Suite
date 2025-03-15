# Python Standards Suite (PS2)

A comprehensive suite of tools to create and enforce code structure, style, and development standards in Python projects.

## Overview

The Python Standards Suite (PS2) is a directory that can be placed outside your source folder to ensure your Python project is created with standards that help avoid errors, conflicts, and poor coding practices. PS2 acts as a centralized system for maintaining consistent code quality throughout development.

## Features

- **Project Generation**: Create standardized Python project structures
- **Code Quality Enforcement**: Ensure adherence to style guides and best practices 
- **Local Import Enforcement**: Prevent import-related issues
- **Dependency Management**: Automate requirements.txt generation and dependency tracking
- **Conflict Resolution**: Detect and resolve naming conflicts
- **Duplication Detection**: Identify and eliminate code duplication
- **Security Scanning**: Find and fix security vulnerabilities
- **Automated Task Management**: Track issues that need manual intervention

## Installation

### From PyPI (recommended)

```bash
pip install python-standards-suite
```

### From Source

```bash
git clone https://github.com/yourusername/python-standards-suite.git
cd python-standards-suite
pip install -e .
```

For full functionality, install with all optional dependencies:

```bash
pip install python-standards-suite[full]
```

## Usage

### Command Line Interface

PS2 provides a command-line interface for easy access to all features:

```bash
# Generate a new project
ps2 generate myproject

# Run all checks on an existing project
ps2 all --project /path/to/project

# Check code quality
ps2 check

# Detect and fix code duplications
ps2 duplications --fix

# Enforce import standards
ps2 imports --fix

# Scan for security issues
ps2 security

# Manage dependencies
ps2 dependencies --update

# Generate task list
ps2 tasks
```

### Python API

You can also use PS2 programmatically in your Python scripts:

```python
from ps2 import initialize_ps2

# Initialize PS2 for a project
ps2 = initialize_ps2("/path/to/project")

# Run code quality checks
results = ps2.check_code_quality(fix=True)

# Generate a new project
new_project_path = ps2.generate_project("myproject", project_type="flask")

# Analyze codebase
analysis = ps2.analyze_codebase()
```

## Configuration

PS2 can be configured via a configuration file. Create a `.ps2.json`, `.ps2.yaml`, or `.ps2.toml` file in your project directory or home directory:

```json
{
  "general": {
    "verbose": true,
    "log_level": "INFO"
  },
  "code_quality": {
    "style_tools": ["black", "isort"],
    "min_coverage": 80.0
  },
  "security_scanner": {
    "scan_dependencies": true,
    "min_severity": "medium"
  }
}
```

You can also specify a custom configuration file with the `--config` option:

```bash
ps2 all --config /path/to/custom-config.yaml
```

## Components

PS2 consists of several integrated components:

- **Project Generator**: Creates standardized project structures
- **Code Analyzer**: Analyzes code structure and complexity
- **Code Quality Enforcer**: Ensures adherence to style guides and best practices
- **Conflict Resolver**: Detects and resolves naming conflicts
- **Dependency Manager**: Manages project dependencies
- **Duplication Detector**: Identifies code duplication
- **Import Enforcer**: Enforces consistent import patterns
- **Performance Monitor**: Tracks code performance
- **Security Scanner**: Identifies security vulnerabilities
- **Task Manager**: Tracks issues requiring manual intervention

## Requirements

- Python 3.8+
- Several optional dependencies for specific functionality (see `setup.py`)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.