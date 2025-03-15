"""
Python Standards Suite (PS2) generated setup.py for {project_name}.

This setup script enables installation of the {project_name} package.
"""

import os
from setuptools import setup, find_packages

# Read the long description from README.md if it exists
if os.path.exists('README.md'):
    with open('README.md', encoding='utf-8') as f:
        long_description = f.read()
else:
    long_description = "{project_description}"

# Read version from package __init__.py if it exists
if os.path.exists('{src_path}/{project_name}/__init__.py'):
    with open('{src_path}/{project_name}/__init__.py', encoding='utf-8') as f:
        for line in f:
            if line.startswith('__version__'):
                version = line.split('=')[1].strip().strip('"\'')
                break
        else:
            version = '0.1.0'
else:
    version = '0.1.0'

# Base dependencies
install_requires = [
    # Add your package dependencies here
    {dependencies}
]

# Development dependencies
dev_requires = [
    'pytest>=7.3.1',
    'pytest-cov>=4.1.0',
    'black>=23.3.0',
    'isort>=5.12.0',
    'flake8>=6.0.0',
    'mypy>=1.2.0',
]

# Optional dependencies
extras_require = {
    'dev': dev_requires,
    'test': [
        'pytest>=7.3.1',
        'pytest-cov>=4.1.0',
    ],
    'docs': [
        'sphinx>=6.1.3',
        'sphinx-rtd-theme>=1.2.0',
    ],
}

setup(
    name="{project_name}",
    version=version,
    description="{project_description}",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="{author_name}",
    author_email="{author_email}",
    url="{project_url}",
    {package_dir_param}
    packages=find_packages({find_packages_param}),
    python_requires="{python_version}",
    install_requires=install_requires,
    extras_require=extras_require,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: {license} License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    include_package_data=True,
    {entry_points_param}
)