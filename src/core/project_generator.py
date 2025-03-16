"""
Project Generator Module for PS2.

This module creates standardized Python project structures with proper 
configurations and boilerplate code, ensuring consistent project setup
and adherence to best practices from the start.
"""

from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports


class ProjectGenerator:
    """
    Generator for standardized Python project structures.
from typing import Dict, List, Set, Tuple, Any, Optional, Union  # TODO: Remove unused imports  # TODO: Line too long, needs manual fixing  # TODO: Remove unused imports
    This class creates new Python projects with standardized directory
    structures, configurations, and boilerplate code, ensuring projects
    adhere to best practices from the start.
    """
    
    def __init__(self, project_path: Union[str, Path], config: Dict):
        """
        Initialize the project generator.
        
        Args:
            project_path: Base path for creating projects.
            config: Configuration dictionary for the generator.
        """
        self.project_path = Path(project_path)
        self.config = config
        self.logger = logging.getLogger("ps2.project_generator")
        self.enabled = False
        
        # Default settings
        self.default_settings = {
            "author_name": os.environ.get("USER", "Unknown"),
            "author_email": "",
            "license": "MIT",
            "python_version": ">=3.8",
            "use_src_layout": True,
            "include_tests": True,
            "include_docs": True,
            "include_ci": True,
            "include_docker": False,
            "create_virtual_env": True,
            "initialize_git": True,
        }
        
        # Apply config settings
        self.settings = {**self.default_settings, **self.config.get(
            "project_generator",
            {})
        
        # Template directory
        self.template_dir = Path(__file__).parent.parent.parent / "templates" / "project"
    
    def enable(self) -> None:
        """Enable the project generator."""
        self.enabled = True
    
    def disable(self) -> None:
        """Disable the project generator."""
    def generate_project(self,
        project_name: str,
        project_type: str = "standard")
    
    def generate_project(self, project_name: str, project_type: str = "standard") -> Path:
        """
        Generate a new Python project.
        
        Args:
            project_name: Name of the project.
            project_type: Type of project template to use.
            
        Returns:
            Path to the generated project.
        """
        if not self.enabled:
            self.logger.warning("Project generator is disabled. Enabling for this run.")
            self.enable()
        
        self.logger.info(f"Generating project: {project_name} (type: {project_type})")
        
        # Validate project name
        if not self._validate_project_name(project_name):
            raise ValueError(f"Invalid project name: {project_name}")
        
        # Create project directory
        project_dir = self.project_path / project_name
        if project_dir.exists():
            self.logger.warning(f"Project directory already exists: {project_dir}")
            i = 1
            while (self.project_path / f"{project_name}_{i}").exists():
                i += 1
            project_dir = self.project_path / f"{project_name}_{i}"
            self.logger.info(f"Using alternative directory: {project_dir}")
        
        # Create project structure based on type
        if project_type == "standard":
            self._create_standard_project(project_name, project_dir)
        elif project_type == "flask":
            self._create_flask_project(project_name, project_dir)
        elif project_type == "django":
            self._create_django_project(project_name, project_dir)
        elif project_type == "fastapi":
            self._create_fastapi_project(project_name, project_dir)
        elif project_type == "cli":
            self._create_cli_project(project_name, project_dir)
        elif project_type == "package":
            self._create_package_project(project_name, project_dir)
        elif project_type == "data_science":
            self._create_data_science_project(project_name, project_dir)
        else:
            self.logger.warning(f"Unknown project type: {project_type}, using standard")
            self._create_standard_project(project_name, project_dir)
        
        # Initialize git repository if configured
        if self.settings["initialize_git"]:
            self._initialize_git(project_dir)
        
        # Create virtual environment if configured
        if self.settings["create_virtual_env"]:
            self._create_virtual_env(project_dir)
        
        # Log success
        self.logger.info(f"Project generated successfully at: {project_dir}")
        
        return project_dir
    
    def _validate_project_name(self, project_name: str) -> bool:
        """
        Validate a project name.
        
        Args:
            project_name: Name to validate.
            
        Returns:
            True if valid, False otherwise.
        """
        # Check if name is valid Python package name
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]*$", project_name):
            self.logger.error(f"Invalid project name: {project_name} (must be a valid Python package name)")
            return False
            "break", "class", "continue", "def", "del", "elif", "else", "except",  # TODO: Line too long, needs manual fixing
            "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",  # TODO: Line too long, needs manual fixing
        python_keywords = {
            "False", "None", "True", "and", "as", "assert", "async", "await",
            "break", "class", "continue", "def", "del", "elif", "else", "except",
            "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
            "nonlocal", "not", "or", "pass", "raise", "return", "try", "while",
            "with", "yield"
        }
        
        if project_name in python_keywords:
            self.logger.error(f"Invalid project name: {project_name} (Python reserved keyword)")
    def _create_standard_project(self,
        project_name: str,
        project_dir: Path)
        
        return True
    
    def _create_standard_project(self, project_name: str, project_dir: Path) -> None:
        """
        Create a standard Python project structure.
        
        Args:
            project_name: Name of the project.
            project_dir: Directory to create the project in.
        """
        self.logger.info(f"Creating standard project structure at: {project_dir}")

        # Create directories
        os.makedirs(project_dir, exist_ok=True)

        if self.settings["use_src_layout"]:
            src_dir = project_dir / "src" / project_name
        else:
            src_dir = project_dir / project_name
        os.makedirs(src_dir, exist_ok=True)
        # Create package __init__.py
        with open(src_dir / "__init__.py", "w") as f:
            f.write(f'"""Main package for {project_name}."""\n\n')
            f.write(f'__version__ = "0.1.0"\n')

        # Create example module
        with open(src_dir / "main.py", "w") as f:
            f.write(f'"""Main module for {project_name}."""\n\n')
            self._extracted_from__create_standard_project_29(
                f,
                'def main():\n',
                '    """Run the main function."""\n',
                '    print("Hello, world!")\n\n\n',
            )
            f.write('if __name__ == "__main__":\n')
            f.write('    main()\n')

        # Create tests directory if configured
        if self.settings["include_tests"]:
            tests_dir = project_dir / "tests"
            os.makedirs(tests_dir, exist_ok=True)

            # Create test __init__.py
            with open(tests_dir / "__init__.py", "w") as f:
                f.write('"""Test package for {project_name}."""\n')

            # Create example test
            with open(tests_dir / "test_main.py", "w") as f:
                f.write(f'"""Tests for {project_name}.main module."""\n\n')
                f.write('import pytest\n\n')
                if self.settings["use_src_layout"]:
                    f.write(f'from src.{project_name}.main import main\n\n\n')
                else:
                    f.write(f'from {project_name}.main import main\n\n\n')
                self._extracted_from__create_standard_project_29(
                    f,
                    'def test_main():\n',
                    '    """Test main function."""\n',
                    '    # This is a placeholder test\n',
                )
                f.write('    assert True\n')

        # Create docs directory if configured
        if self.settings["include_docs"]:
            docs_dir = project_dir / "docs"
            os.makedirs(docs_dir, exist_ok=True)

            # Create example documentation
            with open(docs_dir / "index.md", "w") as f:
                f.write(f'# {project_name.capitalize()}\n\n')
                self._extracted_from__create_standard_project_29(
                    f,
                    'Welcome to the documentation!\n\n',
                    '## Installation\n\n',
                    '```bash\n',
                )
                f.write(f'pip install {project_name}\n')
                self._extracted_from__create_standard_project_29(
                    f, '```\n\n', '## Usage\n\n', '```python\n'
                )
                if self.settings["use_src_layout"]:
                    f.write(f'from src.{project_name} import main\n\n')
                else:
                    f.write(f'from {project_name} import main\n\n')
                f.write('main()\n')
                f.write('```\n')

        # Create CI configuration if configured
        if self.settings["include_ci"]:
            github_dir = project_dir / ".github" / "workflows"
            os.makedirs(github_dir, exist_ok=True)

            # Create GitHub Actions workflow
            with open(github_dir / "python-test.yml", "w") as f:
                self._extracted_from__create_standard_project_29(
                    f, 'name: Python Tests\n\n', 'on:\n', '  push:\n'
                )
                self._extracted_from__create_django_project_98(
                    f,
                    '    branches: [ main ]\n',
                    '  pull_request:\n',
                    '    branches: [ main ]\n\n',
                )
                f.write('jobs:\n')
                f.write('  test:\n')
                f.write('    runs-on: ubuntu-latest\n')
                f.write('    strategy:\n')
                f.write('      matrix:\n')
                f.write('        python-version: [3.8, 3.9, "3.10"]\n\n')
                f.write('    steps:\n')
                f.write('    - uses: actions/checkout@v2\n')
                f.write('    - name: Set up Python ${{ matrix.python-version }}\n')
                f.write('      uses: actions/setup-python@v2\n')
                f.write('      with:\n')
                f.write('        python-version: ${{ matrix.python-version }}\n')
                f.write('    - name: Install dependencies\n')
                f.write('      run: |\n')
                f.write('        python -m pip install --upgrade pip\n')
                f.write('        pip install pytest pytest-cov\n')
                f.write('        pip install -e .\n')
                f.write('    - name: Test with pytest\n')
                f.write('      run: |\n')
                f.write('        pytest --cov=./ --cov-report=xml\n')
                f.write('    - name: Upload coverage to Codecov\n')
                f.write('      uses: codecov/codecov-action@v2\n')
                f.write('      with:\n')
                f.write('        file: ./coverage.xml\n')
                f.write('        fail_ci_if_error: true\n')

        # Create Docker configuration if configured
        if self.settings["include_docker"]:
            # Create Dockerfile
            with open(project_dir / "Dockerfile", "w") as f:
                self._extracted_from__create_standard_project_29(
                    f,
                    'FROM python:3.9-slim\n\n',
                    'WORKDIR /app\n\n',
                    'COPY requirements.txt .\n',
                )
                f.write('RUN pip install --no-cache-dir -r requirements.txt\n\n')
                f.write('COPY . .\n')
                if self.settings["use_src_layout"]:
                    f.write('RUN pip install -e .\n\n')
                f.write(f'CMD ["python", "-m", "{project_name}' + '.main"]\n')

            # Create .dockerignore
            with open(project_dir / ".dockerignore", "w") as f:
                self._extracted_from__create_standard_project_29(
                    f, '__pycache__/\n', '*.py[cod]\n', '*$py.class\n'
                )
                self._extracted_from__create_django_project_98(
                    f, '*.so\n', '.Python\n', 'env/\n'
                )
                f.write('build/\n')
                f.write('develop-eggs/\n')
                f.write('dist/\n')
                f.write('downloads/\n')
                f.write('eggs/\n')
                f.write('.eggs/\n')
                f.write('lib/\n')
                f.write('lib64/\n')
                f.write('parts/\n')
                f.write('sdist/\n')
                f.write('var/\n')
                f.write('*.egg-info/\n')
                f.write('.installed.cfg\n')
                f.write('*.egg\n')
                f.write('.env\n')
                f.write('.venv\n')
                f.write('venv/\n')
                f.write('ENV/\n')
                f.write('.git/\n')
                f.write('docs/\n')
                f.write('tests/\n')

        # Create setup.py
        with open(project_dir / "setup.py", "w") as f:
            f.write(f'"""Setup script for {project_name}' + '."""\n\n')
            f.write('from setuptools import setup, find_packages\n\n')
            f.write('setup(\n')
            f.write(f'    name="{project_name}",\n')
            f.write('    version="0.1.0",\n')
            f.write(f'    description="A Python project called {project_name}",\n')
            f.write('    author="' + self.settings["author_name"] + '",\n')
            f.write('    author_email="' + self.settings["author_email"] + '",\n')
            if self.settings["use_src_layout"]:
                f.write('    package_dir={"": "src"},\n')
                f.write('    packages=find_packages(where="src"),\n')
            else:
                f.write('    packages=find_packages(),\n')
            f.write('    python_requires="' + self.settings["python_version"] + '",\n')
            self._extracted_from__create_standard_project_29(
                f,
                '    install_requires=[\n',
                '        # Add your package dependencies here\n',
                '    ],\n',
            )
            f.write('    classifiers=[\n')
            f.write('        "Programming Language :: Python :: 3",\n')
            f.write('        "License :: OSI Approved :: ' + self.settings["license"] + ' License",\n')
            self._extracted_from__create_standard_project_29(
                f,
                '        "Operating System :: OS Independent",\n',
                '    ],\n',
                ')\n',
            )
        # Create README.md
        with open(project_dir / "README.md", "w") as f:
            f.write(f'# {project_name.capitalize()}\n\n')
            self._extracted_from__create_standard_project_29(
                f,
                'A Python project generated by PS2.\n\n',
                '## Installation\n\n',
                '```bash\n',
            )
            f.write('# Clone the repository\n')
            f.write(f'git clone https://github.com/yourusername/{project_name}.git\n')
            f.write(f'cd {project_name}\n\n')
            self._extracted_from__create_standard_project_29(
                f, '# Install the package\n', 'pip install -e .\n', '```\n\n'
            )
            f.write('## Usage\n\n')
            f.write('```python\n')
            if self.settings["use_src_layout"]:
                f.write(f'from src.{project_name} import main\n\n')
            else:
                f.write(f'from {project_name} import main\n\n')
            self._extracted_from__create_standard_project_29(
                f, 'main()\n', '```\n\n', '## Development\n\n'
            )
            self._extracted_from__create_django_project_98(
                f, '```bash\n', '# Run tests\n', 'pytest\n\n'
            )
            f.write('# Run tests with coverage\n')
            f.write('pytest --cov=./ --cov-report=term-missing\n')
            f.write('```\n')

        # Create LICENSE
                    'Permission is hereby granted, free of charge, to any person obtaining a copy\n',  # TODO: Line too long, needs manual fixing
            if self.settings["license"] == "MIT":
                    'in the Software without restriction, including without limitation the rights\n',  # TODO: Line too long, needs manual fixing
                f.write(f'Copyright (c) {datetime.now().year} {self.settings["author_name"]}\n\n')
                self._extracted_from__create_standard_project_29(
                    f,
                    'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n',  # TODO: Line too long, needs manual fixing
                    'copies of the Software, and to permit persons to whom the Software is\n',  # TODO: Line too long, needs manual fixing
                    'furnished to do so, subject to the following conditions:\n\n',  # TODO: Line too long, needs manual fixing
                )
                self._extracted_from__create_django_project_98(
                    f,
                    'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n',
                    'copies of the Software, and to permit persons to whom the Software is\n',
                    'furnished to do so, subject to the following conditions:\n\n',
                )
                f.write('The above copyright notice and this permission notice shall be included in all\n')
                f.write('copies or substantial portions of the Software.\n\n')
                f.write('THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n')
                f.write('IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n')
                f.write('FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n')
                f.write('AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n')
                f.write('LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n')
                f.write('OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n')
                f.write('SOFTWARE.\n')

        # Create .gitignore
        with open(project_dir / ".gitignore", "w") as f:
            self._extracted_from__create_standard_project_29(
                f,
                '# Byte-compiled / optimized / DLL files\n',
                '__pycache__/\n',
                '*.py[cod]\n',
            )
            self._extracted_from__create_django_project_98(
                f, '*$py.class\n\n', '# C extensions\n', '*.so\n\n'
            )
            f.write('# Distribution / packaging\n')
            f.write('.Python\n')
            f.write('build/\n')
            f.write('develop-eggs/\n')
            f.write('dist/\n')
            f.write('downloads/\n')
            f.write('eggs/\n')
            f.write('.eggs/\n')
            f.write('lib/\n')
            f.write('lib64/\n')
            f.write('parts/\n')
            f.write('sdist/\n')
            f.write('var/\n')
            f.write('wheels/\n')
            f.write('*.egg-info/\n')
            f.write('.installed.cfg\n')
            f.write('*.egg\n\n')
            f.write('# Unit test / coverage reports\n')
            f.write('htmlcov/\n')
            f.write('.tox/\n')
            f.write('.coverage\n')
            f.write('.coverage.*\n')
            f.write('.cache\n')
            f.write('nosetests.xml\n')
            f.write('coverage.xml\n')
            f.write('*.cover\n')
            f.write('.hypothesis/\n\n')
            f.write('# Environments\n')
            f.write('.env\n')
            f.write('.venv\n')
            f.write('env/\n')
            f.write('venv/\n')
            f.write('ENV/\n\n')
            f.write('# IDE specific files\n')
            f.write('.idea/\n')
            f.write('.vscode/\n')
            f.write('*.swp\n')
            f.write('*.swo\n')

        # Create requirements.txt
        with open(project_dir / "requirements.txt", "w") as f:
            self._extracted_from__create_standard_project_29(
                f,
                '# Project dependencies\n',
                'pytest>=7.3.1\n',
                'pytest-cov>=4.1.0\n',
            )
        # Create pyproject.toml
        with open(project_dir / "pyproject.toml", "w") as f:
            self._extracted_from__create_standard_project_29(
                f,
                '[build-system]\n',
                'requires = ["setuptools>=42", "wheel"]\n',
                'build-backend = "setuptools.build_meta"\n\n',
            )
            self._extracted_from__create_django_project_98(
                f,
                '[tool.black]\n',
                'line-length = 88\n',
                'target-version = ["py38"]\n\n',
            )
            f.write('[tool.isort]\n')
            f.write('profile = "black"\n')
            f.write('line_length = 88\n\n')
            f.write('[tool.pytest.ini_options]\n')
            f.write('testpaths = ["tests"]\n')
    def _create_flask_project(self,
        project_name: str,
        project_dir: Path)

    # TODO Rename this here and in `_create_standard_project`
    def _extracted_from__create_standard_project_29(self, f, arg1, arg2, arg3):
        self._extracted_from__create_django_project_98(f, arg1, arg2, arg3)
    
    def _create_flask_project(self, project_name: str, project_dir: Path) -> None:
        """
        Create a Flask web application project structure.
        
        Args:
            project_name: Name of the project.
            project_dir: Directory to create the project in.
        """
        self.logger.info(f"Creating Flask project structure at: {project_dir}")

        # Create standard structure first
        self._create_standard_project(project_name, project_dir)

        # Determine source directory
        if self.settings["use_src_layout"]:
            src_dir = project_dir / "src" / project_name
        else:
            src_dir = project_dir / project_name

        # Create Flask-specific directories
        templates_dir = src_dir / "templates"
        static_dir = src_dir / "static"
        static_css_dir = static_dir / "css"
        static_js_dir = static_dir / "js"

        os.makedirs(templates_dir, exist_ok=True)
        os.makedirs(static_css_dir, exist_ok=True)
        os.makedirs(static_js_dir, exist_ok=True)

        # Create app.py
        with open(src_dir / "app.py", "w") as f:
            f.write(f'"""Flask application for {project_name}."""\n\n')
            self._extracted_from__create_django_project_98(
                f,
                'from flask import Flask, render_template\n\n',
                'app = Flask(__name__)\n\n\n',
                '@app.route("/")\n',
            )
            f.write('def home():\n')
            f.write('    """Render the home page."""\n')
            f.write('    return render_template("index.html", title="Home")\n\n\n')
            f.write('if __name__ == "__main__":\n')
            f.write('    app.run(debug=True)\n')

        # Create base template
        with open(templates_dir / "base.html", "w") as f:
            self._extracted_from__create_django_project_98(
                f, '<!DOCTYPE html>\n', '<html lang="en">\n', '<head>\n'
            )
            f.write('    <meta charset="UTF-8">\n')
            f.write('    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n')
            f.write('    <title>{{ title }} - ' + project_name.capitalize() + '</title>\n')
            self._extracted_from__create_django_project_98(
                f,
                '    <link rel="stylesheet" href="{{ url_for(\'static\', filename=\'css/style.css\') }}">\n',
                '</head>\n',
                '<body>\n',
            )
            f.write('    <header>\n')
            f.write(f'        <h1>{project_name.capitalize()}' + '</h1>\n')
            self._extracted_from__create_django_project_98(
                f,
                '        <nav>\n',
                '            <ul>\n',
                '                <li><a href="{{ url_for(\'home\') }}">Home</a></li>\n',
            )
            f.write('            </ul>\n')
            f.write('        </nav>\n')
            f.write('    </header>\n')
            f.write('    <main>\n')
            f.write('        {% block content %}{% endblock %}\n')
            f.write('    </main>\n')
            f.write('    <footer>\n')
            f.write(
                f'        <p>&copy; {str(datetime.now().year)} {project_name.capitalize()}'
                + '</p>\n'
            )
            self._extracted_from__create_django_project_98(
                f,
                '    </footer>\n',
                '    <script src="{{ url_for(\'static\', filename=\'js/main.js\') }}"></script>\n',
                '</body>\n',
            )
            f.write('</html>\n')

        # Create index template
        with open(templates_dir / "index.html", "w") as f:
            f.write('{% extends "base.html" %}\n\n')
            f.write('{% block content %}\n')
            f.write(f'    <h2>Welcome to {project_name.capitalize()}' + '</h2>\n')
            f.write('    <p>This is a Flask web application.</p>\n')
            f.write('{% endblock %}\n')

        # Create CSS file
        with open(static_css_dir / "style.css", "w") as f:
            self._extracted_from__create_django_project_98(
                f,
                '/* Main stylesheet */\n\n',
                'body {\n',
                '    font-family: Arial, sans-serif;\n',
            )
            f.write('    margin: 0;\n')
            f.write('    padding: 0;\n')
            f.write('    line-height: 1.6;\n')
            f.write('}\n\n')
            f.write('header {\n')
            f.write('    background-color: #4CAF50;\n')
            f.write('    color: white;\n')
            f.write('    padding: 1rem;\n')
            f.write('}\n\n')
            f.write('nav ul {\n')
            f.write('    list-style-type: none;\n')
            f.write('    padding: 0;\n')
            f.write('}\n\n')
            f.write('nav ul li {\n')
            f.write('    display: inline;\n')
            f.write('    margin-right: 10px;\n')
            f.write('}\n\n')
            f.write('nav ul li a {\n')
            f.write('    color: white;\n')
            f.write('    text-decoration: none;\n')
            f.write('}\n\n')
            f.write('main {\n')
            f.write('    padding: 1rem;\n')
            f.write('}\n\n')
            f.write('footer {\n')
            f.write('    background-color: #f8f9fa;\n')
            f.write('    text-align: center;\n')
            f.write('    padding: 1rem;\n')
            f.write('    position: fixed;\n')
            f.write('    bottom: 0;\n')
            f.write('    width: 100%;\n')
            f.write('}\n')

        # Create JavaScript file
        with open(static_js_dir / "main.js", "w") as f:
            f.write('// Main JavaScript file\n\n')
            f.write('document.addEventListener("DOMContentLoaded", function() {\n')
            f.write(
                f'    console.log("{project_name.capitalize()}'
                + ' application loaded");\n'
            )
            f.write('});\n')

        # Update requirements.txt
        with open(project_dir / "requirements.txt", "a") as f:
            self._extracted_from__create_django_project_98(
                f,
                '\n# Flask dependencies\n',
                'flask>=2.2.3\n',
                'flask-wtf>=1.1.1\n',
            )
            f.write('flask-sqlalchemy>=3.0.3\n')

        # Update README with Flask-specific instructions
        with open(project_dir / "README.md", "a") as f:
            self._extracted_from__create_django_project_98(
                f,
                '\n## Flask Application\n\n',
                '```bash\n',
                '# Run the Flask application\n',
    def _create_django_project(self,
        project_name: str,
        project_dir: Path)
            if self.settings["use_src_layout"]:
                f.write(f'python -m src.{project_name}.app\n')
            else:
                f.write(f'python -m {project_name}.app\n')
            f.write('```\n\n')
            f.write('Then navigate to http://127.0.0.1:5000/ in your web browser.\n')
    
    def _create_django_project(self, project_name: str, project_dir: Path) -> None:
        """
        Create a Django web application project structure.
        
        Args:
            project_name: Name of the project.
            project_dir: Directory to create the project in.
        """
        self.logger.info(f"Creating Django project structure at: {project_dir}")

        # Create the main project directory
        os.makedirs(project_dir, exist_ok=True)

        # Create Django project structure
        # In a real implementation, we might use Django's django-admin startproject command
        # For now, we'll manually create the structure

        # Create Django project files
        django_project_dir = project_dir / project_name
        os.makedirs(django_project_dir, exist_ok=True)

        # Create __init__.py
        with open(django_project_dir / "__init__.py", "w") as f:
            f.write("")

        # Create settings.py
        with open(django_project_dir / "settings.py", "w") as f:
            f.write(f'"""Django settings for {project_name} project."""\n\n')
            self._extracted_from__create_django_project_98(
                f,
                'import os\n',
                'from pathlib import Path\n\n',
                '# Build paths inside the project\n',
            )
            f.write('BASE_DIR = Path(__file__).resolve().parent.parent\n\n')

            # Security settings
            f.write('# Security\n')
            f.write('SECRET_KEY = "django-insecure-1234567890"\n')
            f.write('DEBUG = True\n')
            f.write('ALLOWED_HOSTS = ["*"]\n\n')

            # Database settings
            f.write('# Database\n')
            f.write('DATABASES = {\n')
            f.write('    "default": {\n')
            f.write('        "ENGINE": "django.db.backends.sqlite3",\n')
            f.write('        "NAME": BASE_DIR / "db.sqlite3",\n')
            f.write('    }\n')
            f.write('}\n\n')

            # Static files settings
            f.write('# Static files\n')
            f.write('STATIC_URL = "/static/"\n')
            f.write('STATIC_ROOT = BASE_DIR / "static"\n')
            f.write('STATICFILES_DIRS = [BASE_DIR / "static"]\n')
            f.write('STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"\n')
            f.write('\n')

            # Media files settings
            f.write('# Media files\n')
            f.write('MEDIA_URL = "/media/"\n')
            f.write('MEDIA_ROOT = BASE_DIR / "media"\n')
            f.write('\n')

            # Application settings
            f.write('# Application settings\n')
            f.write('INSTALLED_APPS = [\n')
            f.write('    "django.contrib.admin",\n')
            f.write('    "django.contrib.auth",\n')
            f.write('    "django.contrib.contenttypes",\n')
            f.write('    "django.contrib.sessions",\n')
            f.write('    "django.contrib.messages",\n')
            f.write('    "django.contrib.staticfiles",\n')
            f.write(']\n')
            f.write('\n')

            # Middleware settings
            f.write('# Middleware\n')
            f.write('MIDDLEWARE = [\n')
            f.write('    "django.middleware.security.SecurityMiddleware",\n')
            f.write('    "django.contrib.sessions.middleware.SessionMiddleware",\n')
            f.write('    "django.middleware.common.CommonMiddleware",\n')
            f.write('    "django.middleware.csrf.CsrfViewMiddleware",\n')
            f.write('    "django.contrib.auth.middleware.AuthenticationMiddleware",\n')
            f.write('    "django.contrib.messages.middleware.MessageMiddleware",\n')
            f.write('    "django.contrib.staticfiles.middleware.StaticFilesMiddleware",\n')
            f.write(']\n')
            f.write('\n')

            # Database settings
            f.write('# Database\n')
            f.write('DATABASES = {\n')
            f.write('    "default": {\n')
            f.write('        "ENGINE": "django.db.backends.sqlite3",\n')
            f.write('        "NAME": BASE_DIR / "db.sqlite3",\n')
            f.write('    }\n')
            f.write('}\n\n')

            # Security settings
            f.write('# Security\n')
            f.write('SECURE_SSL_REDIRECT = False\n')
            f.write('\n')

            # Internationalization settings
            f.write('# Internationalization\n')
            f.write('LANGUAGE_CODE = "en-us"\n')
            f.write('TIME_ZONE = "UTC"\n')
            f.write('\n')

            # Static files settings
            f.write('# Static files\n')
            f.write('STATIC_URL = "/static/"\n')
            f.write('STATIC_ROOT = BASE_DIR / "static"\n')
            f.write('STATICFILES_DIRS = [BASE_DIR / "static"]\n')
            f.write('STATICFILES_STORAGE = "django.contrib.staticfiles.storage.StaticFilesStorage"\n')
            f.write('\n')

            # Media files settings
            f.write('# Media files\n')
            f.write('MEDIA_URL = "/media/"\n')
            f.write('MEDIA_ROOT = BASE_DIR / "media"\n')
            f.write('\n')

            # Default primary key field type
            f.write('# Default primary key field type\n')
            f.write('DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"\n')
                    "# In a real implementation, we would use django-admin to create manage.py\n",  # TODO: Line too long, needs manual fixing

            # End of settings
            f.write('"""\n')

            # Create manage.py
            with open(django_project_dir / "manage.py", "w") as f:
                self._extracted_from__create_django_project_98(
                    f,
                    "# This is a placeholder for manage.py\n",
                    "# In a real implementation, we would use django-admin to create manage.py\n",
                    "# In a real implementation, we would use pip to create requirements.txt\n",  # TODO: Line too long, needs manual fixing
                )
                f.write("# Placeholder for manage.py content\n")
                f.write("\n")

            # Create requirements.txt
            with open(django_project_dir / "requirements.txt", "w") as f:
                self._extracted_from__create_django_project_98(
                    f,
                    "# This is a placeholder for requirements.txt\n",
                    "# In a real implementation, we would use pip to create requirements.txt\n",
                    "# For now, we'll manually create the structure\n",
                )
                f.write("# Placeholder for requirements.txt content\n")
                f.write("\n")

            # Create README.md
            with open(django_project_dir / "README.md", "w") as f:
                self._extracted_from__create_django_project_98(
                    f, "# Django Project\n", "\n", "## Project Description\n"
                )
                f.write("\n")
                f.write("## Project Structure\n")
                f.write("\n")
                    "# In a real implementation, we would use git to create .gitignore\n",  # TODO: Line too long, needs manual fixing
                f.write("\n")
                f.write("## Project Setup\n")
                f.write("\n")

            # Create .gitignore
            with open(django_project_dir / ".gitignore", "w") as f:
                self._extracted_from__create_django_project_98(
                    f,
                    "# This is a placeholder for .gitignore\n",
                    "# In a real implementation, we would use git to create .gitignore\n",
                    "# For now, we'll manually create the structure\n",
                )
                f.write("# Placeholder for .gitignore content\n")
                f.write("\n")
                f.write("# End of .gitignore\n")
                f.write("\n")
                f.write("# End of README.md\n")
                f.write("\n")
                f.write("# End of manage.py\n")
                f.write("\n")
                f.write("# End of requirements.txt\n")
                    "# In a real implementation, we would use virtualenv to create virtualenv.sh\n",  # TODO: Line too long, needs manual fixing
                f.write("# End of .gitignore\n")
                f.write("\n")


            # Create virtual environment
            with open(django_project_dir / "virtualenv.sh", "w") as f:
                self._extracted_from__create_django_project_98(
                    f,
                    "# This is a placeholder for virtualenv.sh\n",
                    "# In a real implementation, we would use virtualenv to create virtualenv.sh\n",
                    "# For now, we'll manually create the structure\n",
                )
                f.write("# Placeholder for virtualenv.sh content\n")
                f.write("\n")
                f.write("# End of virtualenv.sh\n")
                f.write("\n")

    # TODO Rename this here and in `_create_standard_project`, `_extracted_from__create_standard_project_29`, `_create_flask_project` and `_create_django_project`
    def _extracted_from__create_django_project_98(self, f, arg1, arg2, arg3):
        f.write(arg1)
        f.write(arg2)
        f.write(arg3)