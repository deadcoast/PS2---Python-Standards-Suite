#!/usr/bin/env python3
"""
generate_fix_scripts.py

This script generates automated fix scripts based on error patterns identified
in the categorized error data. It creates customized scripts from templates for
different error types that can be automatically fixed.

Usage: python generate_fix_scripts.py [options] [input_file]

Options:
  --output-dir DIR   Directory to output fix scripts (default: ./scripts/fixes)
  --template DIR     Directory containing script templates (default: ./templates)
  --dry-run          Show what would be generated without writing files
  --verbose          Show detailed output
"""

import json
import os
import re
import sys
import argparse
import shutil
from typing import Dict, List, Any, Optional, Union, Callable

# Default values
DEFAULT_INPUT = 'error_categories.json'
DEFAULT_OUTPUT_DIR = './scripts/fixes'
DEFAULT_TEMPLATE_DIR = './templates'
BASE_TEMPLATE = 'fix_script.py'

# Error patterns and their corresponding fix configurations
FIX_CONFIGURATIONS = {
    # Security fixes
    'SEC001': {
        'description': 'SQL Injection Prevention',
        'pattern': r'(\w+)\s*=\s*["\''].*?\$\{.*?\}.*?["\'']',
        'replacement': r'\1 = db.escape(\2)',
        'validate': lambda content: 'db.escape' in content,
        'extensions': ['.py', '.pyw']
    },
    
    # Performance fixes
    'PERF001': {
        'description': 'Inefficient Loop Optimization',
        'pattern': r'for\s+i\s+in\s+range\(len\((\w+)\)\):',
        'replacement': r'for i, item in enumerate(\1):',
        'extensions': ['.py', '.pyw']
    },
    
    # Style fixes
    'STYLE001': {
        'description': 'Indentation Standardization',
        'pattern': r'^( {1,3}|\t+)',
        'replacement': r'    ',
        'extensions': ['.py', '.pyw']
    },
    'E501': {
        'description': 'Line Length Reduction',
        'pattern': r'^(.{79,})$',
        'replacement': lambda match: match.group(1)[:75] + '\\' + '\n' + ' ' * 4 + match.group(1)[75:] if len(match.group(1)) > 100 else match.group(1),
        'extensions': ['.py', '.pyw']
    },
    
    # Documentation fixes
    'DOC001': {
        'description': 'Missing Function Documentation',
        'pattern': r'def\s+(\w+)\s*\(([^)]*)\)(?:\s*->.*?)?:',
        'replacement': lambda match: generate_docstring(match),
        'extensions': ['.py', '.pyw']
    },
    
    # Import fixes
    'F401': {
        'description': 'Remove Unused Imports',
        'pattern': r'^import\s+(\w+)(?:\s*,\s*\w+)*\s*$|^from\s+[\w.]+\s+import\s+(?:\w+\s*,\s*)*(\w+)(?:\s*,\s*\w+)*\s*$',
        'replacement': '',  # This will be handled by the custom fix function
        'extensions': ['.py', '.pyw']
    }
}

def generate_docstring(match: re.Match) -> str:
    """
    Generates a docstring for a Python function
    Args:
        match: Regex match containing function definition
    Returns:
        Function definition with docstring added
    """
    function_name = match.group(1)
    params = match.group(2)
    
    param_list = []
    if params:
        param_list = [p.strip().split(':', 1)[0].split('=', 1)[0].strip() 
                    for p in params.split(',') if p.strip()]
    
    docstring = f'def {function_name}({params}):\n'
    docstring += '    """\n'
    docstring += f'    {function_name}\n'
    docstring += '    \n'
    
    if param_list:
        docstring += '    Args:\n'
        for param in param_list:
            if param != 'self' and param != 'cls':
                docstring += f'        {param}: Description of {param}\n'
    
    docstring += '    Returns:\n'
    docstring += '        Description of return value\n'
    docstring += '    """\n'
    
    return docstring


def read_error_categories(file_path: str) -> Dict[str, Any]:
    """
    Reads and parses the input error categories file
    Args:
        file_path: Path to the error categories JSON file
    Returns:
        Parsed error categories
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error reading error categories file: {str(e)}")
        sys.exit(1)


def read_fix_script_template(template_dir: str) -> str:
    """
    Reads the fix script template file
    Args:
        template_dir: Directory containing the template
    Returns:
        Template content
    """
    try:
        template_path = os.path.join(template_dir, BASE_TEMPLATE)
        with open(template_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading template file: {str(e)}")
        sys.exit(1)


def generate_fix_script(template: str, error_code: str, config: Dict[str, Any]) -> str:
    """
    Generates a fix script for a specific error pattern
    Args:
        template: The base template content
        error_code: The error code to fix
        config: Configuration for the fix
    Returns:
        Generated script content
    """
    # Replace placeholders in the template
    content = template
    
    # Handle pattern replacement
    pattern_str = config['pattern']
    if isinstance(pattern_str, str):
        pattern_str = pattern_str.replace('\\', '\\\\')
    
    # Handle replacement function or string
    if callable(config.get('replacement')):
        replacement_str = "lambda match: custom_replacement(match)"
    else:
        replacement_str = f"'{config.get('replacement', '')}'"
        replacement_str = replacement_str.replace('\\', '\\\\')
    
    # Replace placeholders
    content = content.replace('ERROR_CODE', error_code)
    content = content.replace('Description of the issue', config['description'])
    content = content.replace('PATTERN_TO_MATCH', pattern_str)
    content = content.replace('REPLACEMENT_PATTERN', replacement_str)
    content = content.replace("EXTENSIONS = ['.py']", f"EXTENSIONS = {config['extensions']}")
    
    return content


def write_fix_script(output_dir: str, error_code: str, content: str) -> None:
    """
    Writes a fix script to a file
    Args:
        output_dir: Directory to write the script to
        error_code: Error code the script fixes
        content: Script content
    """
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        output_path = os.path.join(output_dir, f"fix_{error_code.lower().replace('/', '_')}.py")
        with open(output_path, 'w', encoding='utf-8') as file:
            file.write(content)
        
        # Make script executable
        os.chmod(output_path, 0o755)
        print(f"Generated fix script: {output_path}")
    except Exception as e:
        print(f"Error writing fix script: {str(e)}")


def main() -> None:
    """Main function"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Generate fix scripts for common code issues')
    parser.add_argument('--output-dir', default=DEFAULT_OUTPUT_DIR, help=f'Directory to output fix scripts (default: {DEFAULT_OUTPUT_DIR})')
    parser.add_argument('--template', dest='template_dir', default=DEFAULT_TEMPLATE_DIR, help=f'Directory containing script templates (default: {DEFAULT_TEMPLATE_DIR})')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be generated without writing files')
    parser.add_argument('--verbose', action='store_true', help='Show detailed output')
    parser.add_argument('input_file', nargs='?', default=DEFAULT_INPUT, help=f'Input error categories file (default: {DEFAULT_INPUT})')
    
    args = parser.parse_args()
    
    # Shorthand variables
    INPUT_FILE = args.input_file
    OUTPUT_DIR = args.output_dir
    TEMPLATE_DIR = args.template_dir
    DRY_RUN = args.dry_run
    VERBOSE = args.verbose
    
    print(f"Generating fix scripts from {INPUT_FILE}...")
    
    # Read error categories
    error_categories = read_error_categories(INPUT_FILE)
    
    # Read fix script template
    template = read_fix_script_template(TEMPLATE_DIR)
    
    # Track generated scripts
    generated_scripts = []
    
    # Process each severity category
    for severity, categories in error_categories.get('categories', {}).items():
        for category, errors in categories.items():
            for error in errors:
                # Skip errors that can't be automatically fixed
                if not error.get('automatedFix', False):
                    if VERBOSE:
                        print(f"Skipping {error['errorCode']} ({error.get('description', '')}): Not automatable")
                    continue
                
                # Check if we have a fix configuration for this error
                error_code = error['errorCode']
                fix_config = FIX_CONFIGURATIONS.get(error_code)
                
                if not fix_config:
                    if VERBOSE:
                        print(f"Skipping {error_code}: No fix configuration available")
                    continue
                
                # Generate the fix script
                script_content = generate_fix_script(template, error_code, fix_config)
                
                # Write or simulate writing the script
                if DRY_RUN:
                    print(f"[Dry run] Would generate fix script for {error_code} ({error.get('description', '')})")
                    if VERBOSE:
                        print('--- Script preview ---')
                        print(script_content[:200] + '...')
                        print('---------------------')
                else:
                    write_fix_script(OUTPUT_DIR, error_code, script_content)
                
                generated_scripts.append({
                    'errorCode': error_code,
                    'description': error.get('description', ''),
                    'occurrences': error.get('count', 0),
                    'path': os.path.join(OUTPUT_DIR, f"fix_{error_code.lower().replace('/', '_')}.py")
                })
    
    # Print summary
    print('\nFix Script Generation Summary:')
    print(f"Total scripts generated: {len(generated_scripts)}")
    
    if generated_scripts:
        print('\nGenerated scripts:')
        for script in generated_scripts:
            print(f"- {script['path']} (fixes {script['occurrences']} occurrences of {script['errorCode']}: {script['description']})")
        
        print('\nExample usage:')
        if generated_scripts:
            example = generated_scripts[0]
            print(f"  python {example['path']} [--dry-run] [--verbose] [target_directory]")
    
    if DRY_RUN:
        print('\nThis was a dry run. No files were actually written.')


if __name__ == "__main__":
    main()