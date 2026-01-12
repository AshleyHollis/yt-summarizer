#!/usr/bin/env python3
"""
Validate all GitHub Actions workflow YAML files for syntax errors.
This script checks all .yml and .yaml files in .github/workflows/
"""
import sys
import os
from pathlib import Path

try:
    import yaml
except ImportError as e:
    print('ERROR: PyYAML not installed:', e)
    print('Install with: pip install pyyaml')
    sys.exit(1)


def validate_yaml_file(filepath):
    """Validate a single YAML file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as fh:
            yaml.safe_load(fh)
        return True, None
    except yaml.YAMLError as e:
        return False, str(e)
    except Exception as e:
        return False, f"Unexpected error: {str(e)}"


def main():
    """Main validation function."""
    workflows_dir = Path('.github/workflows')
    
    if not workflows_dir.exists():
        print(f'ERROR: Directory {workflows_dir} not found')
        sys.exit(1)
    
    # Find all YAML workflow files
    workflow_files = list(workflows_dir.glob('*.yml')) + list(workflows_dir.glob('*.yaml'))
    
    if not workflow_files:
        print(f'WARNING: No workflow files found in {workflows_dir}')
        sys.exit(0)
    
    print(f'Validating {len(workflow_files)} workflow file(s)...\n')
    
    errors = []
    for filepath in sorted(workflow_files):
        print(f'Checking {filepath}...', end=' ')
        is_valid, error_msg = validate_yaml_file(filepath)
        
        if is_valid:
            print('✓ OK')
        else:
            print('✗ FAILED')
            errors.append((filepath, error_msg))
    
    # Print summary
    print(f'\n{"="*60}')
    if errors:
        print(f'VALIDATION FAILED: {len(errors)} file(s) with errors\n')
        for filepath, error_msg in errors:
            print(f'File: {filepath}')
            print(f'Error: {error_msg}\n')
        sys.exit(1)
    else:
        print(f'SUCCESS: All {len(workflow_files)} workflow file(s) are valid')
        sys.exit(0)


if __name__ == '__main__':
    main()
