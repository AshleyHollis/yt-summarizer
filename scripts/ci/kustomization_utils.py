#!/usr/bin/env python3
"""
Shared utilities for kustomization generation.

This module provides common functionality for loading templates,
performing variable substitution, and writing formatted YAML files.
"""
import yaml
from datetime import datetime, timezone
from typing import Dict, Any


def load_template(template_path: str) -> Dict[str, Any]:
    """Load a YAML template file."""
    with open(template_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def substitute_variables(data: Dict[str, Any], variables: Dict[str, str]) -> Dict[str, Any]:
    """Recursively substitute variables in the data structure.

    Variables should be in the format __VAR_NAME__ and will be replaced
    with the corresponding value from the variables dict.
    """
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            # Substitute in keys
            new_key = substitute_string_variables(key, variables)
            # Substitute in values
            result[new_key] = substitute_variables(value, variables)
        return result
    elif isinstance(data, list):
        return [substitute_variables(item, variables) for item in data]
    elif isinstance(data, str):
        return substitute_string_variables(data, variables)
    else:
        return data


def substitute_string_variables(text: str, variables: Dict[str, str]) -> str:
    """Substitute __VAR_NAME__ placeholders in a string."""
    result = text
    for var_name, var_value in variables.items():
        placeholder = f"__{var_name}__"
        result = result.replace(placeholder, str(var_value))
    return result


def write_kustomization_file(output_path: str, data: Dict[str, Any], header_comments: list[str]):
    """Write the kustomization data to file with proper formatting and headers."""
    with open(output_path, 'w', encoding='utf-8') as f:
        # Write header comments
        for comment in header_comments:
            f.write(f'# {comment}\n')
        f.write('\n')

        # Use yaml.dump with proper formatting
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)


def generate_from_template(template_path: str, output_path: str, variables: Dict[str, str], header_comments: list[str]):
    """Complete workflow: load template, substitute variables, write output."""
    # Load template
    data = load_template(template_path)

    # Substitute variables
    data = substitute_variables(data, variables)

    # Write output
    write_kustomization_file(output_path, data, header_comments)

    print(f'Generated {output_path}')