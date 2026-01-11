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

        # Custom YAML writing to preserve literal blocks for patches
        write_yaml_with_literal_blocks(f, data, indent=0)


def write_yaml_with_literal_blocks(f, data, indent=0):
    """Write YAML data with proper handling of literal blocks for patch fields."""
    indent_str = '  ' * indent

    if isinstance(data, dict):
        # Sort keys to maintain consistent order, but put certain keys first
        key_order = ['apiVersion', 'kind', 'metadata', 'namespace', 'resources', 'patches', 'images', 'labels']
        sorted_keys = sorted(data.keys(), key=lambda x: (key_order.index(x) if x in key_order else len(key_order), x))

        for i, key in enumerate(sorted_keys):
            value = data[key]
            if key == 'patches' and isinstance(value, list):
                f.write(f'{indent_str}patches:\n')
                for patch_item in value:
                    write_patch_item(f, patch_item, indent + 1)
            elif key == 'labels' and isinstance(value, list):
                f.write(f'{indent_str}labels:\n')
                for label_item in value:
                    f.write(f'{indent_str}- pairs:\n')
                    if 'pairs' in label_item and isinstance(label_item['pairs'], dict):
                        for k, v in label_item['pairs'].items():
                            f.write(f'{indent_str}    {k}: "{v}"\n')
            else:
                f.write(f'{indent_str}{key}:')
                if isinstance(value, (dict, list)):
                    f.write('\n')
                    write_yaml_with_literal_blocks(f, value, indent + 1)
                else:
                    # Quote values that could be confused with booleans
                    if isinstance(value, str) and value.lower() in ('true', 'false', 'null', 'yes', 'no', 'on', 'off'):
                        f.write(f' "{value}"\n')
                    else:
                        f.write(f' {value}\n')
    elif isinstance(data, list):
        for item in data:
            f.write(f'{indent_str}- ')
            if isinstance(item, (dict, list)):
                f.write('\n')
                write_yaml_with_literal_blocks(f, item, indent + 1)
            else:
                f.write(f'{item}\n')


def write_patch_item(f, patch_item, indent):
    """Write a patch item with proper formatting."""
    indent_str = '  ' * indent

    if 'path' in patch_item:
        # This is a path-based patch
        f.write(f'{indent_str}- path: {patch_item["path"]}\n')
    elif 'target' in patch_item:
        # This is a target-based patch
        # Print list item and nest the target fields under it
        f.write(f'{indent_str}- target:\n')
        target = patch_item['target']
        target_order = ['group', 'version', 'apiVersion', 'kind', 'name', 'namespace']
        # Use extra indentation so fields become children of 'target' (list item uses '- ') 
        child_indent = '  ' * (indent + 2)
        for key in target_order:
            if key in target:
                f.write(f'{child_indent}{key}: {target[key]}\n')
        # Write any remaining keys
        for key, value in target.items():
            if key not in target_order:
                f.write(f'{child_indent}{key}: {value}\n')
        if 'patch' in patch_item:
            patch_content = patch_item['patch']
            # patch should be a sibling of 'target' (not a child) - compute a shallower indent
            patch_indent = '  ' * (indent + 1)
            if isinstance(patch_content, str):
                # Check if it's a special delete patch
                if patch_content.strip() == '$patch: delete':
                    f.write(f'{patch_indent}patch: |\n')
                    f.write(f'{patch_indent}  $patch: delete\n')
                    # Add the apiVersion and kind for delete patches
                    if 'target' in patch_item:
                        target = patch_item['target']
                        if 'apiVersion' in target and 'kind' in target and 'name' in target:
                            f.write(f'{patch_indent}  apiVersion: {target["apiVersion"]}\n')
                            f.write(f'{patch_indent}  kind: {target["kind"]}\n')
                            f.write(f'{patch_indent}  metadata:\n')
                            f.write(f'{patch_indent}    name: {target["name"]}\n')
                elif patch_content.startswith('- op:'):
                    # This is a JSON patch as a literal block
                    f.write(f'{patch_indent}patch: |\n')
                    for line in patch_content.split('\n'):
                        if line.strip():
                            f.write(f'{patch_indent}  {line}\n')
                else:
                    # This is a strategic merge patch as a literal block
                    f.write(f'{patch_indent}patch: |\n')
                    for line in patch_content.split('\n'):
                        if line.strip():
                            f.write(f'{patch_indent}  {line}\n')
            elif isinstance(patch_content, list):
                # This is a list of patch operations (JSON patches)
                f.write(f'{patch_indent}patch:\n')
                for op in patch_content:
                    f.write(f'{patch_indent}- op: {op["op"]}\n')
                    f.write(f'{patch_indent}  path: {op["path"]}\n')
                    if 'value' in op:
                        f.write(f'{patch_indent}  value:')
                        if isinstance(op['value'], (dict, list)):
                            f.write('\n')
                            write_yaml_with_literal_blocks(f, op['value'], indent + 2)
                        else:
                            f.write(f' {op["value"]}\n')
            else:
                f.write(f'{patch_indent}patch:\n')
                write_yaml_with_literal_blocks(f, patch_content, indent + 1)
    else:
        # Fallback for other patch types
        f.write(f'{indent_str}- ')
        write_yaml_with_literal_blocks(f, patch_item, indent + 1)


def generate_from_template(template_path: str, output_path: str, variables: Dict[str, str], header_comments: list[str]):
    """Complete workflow: load template, substitute variables, write output."""
    # Load template
    data = load_template(template_path)

    # Substitute variables
    data = substitute_variables(data, variables)

    # Write output
    write_kustomization_file(output_path, data, header_comments)

    print(f'Generated {output_path}')