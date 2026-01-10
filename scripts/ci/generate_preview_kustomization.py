#!/usr/bin/env python3
"""
Generate preview kustomization.yaml with proper YAML formatting.

Usage:
  generate_preview_kustomization.py --template <template.yaml> --output <file> --pr-number <number> --image-tag <tag> --acr-server <server>

This script loads a template and substitutes variables for the preview overlay.
"""
import argparse
import sys
from datetime import datetime, timezone
import yaml


def generate_from_template(template_path: str, output_path: str, pr_number: str, image_tag: str, acr_server: str):
    """Load template and substitute variables."""
    with open(template_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    # Substitute variables
    if 'namespace' in data and '__PR_NUMBER__' in data['namespace']:
        data['namespace'] = data['namespace'].replace('__PR_NUMBER__', pr_number)

    # Substitute in images
    for image in data.get('images', []):
        if '__ACR_SERVER__' in str(image.get('newName', '')):
            image['newName'] = image['newName'].replace('__ACR_SERVER__', acr_server)
        if '__IMAGE_TAG__' in str(image.get('newTag', '')):
            image['newTag'] = image['newTag'].replace('__IMAGE_TAG__', image_tag)

    # Substitute in labels
    for label_group in data.get('labels', []):
        pairs = label_group.get('pairs', {})
        if '__PR_NUMBER__' in str(pairs.get('preview.pr-number', '')):
            pairs['preview.pr-number'] = pairs['preview.pr-number'].replace('__PR_NUMBER__', pr_number)

    # Write to output with proper formatting
    with open(output_path, 'w', encoding='utf-8') as f:
        # Write header comments
        f.write('# Preview overlay - updated by GitHub Actions\n')
        f.write(f'# PR: #{pr_number}\n')
        f.write(f'# Image Tag: {image_tag}\n')
        f.write(f'# Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n')
        f.write('\n')

        # Use yaml.dump with proper formatting
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)

    print(f'Generated {output_path} for PR #{pr_number} with image tag: {image_tag}')


def main():
    parser = argparse.ArgumentParser(description='Generate preview kustomization.yaml')
    parser.add_argument('--template', required=True, help='Path to template file')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--pr-number', required=True, help='PR number')
    parser.add_argument('--image-tag', required=True, help='Image tag')
    parser.add_argument('--acr-server', required=True, help='ACR server')

    args = parser.parse_args()

    generate_from_template(args.template, args.output, args.pr_number, args.image_tag, args.acr_server)


if __name__ == '__main__':
    main()