#!/usr/bin/env python3
"""
Update production kustomization.yaml with new image tags.

Usage:
  update_prod_kustomization.py --template <template.yaml> --output <kustomization.yaml> --image-tag <tag>

This script loads a template and substitutes the image tag.
"""
import argparse
import sys
import yaml
from datetime import datetime, timezone


def update_from_template(template_path: str, output_path: str, image_tag: str):
    """Load template and substitute image tag."""
    with open(template_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    # Substitute image tags
    for image in data.get('images', []):
        if '__IMAGE_TAG__' in str(image.get('newTag', '')):
            image['newTag'] = image['newTag'].replace('__IMAGE_TAG__', image_tag)

    # Write to output with proper formatting
    with open(output_path, 'w', encoding='utf-8') as f:
        # Write header comments
        f.write('# =============================================================================\n')
        f.write('# Production Overlay Kustomization\n')
        f.write('# =============================================================================\n')
        f.write(f'# Single production environment - auto-synced by Argo CD on merge to main\n')
        f.write(f'# Last updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n')
        f.write('\n')

        # Use yaml.dump with proper formatting
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)

    print(f'Generated {output_path} with image tag: {image_tag}')


def main():
    parser = argparse.ArgumentParser(description='Update production kustomization.yaml')
    parser.add_argument('--template', required=True, help='Path to template file')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--image-tag', required=True, help='New image tag')

    args = parser.parse_args()

    update_from_template(args.template, args.output, args.image_tag)


if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()