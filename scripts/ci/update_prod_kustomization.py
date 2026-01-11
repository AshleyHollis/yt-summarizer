#!/usr/bin/env python3
"""
Update production kustomization.yaml with new image tags.

Usage:
  update_prod_kustomization.py --template <template.yaml> --output <kustomization.yaml> --image-tag <tag>

This script loads a template and substitutes the image tag.
"""
import argparse
import sys
import os
from datetime import datetime, timezone

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Import shared utilities
from kustomization_utils import generate_from_template


def main():
    parser = argparse.ArgumentParser(description='Update production kustomization.yaml')
    parser.add_argument('--template', required=True, help='Path to template file')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--image-tag', required=True, help='New image tag')

    args = parser.parse_args()

    # Define variables for substitution
    variables = {
        'IMAGE_TAG': args.image_tag
    }

    # Define header comments
    header_comments = [
        '=============================================================================',
        'Production Overlay Kustomization',
        '=============================================================================',
        'Single production environment - auto-synced by Argo CD on merge to main',
        f'Last updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
    ]

    generate_from_template(args.template, args.output, variables, header_comments)

    print(f'Generated {args.output} with image tag: {args.image_tag}')


if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()