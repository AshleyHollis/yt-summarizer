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

# Import shared utilities
from kustomization_utils import generate_from_template


def main():
    parser = argparse.ArgumentParser(description='Generate preview kustomization.yaml')
    parser.add_argument('--template', required=True, help='Path to template file')
    parser.add_argument('--output', required=True, help='Output file path')
    parser.add_argument('--pr-number', required=True, help='PR number')
    parser.add_argument('--image-tag', required=True, help='Image tag')
    parser.add_argument('--acr-server', required=True, help='ACR server')

    args = parser.parse_args()

    # Define variables for substitution
    variables = {
        'PR_NUMBER': args.pr_number,
        'IMAGE_TAG': args.image_tag,
        'ACR_SERVER': args.acr_server
    }

    # Define header comments
    header_comments = [
        'Preview overlay - updated by GitHub Actions',
        f'PR: #{args.pr_number}',
        f'Image Tag: {args.image_tag}',
        f'Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
    ]

    generate_from_template(args.template, args.output, variables, header_comments)

    print(f'Generated {args.output} for PR #{args.pr_number} with image tag: {args.image_tag}')


if __name__ == '__main__':
    main()