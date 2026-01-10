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
    parser.add_argument('--preview-host', required=False, help='Preview host (replaces __PREVIEW_HOST__ in patches)')
    parser.add_argument('--tls-secret', required=False, help='TLS secret name (replaces __TLS_SECRET__ in patches)')

    args = parser.parse_args()

    # Define variables for substitution
    variables = {
        'PR_NUMBER': args.pr_number,
        'IMAGE_TAG': args.image_tag,
        'ACR_SERVER': args.acr_server,
        'PREVIEW_HOST': args.preview_host or '',
        'TLS_SECRET': args.tls_secret or ''
    }

    # Define header comments
    header_comments = [
        'Preview overlay - updated by GitHub Actions',
        f'PR: #{args.pr_number}',
        f'Image Tag: {args.image_tag}',
        f'Updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}'
    ]

    generate_from_template(args.template, args.output, variables, header_comments)

    # Optionally substitute placeholders in overlay patch files (ingress patch)
    if args.preview_host or args.tls_secret:
        patch_path = 'k8s/overlays/preview/patches/ingress-patch.yaml'
        try:
            with open(patch_path, 'r', encoding='utf-8') as f:
                content = f.read()
            if args.preview_host:
                content = content.replace('__PREVIEW_HOST__', args.preview_host)
            if args.tls_secret:
                content = content.replace('__TLS_SECRET__', args.tls_secret)
            with open(patch_path, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f'Patched {patch_path} with preview host and TLS secret')
        except FileNotFoundError:
            print(f'Patch file not found: {patch_path} (skipping patch substitution)')

    print(f'Generated {args.output} for PR #{args.pr_number} with image tag: {args.image_tag}')


if __name__ == '__main__':
    main()