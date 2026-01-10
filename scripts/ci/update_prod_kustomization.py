#!/usr/bin/env python3
"""
Update production kustomization.yaml with new image tags.

Usage:
  update_prod_kustomization.py --file <kustomization.yaml> --image-tag <tag>

This script updates the image tags in the production kustomization.yaml file.
"""
import argparse
import sys
import yaml
from datetime import datetime, timezone


def update_image_tags(file_path: str, image_tag: str):
    """Update the image tags in the kustomization file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    # Update image tags
    for image in data.get('images', []):
        if image['name'] in ['yt-summarizer-api', 'yt-summarizer-workers']:
            image['newTag'] = image_tag

    # Write back with proper formatting
    with open(file_path, 'w', encoding='utf-8') as f:
        # Write header comments
        f.write('# =============================================================================\n')
        f.write('# Production Overlay Kustomization\n')
        f.write('# =============================================================================\n')
        f.write(f'# Single production environment - auto-synced by Argo CD on merge to main\n')
        f.write(f'# Last updated: {datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}\n')
        f.write('\n')

        # Use yaml.dump with proper formatting
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2, allow_unicode=True)

    print(f'Updated {file_path} with image tag: {image_tag}')


def main():
    parser = argparse.ArgumentParser(description='Update production kustomization.yaml')
    parser.add_argument('--file', required=True, help='Path to kustomization.yaml')
    parser.add_argument('--image-tag', required=True, help='New image tag')

    args = parser.parse_args()

    update_image_tags(args.file, args.image_tag)


if __name__ == '__main__':
    main()