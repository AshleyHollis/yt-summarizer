#!/usr/bin/env python3
"""
Generate preview kustomization.yaml with proper YAML formatting.

Usage:
  generate_preview_kustomization.py --template <template.yaml> --output <file> --pr-number <number> --image-tag <tag> --acr-server <server>

This script loads a template and substitutes variables for the preview overlay.
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
    parser = argparse.ArgumentParser(description="Generate preview kustomization.yaml")
    parser.add_argument("--template", required=True, help="Path to template file")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--pr-number", required=True, help="PR number")
    parser.add_argument("--image-tag", required=True, help="Image tag")
    parser.add_argument("--acr-server", required=True, help="ACR server")
    parser.add_argument(
        "--preview-host",
        required=False,
        help="Preview host (replaces __PREVIEW_HOST__ in patches)",
    )
    parser.add_argument(
        "--tls-secret",
        required=False,
        help="TLS secret name (replaces __TLS_SECRET__ in patches)",
    )
    parser.add_argument(
        "--commit-sha", required=False, help="Commit SHA for uniqueness"
    )
    parser.add_argument(
        "--swa-url",
        required=False,
        help="Azure Static Web App URL (replaces __SWA_URL__ in patches)",
    )

    args = parser.parse_args()

    # Generate SWA URL if not provided (using known pattern from SWA deployment)
    swa_url = args.swa_url
    if not swa_url:
        # Azure Static Web Apps URL pattern: https://red-grass-06d413100-{PR}.eastasia.6.azurestaticapps.net
        swa_url = f"https://red-grass-06d413100-{args.pr_number}.eastasia.6.azurestaticapps.net"
        print(f"Generated SWA URL: {swa_url}")

    # Define variables for substitution
    variables = {
        "PR_NUMBER": args.pr_number,
        "IMAGE_TAG": args.image_tag,
        "ACR_SERVER": args.acr_server,
        "PREVIEW_HOST": args.preview_host or "",
        "TLS_SECRET": args.tls_secret or "",
        "SWA_URL": swa_url,
    }

    # Define header comments
    header_comments = [
        "Preview overlay - updated by GitHub Actions",
        f"PR: #{args.pr_number}",
        f"Image Tag: {args.image_tag}",
        f"Commit: {args.commit_sha or 'unknown'}",
        f"Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
    ]

    generate_from_template(args.template, args.output, variables, header_comments)

    print(
        f"Generated {args.output} for PR #{args.pr_number} with image tag: {args.image_tag}"
    )
    print(
        f"NOTE: Patches are generated inline in kustomization.yaml with substituted values"
    )


if __name__ == "__main__":
    main()
