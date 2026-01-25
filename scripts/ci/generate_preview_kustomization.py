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

    # Create PR-specific overlay directory structure if it doesn't exist
    pr_overlay_dir = f"k8s/overlays/preview-pr-{args.pr_number}"
    pr_patches_dir = os.path.join(pr_overlay_dir, "patches")
    os.makedirs(pr_patches_dir, exist_ok=True)
    print(f"Created PR-specific overlay directory: {pr_overlay_dir}")

    # Substitute placeholders in base-preview files (needed for HTTPRoute and other resources)
    base_preview_dir = "k8s/base-preview"
    try:
        import shutil

        for filename in os.listdir(base_preview_dir):
            src_path = os.path.join(base_preview_dir, filename)
            # Only process YAML files
            if not os.path.isfile(src_path) or not filename.endswith((".yaml", ".yml")):
                continue

            # Copy to PR-specific directory
            dst_path = os.path.join(pr_overlay_dir, filename)
            shutil.copy2(src_path, dst_path)

            # Read, substitute, and write to copy (not source)
            with open(dst_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Global substitutions
            content = content.replace("__PR_NUMBER__", args.pr_number)
            # Optional values
            if args.preview_host:
                content = content.replace("__PREVIEW_HOST__", args.preview_host)
            if args.tls_secret:
                content = content.replace("__TLS_SECRET__", args.tls_secret)
            # Always replace SWA URL (generated or provided)
            if swa_url:
                content = content.replace("__SWA_URL__", swa_url)
            with open(dst_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Copied and patched {src_path} -> {dst_path}")
    except FileNotFoundError:
        print(
            f"Base preview directory not found: {base_preview_dir} (skipping base substitutions)"
        )

    # Copy and substitute placeholders in overlay patch files
    # IMPORTANT: Copy to PR-specific directory, do NOT modify source patches
    source_patch_dir = "k8s/overlays/preview/patches"
    try:
        import shutil

        for filename in os.listdir(source_patch_dir):
            src_path = os.path.join(source_patch_dir, filename)
            # Only process regular files
            if not os.path.isfile(src_path):
                continue

            # Copy to PR-specific patches directory
            dst_path = os.path.join(pr_patches_dir, filename)
            shutil.copy2(src_path, dst_path)

            # Read, substitute, and write to copy (not source)
            with open(dst_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Global substitutions
            content = content.replace("__PR_NUMBER__", args.pr_number)
            # Optional values
            if args.preview_host:
                content = content.replace("__PREVIEW_HOST__", args.preview_host)
            if args.tls_secret:
                content = content.replace("__TLS_SECRET__", args.tls_secret)
            # Always replace SWA URL (generated or provided)
            if swa_url:
                content = content.replace("__SWA_URL__", swa_url)
            with open(dst_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Copied and patched {src_path} -> {dst_path}")
    except FileNotFoundError:
        print(
            f"Source patch directory not found: {source_patch_dir} (skipping patch substitutions)"
        )

    print(
        f"Generated {args.output} for PR #{args.pr_number} with image tag: {args.image_tag}"
    )
    print(f"PR-specific overlay created at: {pr_overlay_dir}")
    print(
        f"NOTE: Source template patches in {source_patch_dir} were NOT modified (they remain as templates)"
    )


if __name__ == "__main__":
    main()
