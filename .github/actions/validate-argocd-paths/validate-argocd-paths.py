#!/usr/bin/env python3
"""
Purpose: Validates that ArgoCD Application manifests reference existing paths
Inputs:
  argocd-manifests-path: Path to ArgoCD application manifests (glob pattern)
Outputs: Exit code 0 (all valid) or 1 (any invalid)
Logic:
  1. Glob for all matching YAML files in manifests path
  2. Parse each file with yaml.safe_load_all()
  3. Filter for documents with kind=Application
  4. Extract spec.source.path and spec.source.repoURL
  5. For paths in this repo, check if directory exists
  6. Report invalid paths and exit with error
"""

import yaml
import os
import sys
import glob

ARGOCD_MANIFESTS_PATH = "${{ inputs.argocd-manifests-path }}"

exit_code = 0
for app_file in glob.glob(ARGOCD_MANIFESTS_PATH):
    print(f"Checking ArgoCD Applications in: {app_file}")

    try:
        with open(app_file, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        for doc in docs:
            if not doc or doc.get("kind") != "Application":
                continue

            app_name = doc.get("metadata", {}).get("name", "unknown")
            source = doc.get("spec", {}).get("source", {})
            repo_url = source.get("repoURL", "")
            path = source.get("path", "")

            # Only check paths for this repo (not Helm charts)
            if "github.com" in repo_url and "yt-summarizer" in repo_url and path:
                if not os.path.exists(path):
                    print(f"❌ Application '{app_name}': path '{path}' does not exist")
                    exit_code = 1
                else:
                    print(f"✅ Application '{app_name}': path '{path}' exists")

    except Exception as e:
        print(f"❌ Error processing {app_file}: {e}")
        exit_code = 1

if exit_code == 0:
    print("\n✅ All ArgoCD Application paths are valid")
else:
    print("\n❌ Some ArgoCD Application paths are invalid")

sys.exit(exit_code)
