#!/usr/bin/env python3
"""
Purpose: Validates YAML syntax for all Kubernetes manifest files
Inputs:
  directory: Directory containing Kubernetes manifests (default: k8s)
Outputs: Exit code 0 (all valid) or 1 (any invalid YAML)
Logic:
  1. Recursively walk through directory
  2. Find all files matching *.yaml or *.yml extension
  3. Parse each file with yaml.safe_load_all()
  4. Catch YAMLError exceptions for syntax errors
  5. Report each valid/invalid file
  6. Exit with error if any file fails validation
"""

import yaml
import os
import sys

SEARCH_DIR = "${{ inputs.directory }}"
if SEARCH_DIR == ".":
    SEARCH_DIR = "."

exit_code = 0

for root, dirs, files in os.walk(SEARCH_DIR):
    for file in files:
        if file.endswith((".yaml", ".yml")):
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    list(yaml.safe_load_all(f))
                print(f"✅ Valid: {filepath}")
            except yaml.YAMLError as e:
                print(f"❌ YAML error in {filepath}: {e}")
                exit_code = 1
            except Exception as e:
                print(f"❌ Error in {filepath}: {e}")
                exit_code = 1

if exit_code == 0:
    print("✅ All YAML files have valid syntax")
else:
    print("::error::YAML syntax validation failed")

sys.exit(exit_code)
