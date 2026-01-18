#!/bin/bash
# =============================================================================
# Setup Kustomize - Install Python Dependencies
# =============================================================================
# PURPOSE:
#   Installs Python dependencies for kustomization validation scripts
#
# INPUTS:
#   None (installs standard dependencies)
#
# OUTPUTS:
#   Installed pip packages (pip, pyyaml)
#
# LOGIC:
#   1. Upgrade pip to latest version
#   2. Install pyyaml for YAML parsing in validation scripts
#
# =============================================================================
set -euo pipefail

echo "Installing Python dependencies for kustomize validation..."
python -m pip install --upgrade pip
pip install pyyaml
echo "✅ Python dependencies installed"
