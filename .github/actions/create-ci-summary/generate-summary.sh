#!/bin/bash

################################################################################
# Action: create-ci-summary / generate-summary.sh
#
# Purpose: Generates a rich GitHub step summary with CI pipeline results,
#          test outcomes, timing information, and detected code changes.
#          Provides visual overview of entire pipeline status.
#
# Inputs (Environment Variables):
#   CHANGED_AREAS                        - Space-separated list of changed code areas
#   COMMIT_SHA                           - Git commit SHA
#   PR_NUMBER                            - Pull request number (empty for main)
#   LINT_PYTHON_RESULT                   - Result of Python linting (success/failure/skipped)
#   LINT_FRONTEND_RESULT                 - Result of frontend linting
#   SCAN_PYTHON_SECURITY_RESULT          - Result of Python security scanning
#   SCAN_JAVASCRIPT_SECURITY_RESULT      - Result of JavaScript security scanning
#   SECRET_SCANNING_RESULT               - Result of secret scanning
#   TEST_SHARED_RESULT, DURATION         - Shared package test results + timing
#   TEST_API_RESULT, DURATION            - API service test results + timing
#   TEST_WORKERS_RESULT, DURATION        - Workers test results + timing
#   TEST_FRONTEND_RESULT                 - Frontend test results
#   KUBERNETES_VALIDATE_RESULT           - K8s manifest validation result
#   VALIDATE_KUSTOMIZE_RESULT            - Kustomize overlay validation result
#   VALIDATE_TERRAFORM_RESULT            - Terraform validation result
#   BUILD_IMAGES_RESULT                  - Docker image build result
#   IMAGE_TAG                            - Generated image tag
#   REPOSITORY                           - GitHub repository (owner/repo)
#   RUN_ID                               - GitHub Actions run ID
#
# Outputs:
#   Writes to $GITHUB_STEP_SUMMARY (GitHub-specific environment variable)
#   Creates formatted markdown tables with status icons and links
#
# Process:
#   1. Helper function to format job status with emoji
#   2. Helper function to format duration (or use dash if empty)
#   3. Determine overall pipeline status
#   4. Generate markdown headers and metadata table
#   5. Generate section tables for: changes, linting, security, tests, validation, builds
#   6. Add links section with action run and PR links
#
# Error Handling:
#   - Gracefully handles missing/empty input variables
#   - Uses dash (-) for missing durations
#   - Skips sections conditionally (e.g., docker images section if no images built)
#   - Does not fail even if some inputs missing
#
################################################################################

set -euo pipefail

CHANGED_AREAS="${CHANGED_AREAS:-}"
COMMIT_SHA="${COMMIT_SHA:?COMMIT_SHA not set}"
PR_NUMBER="${PR_NUMBER:}"
LINT_PYTHON_RESULT="${LINT_PYTHON_RESULT:-skipped}"
LINT_FRONTEND_RESULT="${LINT_FRONTEND_RESULT:-skipped}"
SCAN_PYTHON_SECURITY_RESULT="${SCAN_PYTHON_SECURITY_RESULT:-skipped}"
SCAN_JAVASCRIPT_SECURITY_RESULT="${SCAN_JAVASCRIPT_SECURITY_RESULT:-skipped}"
SECRET_SCANNING_RESULT="${SECRET_SCANNING_RESULT:-skipped}"
TEST_SHARED_RESULT="${TEST_SHARED_RESULT:-skipped}"
TEST_SHARED_DURATION="${TEST_SHARED_DURATION:}"
TEST_API_RESULT="${TEST_API_RESULT:-skipped}"
TEST_API_DURATION="${TEST_API_DURATION:}"
TEST_WORKERS_RESULT="${TEST_WORKERS_RESULT:-skipped}"
TEST_WORKERS_DURATION="${TEST_WORKERS_DURATION:}"
TEST_FRONTEND_RESULT="${TEST_FRONTEND_RESULT:-skipped}"
KUBERNETES_VALIDATE_RESULT="${KUBERNETES_VALIDATE_RESULT:-skipped}"
VALIDATE_KUSTOMIZE_RESULT="${VALIDATE_KUSTOMIZE_RESULT:-skipped}"
VALIDATE_TERRAFORM_RESULT="${VALIDATE_TERRAFORM_RESULT:-skipped}"
BUILD_IMAGES_RESULT="${BUILD_IMAGES_RESULT:-skipped}"
IMAGE_TAG="${IMAGE_TAG:}"
REPOSITORY="${REPOSITORY:?REPOSITORY not set}"
RUN_ID="${RUN_ID:?RUN_ID not set}"

# Helper to format job status
format_status() {
  case "$1" in
    "success") echo "✅ Passed" ;;
    "failure") echo "❌ Failed" ;;
    "skipped") echo "⏭️ Skipped" ;;
    "cancelled") echo "🚫 Cancelled" ;;
    *) echo "❓ Unknown" ;;
  esac
}

# Helper to format duration
format_duration() {
  if [ -n "$1" ] && [ "$1" != "" ]; then
    echo "$1"
  else
    echo "-"
  fi
}

# Determine overall status
OVERALL_STATUS="✅ Success"
HAS_FAILURES=false

for result in "$LINT_PYTHON_RESULT" "$LINT_FRONTEND_RESULT" \
              "$SCAN_PYTHON_SECURITY_RESULT" "$SCAN_JAVASCRIPT_SECURITY_RESULT" \
              "$TEST_SHARED_RESULT" "$TEST_API_RESULT" \
              "$TEST_WORKERS_RESULT" "$TEST_FRONTEND_RESULT" \
              "$KUBERNETES_VALIDATE_RESULT" "$VALIDATE_KUSTOMIZE_RESULT" \
              "$BUILD_IMAGES_RESULT"; do
  if [ "$result" = "failure" ]; then
    HAS_FAILURES=true
    OVERALL_STATUS="❌ Failed"
    break
  fi
done

# Write summary header
echo "# 🔧 CI Pipeline Summary" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Meta information
echo "| Property | Value |" >> $GITHUB_STEP_SUMMARY
echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
echo "| **Status** | $OVERALL_STATUS |" >> $GITHUB_STEP_SUMMARY
if [ -n "$PR_NUMBER" ]; then
  echo "| **Pull Request** | [#$PR_NUMBER](https://github.com/$REPOSITORY/pull/$PR_NUMBER) |" >> $GITHUB_STEP_SUMMARY
fi
echo "| **Commit** | \`$COMMIT_SHA\` |" >> $GITHUB_STEP_SUMMARY
if [ -n "$IMAGE_TAG" ]; then
  echo "| **Image Tag** | \`$IMAGE_TAG\` |" >> $GITHUB_STEP_SUMMARY
fi
echo "" >> $GITHUB_STEP_SUMMARY

# Changed areas section
echo "## 📁 Changes Detected" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
if [ -z "$CHANGED_AREAS" ]; then
  echo "_No changes detected_" >> $GITHUB_STEP_SUMMARY
else
  for area in $CHANGED_AREAS; do
    case "$area" in
      "services/api") echo "- 🐍 **API Service** (\`services/api/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "services/workers") echo "- ⚙️ **Workers** (\`services/workers/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "services/shared") echo "- 📦 **Shared Package** (\`services/shared/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "apps/web") echo "- 🌐 **Frontend** (\`apps/web/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "k8s") echo "- ☸️ **Kubernetes** (\`k8s/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "infra/terraform") echo "- 🏗️ **Terraform** (\`infra/terraform/\`)" >> $GITHUB_STEP_SUMMARY ;;
      "docker") echo "- 🐳 **Docker** (\`docker/\`)" >> $GITHUB_STEP_SUMMARY ;;
      ".github") echo "- 🔄 **CI/CD** (\`.github/\`)" >> $GITHUB_STEP_SUMMARY ;;
      *) echo "- 📄 \`$area\`" >> $GITHUB_STEP_SUMMARY ;;
    esac
  done
fi
echo "" >> $GITHUB_STEP_SUMMARY

# Linting section
echo "## 🧹 Linting" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Check | Status |" >> $GITHUB_STEP_SUMMARY
echo "|-------|--------|" >> $GITHUB_STEP_SUMMARY
echo "| Python (ruff) | $(format_status "$LINT_PYTHON_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "| Frontend (ESLint) | $(format_status "$LINT_FRONTEND_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Security section
echo "## 🔒 Security" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Scan | Status |" >> $GITHUB_STEP_SUMMARY
echo "|------|--------|" >> $GITHUB_STEP_SUMMARY
echo "| Python (bandit/pip-audit) | $(format_status "$SCAN_PYTHON_SECURITY_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "| JavaScript (npm audit) | $(format_status "$SCAN_JAVASCRIPT_SECURITY_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "| Secrets (gitleaks) | $(format_status "$SECRET_SCANNING_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Testing section
echo "## 🧪 Tests" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Test Suite | Status | Duration |" >> $GITHUB_STEP_SUMMARY
echo "|------------|--------|----------|" >> $GITHUB_STEP_SUMMARY
echo "| Shared Package | $(format_status "$TEST_SHARED_RESULT") | $(format_duration "$TEST_SHARED_DURATION") |" >> $GITHUB_STEP_SUMMARY
echo "| API Service | $(format_status "$TEST_API_RESULT") | $(format_duration "$TEST_API_DURATION") |" >> $GITHUB_STEP_SUMMARY
echo "| Workers | $(format_status "$TEST_WORKERS_RESULT") | $(format_duration "$TEST_WORKERS_DURATION") |" >> $GITHUB_STEP_SUMMARY
echo "| Frontend | $(format_status "$TEST_FRONTEND_RESULT") | - |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Validation section
echo "## ✅ Validation" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Check | Status |" >> $GITHUB_STEP_SUMMARY
echo "|-------|--------|" >> $GITHUB_STEP_SUMMARY
echo "| Kubernetes Manifests | $(format_status "$KUBERNETES_VALIDATE_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "| Kustomize Overlays | $(format_status "$VALIDATE_KUSTOMIZE_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "| Terraform | $(format_status "$VALIDATE_TERRAFORM_RESULT") |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Build section
if [ -n "$IMAGE_TAG" ] || [ "$BUILD_IMAGES_RESULT" != "skipped" ]; then
  echo "## 🐳 Docker Images" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "| Build | Status |" >> $GITHUB_STEP_SUMMARY
  echo "|-------|--------|" >> $GITHUB_STEP_SUMMARY
  echo "| Build & Push | $(format_status "$BUILD_IMAGES_RESULT") |" >> $GITHUB_STEP_SUMMARY
  if [ -n "$IMAGE_TAG" ]; then
    echo "" >> $GITHUB_STEP_SUMMARY
    echo "**Images built:**" >> $GITHUB_STEP_SUMMARY
    echo "- \`acrytsummprd.azurecr.io/yt-summarizer-api:$IMAGE_TAG\`" >> $GITHUB_STEP_SUMMARY
    echo "- \`acrytsummprd.azurecr.io/yt-summarizer-workers:$IMAGE_TAG\`" >> $GITHUB_STEP_SUMMARY
  fi
  echo "" >> $GITHUB_STEP_SUMMARY
fi

# Links section
echo "## 🔗 Links" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "- [View Workflow Run](https://github.com/$REPOSITORY/actions/runs/$RUN_ID)" >> $GITHUB_STEP_SUMMARY
if [ -n "$PR_NUMBER" ]; then
  echo "- [View Pull Request](https://github.com/$REPOSITORY/pull/$PR_NUMBER)" >> $GITHUB_STEP_SUMMARY
fi
echo "" >> $GITHUB_STEP_SUMMARY
