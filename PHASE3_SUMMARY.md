================================================================================
PHASE 3 CI/CD REFACTOR COMPLETE: Shared Utilities Library
================================================================================

✅ Created scripts/workflows/lib/ directory with 5 reusable utility files
✅ All files have proper shebangs and comprehensive documentation
✅ All files pass bash syntax validation
✅ Total new utility functions: 36 functions across 1,114 lines
✅ All functions use snake_case naming and follow 100-char line limit

================================================================================
UTILITY FILES CREATED
================================================================================

1. scripts/workflows/lib/github-utils.sh (183 lines, 10 functions)
   Purpose: GitHub Actions integration utilities
   
   Functions:
   - output_var(name, value)         Write variable to $GITHUB_OUTPUT
   - set_output(name, value)         Alias for output_var()
   - get_input(name)                 Read input from $GITHUB_INPUT
   - error(message)                  Output error and exit with code 1
   - warning(message)                Output warning message (non-fatal)
   - info(message)                   Output informational message
   - group_start(name)               Start a GitHub actions ::group::
   - group_end()                     End the current ::group::
   - set_step_summary(text)          Overwrite $GITHUB_STEP_SUMMARY
   - append_step_summary(text)       Append to step summary

2. scripts/workflows/lib/git-utils.sh (167 lines, 8 functions)
   Purpose: Git operations utilities
   
   Functions:
   - get_short_sha(sha)              Get 7-character commit SHA
   - get_commit_message(sha)         Get commit message/title
   - git_diff_exists(directory)      Check if files changed in directory
   - git_diff_files(directory)       Get list of changed files
   - git_log_summary(count)          Get commit summary for recent commits
   - validate_git_state()            Check repo is clean
   - get_current_branch()            Get current branch name
   - is_main_branch(branch)          Check if branch is main/master

3. scripts/workflows/lib/image-utils.sh (245 lines, 6 functions)
   Purpose: Image tag resolution (consolidates 3+ existing scripts)
   Consolidates: prod-extract-ci-image-tag.sh, prod-find-last-image.sh,
                 prod-determine-image-tag.sh
   
   Functions:
   - generate_image_tag(sha)         Create sha-{short_sha} tag format
   - extract_tag_from_kustomize()   Read tag from kustomization.yaml
   - validate_image_tag(tag)        Verify tag format/validity
   - get_ci_image_tag(sha)          Get CI-built tag for commit
   - get_last_prod_image()          Get existing prod tag
   - determine_image_tag(...)       Select which tag to deploy

4. scripts/workflows/lib/k8s-utils.sh (244 lines, 7 functions)
   Purpose: Kubernetes operations utilities
   
   Functions:
   - kubectl_wait_ready(...)        Wait for deployment/pod to be ready
   - kubectl_check_image(...)       Verify image deployed correctly
   - kubectl_get_deployment(...)    Get deployment information
   - kubectl_get_service(...)       Get service information
   - kubectl_port_forward(...)      Setup port forwarding
   - kubectl_get_pod_logs(...)      Get pod logs for debugging
   - kubectl_get_events(...)        Get recent K8s events

5. scripts/workflows/lib/health-utils.sh (275 lines, 5 functions)
   Purpose: Health check and readiness probe utilities
   
   Functions:
   - http_health_check(url, timeout)        Single HTTP health check
   - wait_for_health(url, timeout, ...)     Poll until endpoint healthy
   - check_dns_resolution(hostname)         Verify DNS resolution works
   - check_tls_certificate(hostname, port)  Verify TLS cert validity
   - check_service_ready(service_url)       Comprehensive readiness check

================================================================================
CONSOLIDATION OPPORTUNITIES IDENTIFIED
================================================================================

HIGH-PRIORITY CONSOLIDATIONS (Already captured in utilities):

1. Image tag management (3 scripts → 1 utility module)
   - prod-extract-ci-image-tag.sh (33 lines)
   - prod-find-last-image.sh (42 lines)
   - prod-determine-image-tag.sh (57 lines)
   TOTAL: 132 lines → image-utils.sh functions
   
   REFACTOR OPPORTUNITY: Replace these 3 scripts with:
   - source ./lib/image-utils.sh
   - get_ci_image_tag "$GITHUB_SHA"

2. GitHub Actions output patterns (used in 8+ scripts)
   Pattern: echo "var=$value" >> $GITHUB_OUTPUT
   REFACTOR OPPORTUNITY: All scripts using output_var() instead

3. Git operations (used in 5+ scripts)
   - Commit SHA extraction: get_short_sha()
   - File change detection: git_diff_exists(), git_diff_files()
   - Branch checks: is_main_branch()

4. Health checks (implicit in deployment scripts)
   - Kubernetes readiness: kubectl_wait_ready()
   - Service health: wait_for_health()
   - Can standardize post-deployment verification

MEDIUM-PRIORITY CONSOLIDATIONS (Patterns for future refactoring):

5. Rationale documentation (ci-write-rationale.sh, preview-write-rationale.sh)
   - Both append markdown to $GITHUB_STEP_SUMMARY
   - Could use append_step_summary() utility
   - Estimate: 2-3 scripts, 150+ lines savings

6. Error handling patterns (used in all 16 scripts)
   - Current: Mix of echo "::error::" and exit 1
   - Improved: Use error() function for consistency
   - Benefit: Centralized error handling, easier to audit

7. Change detection logic (ci-detect-changes.sh, preview-detect-infra.sh)
   - git_diff_exists() covers basic pattern
   - Could extract directory scanning patterns
   - Estimate: 2 scripts, 100+ lines potential savings

LOW-PRIORITY (Nice to have):

8. Logging and output formatting
   - Emoji usage (✅, ❌, ⏳, 🔍) could be standardized
   - Message formatting patterns

================================================================================
DEPENDENCY MAP FOR UTILITIES
================================================================================

github-utils.sh:
  └─ No external dependencies (uses $GITHUB_* env vars)

git-utils.sh:
  └─ Depends on: git command

image-utils.sh:
  ├─ Depends on: git (get_short_sha)
  ├─ Depends on: grep (extract_tag_from_kustomize)
  └─ Optional: github-utils.sh (output_var function)

k8s-utils.sh:
  └─ Depends on: kubectl command

health-utils.sh:
  ├─ Depends on: curl (HTTP checks)
  ├─ Optional: dig or nslookup (DNS checks)
  └─ Optional: openssl (TLS checks)

================================================================================
USAGE EXAMPLES FOR EXISTING SCRIPTS
================================================================================

1. Replace prod-extract-ci-image-tag.sh:
   Before:
     source prod-extract-ci-image-tag.sh
   After:
     source ./lib/image-utils.sh
     get_ci_image_tag "$GITHUB_SHA"

2. Replace prod-find-last-image.sh:
   Before:
     source prod-find-last-image.sh
   After:
     source ./lib/image-utils.sh
     get_last_prod_image "k8s/overlays/prod/kustomization.yaml"

3. Replace prod-determine-image-tag.sh:
   Before:
     source prod-determine-image-tag.sh
   After:
     source ./lib/image-utils.sh
     determine_image_tag "$CI_STATUS" "$PROD_STATUS" "$CI_TAG" "$PROD_TAG"

4. Improve ci-write-rationale.sh output:
   Add after initial echo:
     source ./lib/github-utils.sh
     append_step_summary "## CI Results..."

5. Improve error handling in any script:
   Before:
     echo "::error::Failed to build"
     exit 1
   After:
     source ./lib/github-utils.sh
     error "Failed to build"

================================================================================
QUALITY CHECKLIST
================================================================================

✅ All files have #!/bin/bash shebang
✅ All files have comprehensive header comments
✅ All files document purpose and list all functions
✅ All functions have parameter documentation
✅ All functions have return value documentation
✅ All functions have example usage
✅ All files use proper error handling
✅ All files are executable (chmod +x)
✅ All lines <= 100 characters (follows coding standards)
✅ All functions use snake_case naming
✅ All files pass bash syntax validation (-n)
✅ All files follow POSIX-compatible bash patterns

================================================================================
NEXT STEPS FOR FUTURE SESSIONS
================================================================================

PHASE 4 - Integration (Recommended for next session):

1. Refactor prod-extract-ci-image-tag.sh to use image-utils.sh
2. Refactor prod-find-last-image.sh to use image-utils.sh
3. Refactor prod-determine-image-tag.sh to use image-utils.sh
4. Update all scripts to use github-utils.sh functions
5. Update scripts to use git-utils.sh functions
6. Create integration tests for each utility function
7. Document utility library in scripts/README.md

PHASE 5 - Expansion (After integration):

1. Create additional utility modules:
   - acr-utils.sh (Azure Container Registry operations)
   - terraform-utils.sh (Terraform operations)
   - docker-utils.sh (Docker build operations)
   - logging-utils.sh (Structured logging)

2. Create README.md for scripts/workflows/lib/ with:
   - Function reference
   - Usage examples
   - Dependency requirements
   - Integration guidelines

3. Create test suite for utilities:
   - Unit tests for each function
   - Integration tests for workflows

================================================================================
