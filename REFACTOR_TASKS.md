# CI/CD Pipeline Refactor - Task Breakdown

**Last Updated**: 2024-01-18  
**Status**: In Progress (Phase 1)

## Overview

Comprehensive refactor to extract inline scripts from GitHub Actions workflows and composite actions into dedicated files. Eliminates duplication, improves maintainability, and aligns preview/prod pipelines.

---

## Phase 1: Extract Workflow Inline Scripts

Extract all `run: |` blocks from workflow YAML into dedicated script files.

### 1.1 CI Workflow Inline Scripts
**File**: `.github/workflows/ci.yml`

- [x] **ci.yml - lines 86-93**: Main branch detection script
  - **Target file**: `scripts/workflows/ci-check-main-branch.sh`
  - **Action**: Extract `if [[ "${{ github.ref }}" == ...]]` logic
  - **Status**: ✓ Completed

- [x] **ci.yml - lines 99-110**: Change detection script
  - **Target file**: `scripts/workflows/ci-detect-changes.sh`
  - **Action**: Extract inline bash + PowerShell call
  - **Status**: ✓ Completed

- [x] **ci.yml - lines 852-868**: Execution rationale output
  - **Target file**: `scripts/workflows/ci-write-rationale.sh`
  - **Action**: Extract multiline echo logic
  - **Status**: ✓ Completed

### 1.2 Preview Workflow Inline Scripts
**File**: `.github/workflows/preview.yml`

- [x] **preview.yml - lines 184-195**: Finalize deployment flags
  - **Target file**: `scripts/workflows/preview-finalize-flags.sh`
  - **Action**: Extract conditional flag setting
  - **Status**: ✓ Completed

- [x] **preview.yml - lines 199-209**: Detect infra changes
  - **Target file**: `scripts/workflows/preview-detect-infra.sh`
  - **Action**: Extract git diff check for infra/terraform/
  - **Status**: ✓ Completed

- [ ] **preview.yml - lines 404-465**: Find PR image tag (complex logic)
  - **Target file**: `scripts/workflows/preview-find-pr-image-tag.sh`
  - **Action**: Extract commit walking + tag generation logic
  - **Status**: Pending

- [ ] **preview.yml - lines 527-540**: Post queue status (JavaScript)
  - **Target file**: `scripts/workflows/preview-post-queue-status.js`
  - **Action**: Extract github.rest.issues.createComment script
  - **Status**: Pending

- [ ] **preview.yml - lines 1042-1057**: Write execution rationale
  - **Target file**: `scripts/workflows/preview-write-rationale.sh`
  - **Action**: Extract multiline echo logic
  - **Status**: Pending

### 1.3 Deploy-Prod Workflow Inline Scripts
**File**: `.github/workflows/deploy-prod.yml`

- [ ] **deploy-prod.yml - lines 359-366**: Extract CI image tag
  - **Target file**: `scripts/workflows/prod-extract-ci-image-tag.sh`
  - **Action**: Extract short SHA + tag generation
  - **Status**: Pending

- [ ] **deploy-prod.yml - lines 425-441**: Find last production image
  - **Target file**: `scripts/workflows/prod-find-last-image.sh`
  - **Action**: Extract kustomization grep + validation
  - **Status**: Pending

- [ ] **deploy-prod.yml - lines 493-515**: Determine image tag logic
  - **Target file**: `scripts/workflows/prod-determine-image-tag.sh`
  - **Action**: Extract conditional tag selection (CI vs. last prod)
  - **Status**: Pending

- [ ] **deploy-prod.yml - lines 624-636**: Write execution rationale
  - **Target file**: `scripts/workflows/prod-write-rationale.sh`
  - **Action**: Extract multiline echo logic
  - **Status**: Pending

### 1.4 Other Workflow Inline Scripts
**File**: `.github/workflows/preview-cleanup.yml`, `preview-e2e.yml`, `swa-cleanup-scheduled.yml`, etc.

- [ ] **preview-cleanup.yml**: Extract any inline scripts
  - **Status**: Pending

- [ ] **preview-e2e.yml**: Extract any inline scripts
  - **Status**: Pending

- [ ] **swa-cleanup-scheduled.yml**: Extract any inline scripts
  - **Status**: Pending

---

## Phase 2: Extract Composite Action Inline Scripts

Extract inline `run:` blocks from composite actions into dedicated script files.

### 2.1 High-Priority Composite Actions (Complex Logic)

- [ ] **post-terraform-plan/action.yml**: Extract terraform plan JSON parsing + GitHub API calls
  - **Target file**: `post-terraform-plan/script.sh` or `.js`
  - **Status**: Pending

- [ ] **cleanup-stale-swa-environments/action.yml**: Extract SWA enumeration + deletion logic
  - **Target file**: `cleanup-stale-swa-environments/script.sh`
  - **Status**: Pending

- [ ] **check-preview-concurrency/action.yml**: Extract preview count + concurrency check
  - **Target file**: `check-preview-concurrency/script.sh`
  - **Status**: Pending

- [ ] **verify-deployment-image/action.yml**: Extract kubectl checks
  - **Target file**: `verify-deployment-image/script.sh`
  - **Status**: Pending

- [ ] **build-images/action.yml**: Extract Docker build + push logic
  - **Target file**: `build-images/script.sh`
  - **Status**: Pending

### 2.2 Medium-Priority Composite Actions

- [ ] **detect-pr-code-changes/action.yml**: Extract change detection logic
  - **Target file**: `detect-pr-code-changes/script.sh`
  - **Status**: Pending

- [ ] **get-pr-metadata/action.yml**: Extract PR metadata extraction
  - **Target file**: `get-pr-metadata/script.sh`
  - **Status**: Pending

- [ ] **update-preview-overlay/action.yml**: Extract kustomize updates
  - **Target file**: `update-preview-overlay/script.sh`
  - **Status**: Pending

- [ ] **commit-overlay-changes/action.yml**: Extract git operations
  - **Target file**: `commit-overlay-changes/script.sh`
  - **Status**: Pending

- [ ] **kustomize-validate/action.yml**: Extract kustomize build validation
  - **Target file**: `kustomize-validate/script.sh`
  - **Status**: Pending

### 2.3 Lower-Priority Composite Actions (Simpler Logic)

- [ ] **setup-python/action.yml**: Check if has inline scripts
- [ ] **setup-node/action.yml**: Check if has inline scripts
- [ ] **setup-kustomize/action.yml**: Check if has inline scripts
- [ ] **azure-acr-login/action.yml**: Check if has inline scripts
- [ ] **health-check/action.yml**: Check if has inline scripts
- [ ] **wait-for-ci/action.yml**: Check if has inline scripts
- [ ] **wait-for-argocd-sync/action.yml**: Check if has inline scripts

---

## Phase 3: Consolidate Duplicated Logic

Reduce action count and improve reusability.

### 3.1 Deduplicate Health Checks
- [ ] **Consolidate**: `health-check` and `health-check-preview` into single action with parameters
  - **Target**: `.github/actions/health-check/action.yml`
  - **Changes**:
    - Add optional `namespace` parameter
    - Add optional `external-url` parameter
    - Keep backward compatibility
  - **Status**: Pending

### 3.2 Deduplicate Terraform Steps
- [ ] **Consolidate**: Terraform setup, validate, plan across all workflows
  - **Review**: `preview.yml`, `deploy-prod.yml` terraform jobs
  - **Consider**: Creating `run-terraform` composite action
  - **Status**: Pending

### 3.3 Deduplicate Azure Logins
- [ ] **Track**: All Azure login steps across workflows
  - **Count**: How many use `azure/login@v2` vs. custom action
  - **Goal**: Ensure consistent approach
  - **Status**: Pending

### 3.4 Deduplicate Image Tag Resolution
- [ ] **Consolidate**: Image tag extraction logic between preview and prod
  - **Files**: `preview.yml` (lines 402-465), `deploy-prod.yml` (lines 359-366, 425-441)
  - **Create**: Shared utility script `scripts/workflows/resolve-image-tag.sh`
  - **Status**: Pending

---

## Phase 4: Align Preview & Production Pipelines

Add missing verification stages to production.

### 4.1 Production Verification Stage
- [ ] **MISSING in prod**: Verify deployment stage (exists in preview as `verify-deployment` job)
  - **Add to prod**: New job after `update-overlay`
  - **Steps**:
    - Wait for Argo CD sync (preview does this)
    - Verify API deployment image (preview does this)
    - Verify worker deployments (preview does this)
    - Run health checks (prod has `health-check` but not integrated with verify)
  - **Status**: Pending

### 4.2 Production Concurrency Gate
- [ ] **MISSING in prod**: Concurrency limit check
  - **Note**: Only preview has `check-concurrency` job
  - **Prod consideration**: Do we need this for production? Probably not, but document rationale
  - **Status**: Review Required

### 4.3 Production Consistency
- [ ] **Document**: Why preview and prod differ in certain areas
  - Create: `docs/preview-vs-prod-pipeline-differences.md`
  - Explain: Image tag strategy, concurrency limits, verification stages
  - **Status**: Pending

---

## Phase 5: Repository Structure

Create organized directory structure for scripts.

### 5.1 Create Script Directories
- [ ] Create `scripts/workflows/` directory
  - **Purpose**: Workflow-specific scripts
  - **Naming**: `{workflow}-{purpose}.sh` or `.js`
  - **Example**: `ci-detect-changes.sh`, `preview-find-pr-image-tag.sh`, `prod-extract-ci-image-tag.sh`
  - **Status**: Pending

- [ ] Create `.github/actions/*/script.sh` or `script.ps1` files
  - **Purpose**: One per composite action that has inline code
  - **Pattern**: Use `shell: bash` in action.yml to call script.sh
  - **Example**: `.github/actions/build-images/script.sh`
  - **Status**: Pending

### 5.2 Create Shared Utilities
- [ ] Create `scripts/workflows/lib/` subdirectory
  - **Purpose**: Reusable shell functions
  - **Files**:
    - `lib/git-utils.sh` - git operations (diff, log, rev-parse)
    - `lib/image-utils.sh` - image tag resolution
    - `lib/k8s-utils.sh` - kubectl operations
    - `lib/github-utils.sh` - GitHub API calls
  - **Status**: Pending

---

## Phase 6: Update Workflows & Actions

Update workflow YAML and action.yml files to call extracted scripts.

### 6.1 Update ci.yml
- [ ] Replace inline scripts with `.github/actions/` calls or bash script calls
- [ ] Verify all 3 inline scripts extracted and called correctly
- [ ] **Status**: Pending

### 6.2 Update preview.yml
- [ ] Replace all 5 inline scripts with external calls
- [ ] Verify all finalize-flags, infra-detect, find-tag, queue-status, rationale extracted
- [ ] **Status**: Pending

### 6.3 Update deploy-prod.yml
- [ ] Replace all 4 inline scripts with external calls
- [ ] Verify extract-tag, find-last-image, determine-tag, rationale extracted
- [ ] **Status**: Pending

### 6.4 Update Composite Actions
- [ ] For each action in Phase 2 with inline scripts:
  1. Create script file
  2. Update action.yml to call script
  3. Change `run: |` block to `run: bash/pwsh ${{ github.action_path }}/script.sh`
  4. Preserve all parameters and environment variables
- [ ] **Status**: Pending

---

## Phase 7: Testing & Validation

Ensure refactored pipelines work identically.

### 7.1 Unit Tests for Scripts
- [ ] Test each extracted script independently
  - **Tool**: bash-unit or similar
  - **Coverage**: All code paths (main branch, PR, k8s-only, etc.)
  - **Status**: Pending

### 7.2 Workflow Syntax Validation
- [ ] Run actionlint on all refactored workflows
  - **Command**: `actionlint .github/workflows/*.yml`
  - **Verify**: No new errors introduced
  - **Status**: Pending

### 7.3 Integration Testing
- [ ] Trigger test runs on:
  1. PR with code changes (should follow path 1)
  2. PR with k8s-only changes (should follow path 2)
  3. Push to main (should deploy to prod with verified images)
- [ ] **Status**: Pending

### 7.4 Behavior Verification
- [ ] Confirm all jobs run/skip identically to pre-refactor state
- [ ] Verify output variables are correctly passed between jobs
- [ ] Verify artifact handling unchanged
- [ ] **Status**: Pending

---

## Phase 8: Documentation

Document refactored pipelines.

- [ ] **ci.yml**: Update header comments with new script references
- [ ] **preview.yml**: Update header comments with new script references
- [ ] **deploy-prod.yml**: Update header comments with new script references
- [ ] **REFACTORING.md**: Create guide for future maintainers
  - How to add a new workflow script
  - Where scripts live and naming conventions
  - How to update shared utilities
  - **Status**: Pending

---

## Phase 9: Final Verification & Merge

Run full test suite and verify behavior.

- [ ] Run `./scripts/run-tests.ps1` (all components, with E2E)
  - **Status**: Pending

- [ ] Verify no regressions in CI/CD behavior
  - **Status**: Pending

- [ ] Create commit(s) with clear messages
  - Break into logical groups (e.g., "extract ci.yml scripts", "extract preview.yml scripts", etc.)
  - **Status**: Pending

- [ ] Push to branch and create PR for review
  - **Status**: Pending

---

## Dependencies & Ordering

```
Phase 1 (Extract workflows)
    ↓
Phase 2 (Extract actions)
    ↓
Phase 3 (Consolidate logic)
    ↓
Phase 4 (Align pipelines)
    ↓
Phase 5 (Create structure)
    ↓ (tasks in phases 1-4 depend on this)
Phase 6 (Update references)
    ↓
Phase 7 (Test & validate)
    ↓
Phase 8 (Document)
    ↓
Phase 9 (Merge)
```

---

## Key Principles

1. **Behavior Preserved**: 100% identical logic, just moved to files
2. **No Logic Changes**: Only extraction, no refactoring of logic itself
3. **Backward Compatible**: All outputs, parameters, env vars unchanged
4. **Consistent Naming**: Snake_case for files, clear purpose in names
5. **Error Handling**: Maintain all `set -e`, `continue-on-error`, etc.
6. **Comments**: Preserve inline comments, add file headers with purpose
7. **Git History**: Clear commit messages, one refactor unit per commit

---

## Quick Reference: Inline Script Locations

### CI Workflow (3 scripts)
- Lines 86-93: Main branch check
- Lines 99-110: Change detection
- Lines 852-868: Execution rationale

### Preview Workflow (5 scripts)
- Lines 184-195: Finalize flags
- Lines 199-209: Infra detection
- Lines 404-465: Find PR image tag (COMPLEX)
- Lines 527-540: Queue status (JavaScript)
- Lines 1042-1057: Execution rationale

### Deploy-Prod Workflow (4 scripts)
- Lines 359-366: Extract CI image tag
- Lines 425-441: Find last prod image
- Lines 493-515: Determine image tag
- Lines 624-636: Execution rationale

**Total: 12 workflow inline scripts**

### Composite Actions (20+ scripts)
See Phase 2 detailed list above.

**Total: 12+ workflow scripts + 20+ action scripts = ~32-40 scripts to extract**

---

## Progress Tracking

```
Total Tasks: ~80+
Completed: 0
In Progress: 0
Pending: 80+

Phase 1 (Extract workflows): 0/12 ✗
Phase 2 (Extract actions): 0/20+ ✗
Phase 3 (Consolidate): 0/4 ✗
Phase 4 (Align pipelines): 0/3 ✗
Phase 5 (Create structure): 0/2 ✗
Phase 6 (Update references): 0/6 ✗
Phase 7 (Test & validate): 0/4 ✗
Phase 8 (Document): 0/4 ✗
Phase 9 (Merge): 0/1 ✗
```

---

## Notes

- This file is the single source of truth for refactor progress
- Update status as tasks complete (use ✓ for completed)
- For blocked tasks, add note with reason in section
- Keep PR link here once created: `PR #XXX`

