# Terraform Plan Refactoring Summary

## Overview
Refactored the "Post Plan to PR" step in `infra.yml` into a reusable composite action that posts to both PR comments and provides a pipeline summary.

## Changes Made

### 1. New Composite Action: `.github/actions/post-terraform-plan/`

**Files Created:**
- `action.yml` - Main composite action definition
- `README.md` - Documentation and usage examples
- `CHANGES.md` - This changelog file

**Features:**
- Posts formatted Terraform plan to PR comments
- Generates step summary in GitHub Actions run page
- Groups resources by action type (create, update, replace, destroy)
- Provides collapsible resource details
- Tracks and updates existing bot comments
- Configurable to skip PR comments for non-PR workflows

**Inputs:**
- `plan-summary` (required): JSON summary with `add`, `change`, `destroy`, `has_changes`
- `formatted-plan` (required): Formatted terraform plan output
- `plan-outcome` (required): Plan outcome - `success` or `failure`
- `skip-pr-comment` (optional, default: `false`): Skip PR comment posting

**Outputs:**
- `comment-id`: ID of created/updated PR comment

### 2. Updated Workflow: `.github/workflows/infra.yml`

**Before:**
- 130+ lines of inline JavaScript in `actions/github-script@v7`
- PR comment only (no pipeline summary)
- Not reusable across workflows

**After:**
- 5 lines using the new composite action
- Automatic PR comment + pipeline summary
- Fully reusable

**Diff:**
```yaml
# Before (126 lines):
- name: Post Plan to PR
  if: github.event_name == 'pull_request'
  uses: actions/github-script@v7
  # ... 120 lines of JavaScript

# After (5 lines):
- name: Post Plan to PR and Summary
  uses: ./.github/actions/post-terraform-plan
  with:
    plan-summary: ${{ steps.plan.outputs.plan_summary }}
    formatted-plan: ${{ steps.plan.outputs.formatted_plan }}
    plan-outcome: ${{ steps.plan.outcome }}
```

### 3. Updated Action: `.github/actions/create-infra-summary/`

**Changes:**
- Enhanced summary with references to plan details
- Added helpful notes about where to find plan results
- More informative for non-PR workflows

## Benefits

### ✅ Reusability
- Can now be used in any workflow that runs Terraform
- Easy to integrate with preview environments or other infrastructure flows
- Consistent formatting across all workflows

### ✅ Maintainability
- Single source of truth for plan formatting logic
- Easier to update and test
- Better separation of concerns

### ✅ Enhanced UX
- Pipeline summary now shows plan details inline
- Better visibility in Actions run page
- PR comments still provide detailed breakdown

### ✅ Testability
- Composite action can be tested independently
- Easier to mock inputs for testing
- Cleaner contract with defined inputs/outputs

## Usage Examples

### Basic Usage (as in infra.yml)
```yaml
- name: Terraform Plan
  id: plan
  uses: ./.github/actions/terraform-plan
  with:
    working-directory: 'infra/terraform/environments/prod'
    subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
    sql-admin-password: ${{ secrets.SQL_ADMIN_PASSWORD }}

- name: Post Plan to PR and Summary
  uses: ./.github/actions/post-terraform-plan
  with:
    plan-summary: ${{ steps.plan.outputs.plan_summary }}
    formatted-plan: ${{ steps.plan.outputs.formatted_plan }}
    plan-outcome: ${{ steps.plan.outcome }}
```

### Non-PR Workflow (skip PR comment)
```yaml
- name: Post Plan Summary Only
  uses: ./.github/actions/post-terraform-plan
  with:
    plan-summary: ${{ steps.plan.outputs.plan_summary }}
    formatted-plan: ${{ steps.plan.outputs.formatted_plan }}
    plan-outcome: ${{ steps.plan.outcome }}
    skip-pr-comment: 'true'  # No PR to comment on
```

## Migration Guide

No migration needed - the existing `infra.yml` workflow has been updated. To use in other workflows:

1. Ensure `terraform-plan` action outputs are available
2. Call `post-terraform-plan` with the three required inputs
3. Set `skip-pr-comment: 'true'` for non-PR workflows

## Future Enhancements

Potential improvements:
- Support for plan drift comparison
- Cost estimation integration
- Security scanning integration
- Comparison with previous plan in PR
- Custom styling options
