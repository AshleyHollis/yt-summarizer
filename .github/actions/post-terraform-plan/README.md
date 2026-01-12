# Post Terraform Plan

A composite GitHub Action that posts formatted Terraform plan output to PR comments and generates a pipeline summary.

## Features

- Posts detailed Terraform plan output to pull request comments
- Generates step summary in GitHub Actions run page
- Groups resources by action type (create, update, replace, destroy)
- Provides resource-level details in collapsible sections
- Tracks and updates existing bot comments instead of creating duplicates

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `plan-summary` | Yes | - | JSON summary of plan changes with keys: `add`, `change`, `destroy`, `has_changes` |
| `formatted-plan` | Yes | - | Formatted terraform plan output |
| `plan-outcome` | Yes | - | Plan outcome: `success` or `failure` |
| `skip-pr-comment` | No | `false` | Skip posting to PR comment (useful for non-PR workflows) |

## Outputs

| Output | Description |
|--------|-------------|
| `comment-id` | ID of the created or updated PR comment (only available when skip-pr-comment is false) |

## Usage Example

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
    skip-pr-comment: 'false'  # Set to 'true' for non-PR workflows
```

## PR Comment Output

The action generates a markdown comment with:

- Status header with emoji indicator
- Summary badges showing resource counts
- Collapsible sections for each action type:
  - ➕ Resources to Create
  - ♻️ Resources to Replace
  - 🔄 Resources to Update
  - 🗑️ Resources to Destroy
- Resource details in HCL code blocks
- Footer with timestamp and run link

## Pipeline Summary

The action adds a step summary to GitHub Actions run page with:

- Plan status (success/failure)
- Resource changes table
- "No changes" message when applicable

## Implementation Notes

- The action parses Terraform plan output to identify individual resources
- Only posts to PR comments when running in a pull request context
- Updates existing bot comments instead of creating duplicates
- Handles large plan outputs by truncating at 60,000 characters if needed
- Uses GitHub token with default permissions (needs `pull-requests: write` for PR comments)
