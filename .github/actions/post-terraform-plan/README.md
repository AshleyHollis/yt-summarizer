# Post Terraform Plan

A GitHub Action that posts beautifully formatted Terraform plan output to PR comments and generates pipeline summaries with Terraform Cloud-like styling.

![Terraform Plan Preview](screenshots/terraform-plan-v2.jpeg)

## Features

- 🎨 **Terraform Cloud-inspired styling** with purple gradient header and professional UI
- 🟢🟡🔴🟣 **Color-coded change indicators** for create, update, destroy, and replace actions
- 📊 **Summary stats** showing resource counts at a glance
- 📁 **Collapsible sections** for each change type
- 🔍 **Expandable resource details** with syntax-highlighted HCL code
- 📱 **Responsive design** that works on mobile
- 🔄 **Comment update** - Updates existing comments instead of creating duplicates
- ✨ **No changes message** - Clear feedback when infrastructure matches configuration

## Screenshots

| Full Page | No Changes |
|-----------|------------|
| ![Full Page](screenshots/terraform-plan-replace-section.jpeg) | ![No Changes](screenshots/terraform-plan-no-changes.jpeg) |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `plan-summary` | Yes | - | JSON summary of plan changes with keys: `add`, `change`, `destroy`, `has_changes` |
| `formatted-plan` | Yes | - | Terraform plan output in JSON format |
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

## Local Development

### Prerequisites

- Node.js 18+ installed
- Python 3.x (for HTTP server)

### Setup

```bash
cd .github/actions/post-terraform-plan
npm install
```

### Run Unit Tests

```bash
# Run all unit tests
npm test

# Run parser tests only
npm run test:parser

# Run markdown generator tests only
npm run test:markdown
```

### Generate Preview

Generate an HTML preview to visualize the Terraform plan output:

```bash
# Generate preview from realistic fixture
npm run preview

# Generate all previews
npm run preview:all

# Generate and open in browser (Windows)
npm run open-preview
```

### View Preview Locally

Start a local HTTP server:

```bash
cd preview
python -m http.server 8080
```

Then open http://localhost:8080/realistic-preview.html in your browser.

### Run Playwright UI Tests

```bash
# Install Playwright browsers
npx playwright install

# Run UI tests
npm run test:ui

# Run all tests (unit + UI)
npm run test:all
```

### Test Fixtures

The following test fixtures are available in `test-fixtures/`:

| Fixture | Description |
|---------|-------------|
| `realistic-plan.json` | A realistic plan with creates, updates, destroys, and replaces |
| `no-changes-plan.json` | A plan with no changes |
| `create-only-plan.json` | A plan with only create actions |

### Creating Custom Fixtures

To test with your own Terraform plan:

1. Run `terraform plan -out=plan.tfplan` in your Terraform directory
2. Convert to JSON: `terraform show -json plan.tfplan > plan.json`
3. Copy `plan.json` to `test-fixtures/`
4. Generate preview: `node src/generate-preview.js test-fixtures/plan.json`

## Project Structure

```
.github/actions/post-terraform-plan/
├── action.yml              # GitHub Action definition
├── package.json            # npm scripts and dependencies
├── playwright.config.js    # Playwright configuration
├── README.md              # This file
├── src/
│   ├── index.js           # Main entry point
│   ├── terraform-plan-parser.js    # JSON plan parsing
│   ├── markdown-generator.js       # GitHub markdown output
│   ├── html-generator.js           # HTML preview generation
│   ├── generate-preview.js         # CLI preview generator
│   └── action-main.js              # GitHub Action entry point
├── tests/
│   ├── parser.test.js     # Parser unit tests
│   ├── markdown.test.js   # Markdown generator tests
│   └── ui.spec.js         # Playwright UI tests
├── test-fixtures/
│   ├── realistic-plan.json
│   ├── no-changes-plan.json
│   └── create-only-plan.json
├── preview/               # Generated HTML previews
└── screenshots/           # UI screenshots
```

## Color Scheme

The action uses a Terraform Cloud-inspired color palette:

| Color | Usage | Hex |
|-------|-------|-----|
| Purple | Header, branding | `#5c4ee5` |
| Green | Create/add | `#2eb039` |
| Yellow | Update/change | `#d4a017` |
| Red | Destroy | `#c62b2b` |
| Purple (light) | Replace | `#5c4ee5` |

## Implementation Notes

- The action parses Terraform JSON plan output to identify individual resources
- Only posts to PR comments when running in a pull request context
- Updates existing bot comments instead of creating duplicates (uses HTML comment marker)
- Handles large plan outputs by truncating at 60,000 characters if needed
- Uses GitHub token with default permissions (needs `pull-requests: write` for PR comments)
