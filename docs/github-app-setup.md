# GitHub App Setup for Production Deployments

## Overview

This document guides you through setting up a GitHub App to allow automated production deployments to bypass branch protection rules on the `main` branch.

## Why GitHub App?

The production deployment workflow needs to commit kustomization updates directly to `main`, which is protected by branch rulesets requiring pull requests. A GitHub App provides:

- ✅ Granular, scoped permissions (better than PAT)
- ✅ Proper RBAC integration with GitHub's security model
- ✅ Ability to bypass branch protection rules
- ✅ No token rotation requirements (unlike PATs)
- ✅ Clear audit trail (commits show as app, not a user)

## Step 1: Create the GitHub App

1. **Navigate to**: https://github.com/settings/apps/new

2. **Basic Information**:
   - **GitHub App name**: `YT Summarizer Deploy Bot` (or your preferred unique name)
   - **Description**: `Automated deployment bot for YT Summarizer production deployments`
   - **Homepage URL**: `https://github.com/AshleyHollis/yt-summarizer`

3. **Webhook**:
   - ✅ **Uncheck** "Active" (we don't need webhooks)

4. **Repository Permissions**:
   - **Contents**: `Read and write` ✅ (required to commit files)
   - **Metadata**: `Read-only` (auto-selected)
   - **Pull requests**: `Read and write` (optional, for future PR-based flow)

5. **Account Permissions**: Leave all as default (None)

6. **Where can this GitHub App be installed?**:
   - Select: `Only on this account` ✅

7. Click **Create GitHub App**

## Step 2: Generate Private Key

1. After creating the app, you'll be on the app's settings page
2. Scroll down to **Private keys** section
3. Click **Generate a private key**
4. A `.pem` file will download automatically
5. **Save this file securely** - you'll need it in Step 4

## Step 3: Note the App ID

1. On the app's settings page, find the **App ID** near the top
2. **Copy this number** (e.g., `123456`) - you'll need it in Step 4

## Step 4: Install the App on Your Repository

1. On the app's settings page, click **Install App** in the left sidebar
2. Select your GitHub account
3. On the installation page:
   - Select: `Only select repositories` ✅
   - Choose: `yt-summarizer` ✅
4. Click **Install**
5. **Note the installation ID** from the URL after installation
   - URL format: `https://github.com/settings/installations/INSTALLATION_ID`
   - Example: if URL is `https://github.com/settings/installations/12345678`, the ID is `12345678`

## Step 5: Store Credentials in Repository Secrets

Run these commands from your local repository:

```powershell
# Set the App ID (replace YOUR_APP_ID with the actual number from Step 3)
gh secret set DEPLOY_APP_ID --body "YOUR_APP_ID"

# Set the Private Key (replace path with actual path to your .pem file)
gh secret set DEPLOY_APP_PRIVATE_KEY --body-file "C:\path\to\your-app-name.2026-01-17.private-key.pem"
```

Verify the secrets were created:

```powershell
gh secret list
```

You should see:
- `DEPLOY_APP_ID`
- `DEPLOY_APP_PRIVATE_KEY`

## Step 6: Add GitHub App as Bypass Actor to Ruleset

First, get your app's slug/ID for the bypass configuration:

```powershell
# Get the app details (replace YOUR_APP_ID with the actual number)
gh api apps/YOUR_APP_ID --jq '{id, slug, name}'
```

Then update the ruleset to allow the app to bypass protection:

```powershell
# Get current ruleset configuration
gh api repos/AshleyHollis/yt-summarizer/rulesets/11680417 > ruleset.json

# Edit ruleset.json and add your app to bypass_actors array
# The app entry should look like:
# {
#   "actor_id": YOUR_APP_ID,
#   "actor_type": "Integration",
#   "bypass_mode": "always"
# }

# Update the ruleset
gh api -X PUT repos/AshleyHollis/yt-summarizer/rulesets/11680417 \
  --input ruleset.json
```

**Alternative**: Use the GitHub web interface:
1. Go to: https://github.com/AshleyHollis/yt-summarizer/settings/rules
2. Click on `main-branch-protection` ruleset
3. Scroll to **Bypass list**
4. Click **Add bypass**
5. Select your app from the dropdown
6. Click **Add**

## Step 7: Test the Setup

Trigger a test deployment to verify the app can bypass protection:

```powershell
gh workflow run deploy-prod.yml --ref main `
  -f run_terraform=true `
  -f run_deploy=true `
  -f run_frontend=false `
  -f run_health_check=false
```

Monitor the deployment:

```powershell
# Get the latest run
gh run list --workflow=deploy-prod.yml --limit 1

# Watch it (replace RUN_ID with actual ID)
gh run watch RUN_ID
```

**Expected behavior**:
- ✅ The "Update Production Overlay" job should complete successfully
- ✅ The commit should be pushed to main without errors
- ✅ The commit author should show as your GitHub App

## Verification Checklist

After completing all steps, verify:

- [ ] GitHub App created with correct permissions
- [ ] Private key generated and downloaded
- [ ] App installed on `yt-summarizer` repository
- [ ] `DEPLOY_APP_ID` secret created
- [ ] `DEPLOY_APP_PRIVATE_KEY` secret created
- [ ] App added to ruleset bypass list
- [ ] Test deployment successful
- [ ] Commits show app as author

## Troubleshooting

### Error: "Resource not accessible by integration"

**Cause**: App doesn't have required permissions

**Fix**:
1. Go to app settings
2. Update Repository permissions → Contents → Read and write
3. Accept the permission update on the installation

### Error: "refusing to allow a GitHub App to create or update workflow"

**Cause**: GitHub Apps cannot modify workflow files by default

**Fix**: This is expected - the app should only be updating `k8s/overlays/prod/kustomization.yaml`, not workflow files

### Error: "Bad credentials"

**Cause**: Private key or App ID incorrect

**Fix**:
1. Verify secrets are set correctly: `gh secret list`
2. Regenerate private key if needed
3. Update `DEPLOY_APP_PRIVATE_KEY` secret

### Push still rejected by ruleset

**Cause**: App not added to bypass list

**Fix**: Follow Step 6 again and ensure app is in the bypass actors list

## Files Modified

The following files were updated to support GitHub App authentication:

1. **`.github/workflows/deploy-prod.yml`** (lines 461-477)
   - Added `Generate GitHub App token` step
   - Updated checkout to use app token instead of GITHUB_TOKEN

2. **`.github/actions/get-app-token/action.yml`** (NEW)
   - Reusable action for generating app tokens
   - Can be used in other workflows as needed

## Security Considerations

- ✅ Private key is stored as encrypted secret
- ✅ App has minimal required permissions (Contents: write)
- ✅ App is scoped to single repository
- ✅ Branch protection still enforced for human users
- ✅ Clear audit trail via app identity
- ✅ No token rotation needed (unlike PATs)

## Future Enhancements

Consider these improvements:

1. **PR-based deployments**: Update workflow to create PRs instead of direct commits
2. **Multiple environments**: Create separate apps for staging/prod if needed
3. **Granular permissions**: Further restrict app permissions as workflow evolves

## References

- [GitHub Apps Documentation](https://docs.github.com/en/apps)
- [Creating GitHub Apps](https://docs.github.com/en/apps/creating-github-apps)
- [Repository Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets)
- [actions/create-github-app-token](https://github.com/actions/create-github-app-token)

---

**Last Updated**: 2026-01-17  
**Status**: Ready for implementation  
**Owner**: Ashley Hollis
