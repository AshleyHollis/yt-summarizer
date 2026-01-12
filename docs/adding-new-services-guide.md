# Adding New Services - Example Guide

## ✅ How Easy Is It Now?

With the new data provider pattern, adding a new service to the pipeline is trivial!

## Example: Adding a Notification Service

### Step 1: Create the service code
```
services/
  notifications/
    __init__.py
    service.py
    tests/
      test_service.py
```

### Step 2: Add job to ci.yml (that's it!)

```yaml
test-notifications:
  name: Test Notifications Service
  runs-on: ubuntu-latest
  needs: [detect-changes]
  # ✅ Job decides when it should run - self-documenting!
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'services/notifications') ||
    contains(needs.detect-changes.outputs.changed_areas, 'services/shared')
  steps:
    - uses: actions/checkout@v4

    - name: Setup Python with uv
      uses: ./.github/actions/setup-python-uv
      with:
        python-version: '3.11'
        service-package: services/notifications

    - name: Run tests
      run: pytest services/notifications/tests -v
```

### Step 3 (Optional): Add to area patterns for categorization

If you want to explicitly categorize it, update `detect-changes.ps1`:

```powershell
$areaPatterns = @{
    'services/api'           = @('services/api/**')
    'services/workers'       = @('services/workers/**')
    'services/notifications' = @('services/notifications/**')  # ← Add this
    'services/shared'        = @('services/shared/**')
    # ... rest
}
```

**But this is optional!** The job will still work because `services/notifications/**` will be detected as a changed path and jobs can check for it directly.

## That's It!

**Old way:** 4+ changes across script and workflow  
**New way:** 1 change (just add the job!)

## More Examples

### Adding E2E Tests for New Feature Area

```yaml
e2e-admin:
  name: E2E Admin Tests
  needs: [detect-changes, deploy-preview]
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'apps/web') &&
    contains(github.event.pull_request.labels.*.name, 'admin-features')
  steps:
    - uses: actions/checkout@v4
    - run: npx playwright test admin/
```

### Adding Infrastructure Job

```yaml
validate-helm:
  name: Validate Helm Charts
  needs: [detect-changes]
  if: contains(needs.detect-changes.outputs.changed_areas, 'k8s')
  steps:
    - uses: actions/checkout@v4
    - run: helm lint k8s/charts/
```

### Adding Build Job for New Service

```yaml
build-notifications:
  name: Build Notifications Image
  needs: [detect-changes, meta, test-notifications]
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'services/notifications') ||
    contains(needs.detect-changes.outputs.changed_areas, 'docker')
  steps:
    - uses: actions/checkout@v4

    - name: Login to ACR
      uses: ./.github/actions/azure-acr-login
      with:
        client-id: ${{ secrets.AZURE_CLIENT_ID }}
        tenant-id: ${{ secrets.AZURE_TENANT_ID }}
        subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
        acr-name: ${{ vars.ACR_NAME }}

    - name: Build and push
      uses: ./.github/actions/docker-build-push
      with:
        context: services/notifications
        image-name: yt-summarizer-notifications
        image-tag: ${{ needs.meta.outputs.image_tag }}
        registry: ${{ vars.ACR_LOGIN_SERVER }}
```

## Key Principles

1. **Jobs know what they need** - Logic is in the workflow, not hidden in scripts
2. **No script changes** - Just add jobs, they check `changed_areas` themselves
3. **Self-documenting** - Reading the job shows exactly what triggers it
4. **Flexible conditions** - Combine multiple areas with OR/AND logic
5. **Easy to test** - Add a label, watch which jobs run

## Testing Your New Job

1. Create a PR with changes to your service
2. Check the detect-changes output in Actions
3. Verify your job runs when expected
4. If not, adjust the `if:` condition in your job

**The script doesn't need to know about your job at all!**
