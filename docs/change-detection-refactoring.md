# Change Detection Refactoring - Improved Design

## Problem with Original Design

The original `detect-changes.ps1` script had **tight coupling** between change detection and pipeline logic:

```powershell
# ❌ Script decides what stages should run
$stages = @{
    test_api = $changes.api -or $changes.shared
    test_workers = $changes.workers -or $changes.shared
    build_images = ($changes.api -or $changes.workers) -and -not $changes.tests_only
}
```

**Issues:**
1. **Brittle**: Adding a new service/component requires updating the script
2. **Tight Coupling**: Pipeline stages are hardcoded in the script
3. **Poor Separation**: Script contains pipeline logic, not just data
4. **Hard to Maintain**: Two places to update (script + workflow)

## New Design: Data Provider Pattern

The script now **only detects changed areas** - it provides data, not decisions:

```powershell
# ✅ Script only outputs changed paths
$areaPatterns = @{
    'services/api'     = @('services/api/**')
    'services/workers' = @('services/workers/**')
    'apps/web'         = @('apps/web/**')
}

# Output: "services/api services/workers apps/web"
```

### Jobs Decide for Themselves

Each job contains its own conditional logic:

```yaml
test-api:
  needs: [detect-changes]
  # ✅ Job owns its logic - knows it needs services/api or services/shared
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
    contains(needs.detect-changes.outputs.changed_areas, 'services/shared')
  steps:
    - run: pytest services/api/tests

build-api:
  needs: [detect-changes]
  # ✅ Job decides when to build based on relevant paths
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
    contains(needs.detect-changes.outputs.changed_areas, 'docker')
```

## Benefits

### 1. **Decoupled**
- Script: "These paths changed"
- Jobs: "I care about these paths, so I'll run"

### 2. **Self-Documenting**
Workflow file shows exactly what triggers each job:

```yaml
test-api:
  # Clear: This job runs when API or shared package changes
  if: contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
      contains(needs.detect-changes.outputs.changed_areas, 'services/shared')
```

### 3. **Easy to Extend**
Adding a new service:

```diff
# 1. Add to script (optional - for categorization)
$areaPatterns = @{
+   'services/notifications' = @('services/notifications/**')
}

# 2. Add job (it just works!)
+test-notifications:
+  needs: [detect-changes]
+  if: contains(needs.detect-changes.outputs.changed_areas, 'services/notifications')
```

### 4. **Low Maintenance**
- Script rarely changes (just path patterns)
- Jobs manage their own conditions
- No synchronization needed

## Migration Example

### Before (Coupled)

**Script:**
```powershell
# Script decides pipeline logic ❌
$stages = @{
    test_api = $changes.api -or $changes.shared
    build_api = $changes.api -and -not $changes.tests_only
}
```

**Workflow:**
```yaml
test-api:
  # Job blindly trusts script's decision ❌
  if: needs.detect-changes.outputs.stage_test_api == 'true'
```

### After (Decoupled)

**Script:**
```powershell
# Script just provides data ✅
$changedAreas = @('services/api', 'services/shared')
# Outputs: "services/api services/shared"
```

**Workflow:**
```yaml
test-api:
  # Job owns its logic ✅
  if: |
    contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
    contains(needs.detect-changes.outputs.changed_areas, 'services/shared')
```

## Implementation

### Script Output

```powershell
# Space-separated string for easy contains() checks
changed_areas="services/api services/workers apps/web k8s"
has_code_changes="true"  # Convenience: excludes docs-only
```

### Job Patterns

**Simple case (one path):**
```yaml
if: contains(needs.detect-changes.outputs.changed_areas, 'services/api')
```

**Multiple paths (OR logic):**
```yaml
if: |
  contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
  contains(needs.detect-changes.outputs.changed_areas, 'services/shared')
```

**Complex logic:**
```yaml
if: |
  (contains(needs.detect-changes.outputs.changed_areas, 'services/api') ||
   contains(needs.detect-changes.outputs.changed_areas, 'services/shared')) &&
  !contains(needs.detect-changes.outputs.changed_areas, 'docs')
```

**Convenience flag (exclude docs):**
```yaml
if: needs.detect-changes.outputs.has_code_changes == 'true'
```

## Adding New Components

### Old Way (Brittle) ❌
1. Add patterns to script
2. Add component flag to script
3. Add stage logic to script
4. Update workflow to use new stage flag
5. **4 changes, 2 files, easy to forget steps**

### New Way (Flexible) ✅
1. Add pattern to script (optional, for categorization)
2. Add job with condition checking the path
3. **2 changes, job is self-contained, hard to mess up**

## Example: Adding a Notification Service

```diff
# detect-changes-v2.ps1
$areaPatterns = @{
    'services/api'     = @('services/api/**')
+   'services/notify'  = @('services/notify/**')  # Optional!
}

# ci.yml
+test-notifications:
+  name: Test Notifications Service
+  needs: [detect-changes]
+  if: contains(needs.detect-changes.outputs.changed_areas, 'services/notify')
+  runs-on: ubuntu-latest
+  steps:
+    - uses: actions/checkout@v4
+    - run: pytest services/notify/tests
```

**That's it!** The script doesn't need to know about the test-notifications job.

## File Structure

```
scripts/ci/
├── detect-changes.ps1      # Old version (deprecated)
└── detect-changes-v2.ps1   # New version (data provider pattern)

.github/workflows/
└── ci.yml                   # Jobs own their conditions
```

## Rollout Plan

1. ✅ Create detect-changes-v2.ps1 with new design
2. ⏳ Update ci.yml to use new script and job conditions
3. ⏳ Test with sample PR
4. ⏳ Replace detect-changes.ps1 with v2
5. ⏳ Update documentation

## Summary

| Aspect | Old Design | New Design |
|--------|-----------|------------|
| **Coupling** | Tight (script knows jobs) | Loose (script just provides data) |
| **Maintenance** | High (2 files to sync) | Low (jobs self-contained) |
| **Extensibility** | Brittle (4+ changes) | Flexible (1-2 changes) |
| **Clarity** | Obscure (logic in script) | Clear (logic in workflow) |
| **Testability** | Hard (mock pipeline stages) | Easy (test data output) |

**Result:** More maintainable, more flexible, more reliable change detection!
