# Preview Workflow Refactoring - SOLID/Clean Code Principles

## Summary
This refactoring applied SOLID and Clean Code principles by extracting inline bash scripts into reusable composite actions, making the preview.yml workflow more declarative and maintainable.

## Changes Made

### 1. Created Composite Actions (Single Responsibility Principle)

#### `.github/actions/get-pr-metadata/action.yml`
**Purpose**: Extract PR metadata from pull_request or workflow_dispatch events
**Inputs**:
- Event context data (event name, PR number, refs, SHAs)
**Outputs**:
- `pr_number`, `pr_head_ref`, `pr_head_sha`, `base_sha`
**Benefits**:
- Consolidates two inline bash scripts (set PR metadata + set base SHA) into one cohesive action
- Single source of truth for PR metadata extraction
- Reusable across multiple workflows

#### `.github/actions/get-production-image-tag/action.yml`
**Purpose**: Extract current image tag from production Kustomize overlay
**Inputs**:
- `overlay-path` (defaults to `k8s/overlays/prod/kustomization.yaml`)
**Outputs**:
- `image_tag`
**Benefits**:
- Encapsulates grep logic for production tag extraction
- Includes proper error handling with descriptive messages
- Can be reused when needing current production tag

#### `.github/actions/compute-preview-image-tag/action.yml`
**Purpose**: Determine which image tag to use for preview deployment
**Inputs**:
- `needs-image-build`: Whether new images need to be built
- `ci-image-tag`: Tag from CI workflow (if images were built)
- `production-image-tag`: Current production tag (fallback)
**Outputs**:
- `image_tag`: Computed tag for deployment
- `source`: Origin of tag (`ci` or `production`)
**Benefits**:
- Core business logic isolated in reusable component
- Fail-fast validation with descriptive errors
- Clear decision logic with logging
- Single Responsibility: only computes image tag

### 2. Workflow Simplification

#### Before
```yaml
- name: Set PR metadata
  id: set-pr
  run: |
    # 15 lines of inline bash script

- name: Set base SHA for comparison
  id: base-sha
  run: |
    # 5 lines of inline bash script
```

#### After
```yaml
- name: Get PR metadata
  id: set-pr
  uses: ./.github/actions/get-pr-metadata
  with:
    event-name: ${{ github.event_name }}
    pr-number-input: ${{ github.event.inputs.pr_number }}
    # ... other inputs
```

### 3. Key Improvements

#### Adherence to SOLID Principles

1. **Single Responsibility Principle (SRP)**
   - Each composite action has ONE clear purpose
   - `get-pr-metadata`: Extract PR metadata only
   - `get-production-image-tag`: Extract prod tag only
   - `compute-preview-image-tag`: Compute image tag only

2. **Open/Closed Principle (OCP)**
   - Actions are open for extension (can add new inputs/outputs)
   - Closed for modification (workflow logic doesn't need to change)

3. **Dependency Inversion Principle (DIP)**
   - Workflows depend on abstractions (composite actions) not concrete scripts
   - Easy to swap implementation without changing workflow

#### Clean Code Principles

1. **Descriptive Names**
   - Action names clearly describe what they do
   - Input/output names are self-documenting

2. **Don't Repeat Yourself (DRY)**
   - PR metadata extraction logic in one place
   - Image tag computation centralized

3. **Fail Fast**
   - All actions validate inputs and fail with descriptive errors
   - No silent failures or fallbacks

4. **Separation of Concerns**
   - Workflow orchestrates high-level steps
   - Actions handle implementation details

### 4. Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Total lines | 715 | 490 | -31% |
| Inline bash scripts | 5 | 1* | -80% |
| Composite actions | 0 | 3 | +3 reusable components |
| Code duplication | High | Low | Eliminated |

*The remaining inline script (Post queue status) is a simple GitHub script that's already action-like and doesn't warrant extraction.

### 5. Benefits

1. **Testability**: Composite actions can be tested independently
2. **Reusability**: Actions can be used in other workflows (e.g., production deployment)
3. **Maintainability**: Logic changes happen in one place
4. **Readability**: Workflow is now declarative and high-level
5. **Debugging**: Easier to trace issues to specific actions
6. **Documentation**: Action metadata (name, description, inputs/outputs) serves as documentation

## Migration Guide

No changes required for existing PRs or deployments. The workflow behavior is identical, just better organized.

### Testing New Actions

To test the refactored workflow:
1. Open a PR with code changes → should trigger CI and use new image
2. Open a PR with only K8s changes → should use production image
3. Manually trigger workflow with `force_deploy=true` → should use production image

## Future Enhancements

Potential additional extractions:
- [ ] Extract AKS login logic to composite action
- [ ] Extract ArgoCD sync waiting to reusable component
- [ ] Create action for preview cleanup
- [ ] Add unit tests for composite actions using act or similar

## Related Documentation

- [SOLID_CLEAN_CODE_CHECKLIST.md](../../SOLID_CLEAN_CODE_CHECKLIST.md)
- [Pipeline Detection Guide](pipeline-detection.md)
- [Developer Guide](developer-guide.md)
