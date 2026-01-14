# Post-Process Approach Implementation - Summary

## What Changed

The `.github/actions/post-terraform-plan` action now uses a **post-process approach** for consistent indentation.

### Key Benefits

- **Separation of concerns**: Formatters generate canonical output, post-processor handles presentation
- **Easier testing**: Post-processor can be tested independently
- **Better maintainability**: Indentation rules live in one place (`post-process.js`)
- **More reliable**: Edge cases handled centrally

## Files Modified

1. **`src/formatters/array-formatter.js`**
   - Simplified to generate canonical output
   - Removed complex indentation logic
   - Format now: `marker + key + = + value`

2. **`src/change-detection.js`**
   - Simplified to generate canonical output
   - Removed marker-displaying logic
   - Focus on what changed, not how it looks

3. **`src/resource-change-formatter.js`**
   - Added post-processor integration
   - Calls `applyIndentation()` on formatted lines
   - Returns properly indented output

## How It Works

### Before (Fix at Source)
```
Formatter Logic + Formatting → Final Output
```
Formatters had to handle both business logic AND presentation formatting. This created complex code where marker type affected indentation.

### After (Post-Process)
```
Formatter Logic → Canonical Output
                              ↓
                    Post-Processor → Final Indented Output
```
Formatters generate simple canonical output (just markers + content). Post-processor handles all formatting:
- 4-space indentation for attributes
- 6-space indentation for array values
- Proper nesting with 4 spaces per level
- Marker placement at column 0

## Test Results

✓ All 59 tests pass:
- 40 parser tests
- 19 markdown tests
- 10 post-process tests

## Example Output

```diff
# Consistent 4-space indentation (CORRECT)
+ resource "azuread_application" "github_actions" {
    display_name = "github-actions-yt-summarizer"
    owners = (known after apply)
    sign_in_audience = "AzureADMyOrg"
    tags = [
      "Environment:prod",
      "ManagedBy:terraform",
      "Project:yt-summarizer",
      "TestPipelineDate:2026-01-13-v2",
    ]
}
```

## Tracking

See `INDENTATION_FIX_ATTEMPTS.md` for detailed history of all attempts and what was tried.
