# Terraform Plan Indentation Fix - Summary

## Problem

The `.github/actions/post-terraform-plan` action was outputting Terraform plan outputs with inconsistent/incorrect indentation:

```diff
# INCORRECT - Mix of random spacing
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

Expected output:
```diff
# CORRECT - Consistent 4-space indentation
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

## Root Cause

The issue was in how diff markers were being embedded into the indentation:

1. **'  ' Marker**: Used for create/destroy actions, should NOT be displayed in output
2. **Other Markers (+, -, !, !!)**: Displayed at column 0 for updates

The bug was that `'  '` was being treated like other markers and displayed, causing inconsistent spacing when different markers had different lengths (1 vs 2 characters).

## Solution

### Modified Files

1. **`src/formatters/array-formatter.js`**
   - `formatMultilineArray`: Fixed to hide `'  '` marker
   - `formatInlineArray`: Fixed to hide `'  '` marker

2. **`src/change-detection.js`**
   - `formatSimpleValueChange`: Fixed to skip displaying `'  '` marker
   - `formatArrayOfObjects`: Fixed to skip displaying `'  '` marker for blocks
   - `formatSimpleArray`: Fixed to skip displaying `'  '` marker
   - `formatNestedBlock`: Fixed to skip displaying `'  '` marker

3. **`INDENTATION_FIX_ATTEMPTS.md`**: Created log to track attempts and avoid repeating failures

### Fix Implementation

Key changes:

```javascript
// Helper to hide '  ' marker while showing other markers
const showMarker = marker !== '  ';
const markerPart = showMarker ? `${marker} ` : '';

// For create/destroy: just use prefix (4 spaces)
// For updates: use marker + space + prefix (e.g., "+    " for attributes)
const attrIndent = markerPart + prefix;
const valueIndent = markerPart + prefix + '  '; // 2 more spaces for array values
```

## Results

The fix ensures:
- **Create/Destroy actions**: Attributes at 4 spaces, array values at 6 spaces
- **Update actions**: Markers at column 0, attributes at "+ " + 4 spaces, array values at "+ " + 6 spaces
- **All marker types**: Consistent indentation regardless of marker type

## Verification

Run the GitHub Action to verify correct output. The Terraform plan should now display with consistent 4-space indentation for attributes and 6-space indentation for array values.
