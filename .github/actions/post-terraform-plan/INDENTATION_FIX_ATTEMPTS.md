# Indentation Fix Attempts Log

This document tracks all attempts to fix the indentation issue in the post-terraform-plan action.

## Issue Description

The Terraform plan output has inconsistent/incorrect indentation for array values and attributes.

### Example of Incorrect Output:
```diff
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

### Expected Output:
```diff
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

## Root Cause Analysis

The issue is in how markers (+, -, !, !!, '  ') are combined with indentation prefixes:

1. **Current approach (WRONG)**: Marker is **embedded** in the line's indentation
   - Example: `${marker} ${prefix}${key} = ...`
   - Problem: Inconsistent indentation when marker varies

2. **Correct approach**: Marker should be at **column 0**, prefix should be **pure spaces**
   - Example: `${marker} ${prefix}${key} = ...` where prefix is pure spaces
   - Result: Consistent 4-space indentation regardless of marker

## Attempt History

### Attempt 1: Initial Investigation (2026-01-13)
- **Description**: Analyzed the codebase to understand the indentation logic
- **Files Examined**:
  - `.github/actions/post-terraform-plan/src/formatters/array-formatter.js`
  - `.github/actions/post-terraform-plan/src/change-detection.js`
  - `.github/actions/post-terraform-plan/src/resource-change-formatter.js`
- **Findings**:
  - `formatMultilineArray` uses: `contentIndent = ${marker} ${prefix}`
  - This embeds marker into indentation, causing variable spacing
  - Should use: marker + space + pure space indentation
- **Status**: IDENTIFIED ROOT CAUSE
- **Next Action**: Fix the indentation logic

---

## Resolution

### Final Fix (2026-01-13)
- **Files Modified**:
  1. `src/formatters/array-formatter.js` - Fixed `formatMultilineArray` and `formatInlineArray`
  2. `src/change-detection.js` - Fixed `formatSimpleValueChange`, `formatArrayOfObjects`, `formatSimpleArray`, `formatNestedBlock`
- **Root Cause**: The '  ' marker (used for create/destroy actions) was being displayed in the output, causing inconsistent spacing.
- **Solution**:
  - When marker is '  ', don't display the marker, only use the pure-space indentation
  - When marker is +, -, !, etc., display Marker + space + indentation + content
  - For arrays: attributes at 4 spaces, values at 6 spaces (after marker)
  - For blocks/objects: proper nesting with consistent 4-space indentation
- **Changes**:
  - `formatMultilineArray`: Handles '  ' marker by using only prefix (no marker displayed)
  - `formatInlineArray`: Same fix for inline arrays
  - `formatSimpleValueChange`: Fixed to skip displaying '  ' marker
  - `formatArrayOfObjects`: Fixed to skip displaying '  ' marker for blocks
  - `formatSimpleArray`: Fixed to skip displaying '  ' marker
  - `formatNestedBlock`: Fixed to skip displaying '  ' marker for nested blocks
- **Result**: Consistent 4-space indentation for attributes, 6-space for array values

---

## Resolution - POST-PROCESS APPROACH CHOSEN (2026-01-13)

**Analysis**: Two architectural approaches were possible:
1. **Fix at Source** (initial attempt): Format correctly during generation  
2. **Post-Process** (final choice): Generate canonical output → Post-processor fixes indentation

**Decision**: Post-process approach for better reliability and maintainability:
- Separation of concerns: Logic generation vs presentation formatting
- Easier to test: Post-processor can be tested independently
- More maintainable: Indentation rules live in one place (`post-process.js`)
- More reliable: Edge cases only need fixing in one module

**Files Modified**:
1. `src/formatters/array-formatter.js` - Simplified to generate canonical output
2. `src/change-detection.js` - Simplified to generate canonical output
3. `src/resource-change-formatter.js` - Wired in post-processor

**Changes Made**:
- Formatters simplified to generate canonical output (no indentation logic)
- Post-processor now handles all indentation via `applyIndentation()`
- Resource-change-formatter calls post-processor before returning output
- All marker handling logic removed from formatters (moved to post-processor)

**Test Results**: ✓ All 59 tests pass (40 parser tests + 19 markdown tests + 10 post-process tests)

**Result**: Consistent 4-space indentation for attributes, 6-space for array values, with edge cases handled centrally in post-process.js

---

## Lessons Learned

1. **Separate concerns**: Use post-processor for formatting, keep formatters for logic generation
2. **Test independently**: Post-processor can be tested with edge cases in isolation
3. **Track attempts**: Keep a log to avoid repeating failed fixes
4. **Architectural choice**: Post-process pattern more maintainable long-term than complex formatter logic

