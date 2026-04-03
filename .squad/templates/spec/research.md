# Research: {feature-name}

## Executive Summary
<!-- 2-3 sentence overview of findings -->

## External Research

### Best Practices
<!-- Finding with source URL -->

### Prior Art
<!-- Similar solutions found -->

### Pitfalls to Avoid
<!-- Common mistakes from community -->

## Codebase Analysis

### Existing Patterns
<!-- Pattern found in codebase with file path -->

### Dependencies
<!-- Existing deps that can be leveraged -->

### Constraints
<!-- Technical limitations discovered -->

## Quality Commands

| Type | Command | Source |
|------|---------|--------|
| Lint | `{actual command}` | {where found} |
| TypeCheck | `{actual command}` | {where found} |
| Test | `{actual command}` | {where found} |
| Build | `{actual command}` | {where found} |

**Local CI**: `{lint} && {typecheck} && {test} && {build}`

<!-- Discover these from package.json scripts, Makefile, CI configs -->
<!-- NEVER assume commands — always verify they exist -->

## Verification Tooling

| Tool | Command/Value | Detected From |
|------|--------------|---------------|
| Dev Server | `{command}` | {source} |
| Port | `{number}` | {source} |
| Health Endpoint | `{path}` | {source} |
| Browser Automation | `{tool}` | {source} |

**Project Type**: Web App / API / CLI / Library
**Verification Strategy**: {how VE tasks should verify this feature works}

## Related Specs

| Spec | Relationship | May Need Update |
|------|-------------|----------------|
| {spec-name} | {High/Medium/Low — why} | {yes/no} |

## Feasibility Assessment

| Aspect | Assessment | Notes |
|--------|-----------|-------|
| Technical Viability | High/Medium/Low | {why} |
| Effort Estimate | S/M/L/XL | {basis} |
| Risk Level | High/Medium/Low | {key risks} |

## Recommendations for Requirements
1. {Specific recommendation based on research}
2. {Another recommendation}

## Open Questions
- {Questions that need clarification}

## Sources
- {URL or file path}
