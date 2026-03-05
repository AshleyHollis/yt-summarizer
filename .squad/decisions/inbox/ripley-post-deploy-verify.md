# Decision: Security Headers Deployment Blocked by CI Failure

**Date**: 2026-03-05
**Author**: Ripley (Backend Dev)
**Status**: Needs Action

## Context

PR #170 (CORS preflight fix + SecurityHeadersMiddleware) merged to main, but the Deploy to Production pipeline is blocked. The CI workflow (`22706152321`) failed, causing the "Wait for CI" gate in the deploy workflow (`22706152345`) to fail with exit code 1.

The currently deployed image (`sha-16e161d`) predates PR #170 and does NOT include the SecurityHeadersMiddleware. CORS preflight is working, but security headers (HSTS, X-Content-Type-Options, X-Frame-Options, CSP, Referrer-Policy) are absent in production.

## Decision

Parker (DevOps) should investigate the CI failure and unblock the deploy pipeline so the security headers reach production.

## Impact

- Production API is missing security headers until deployment completes
- CORS is functional — frontend-to-API communication is not blocked
- No user-facing regression from the current state
