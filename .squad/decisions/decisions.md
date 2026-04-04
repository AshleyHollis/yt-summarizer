# Decisions

## Decisions Index

| Date | Author | Topic | Status |
|------|--------|-------|--------|
| 2026-04-04 | Parker | E2E Job AKS Mutation Fix | Proposed |
| 2026-04-04 | Parker | Preview Azure OpenAI ESO State Leak | Completed |
| 2026-04-04 | Kane | E2E Triage — PR #186 | Completed |
| 2026-04-04 | spec-f* | Feature Spec Imports | Completed |
| 2026-04-03 | Kane, others | E2E & Preview Testing | Documented |

*See archive/ for older decisions.*

---

# Parker — E2E Job AKS Mutation Fix (2026-04-04)

**Status**: Proposed — awaiting Ashley review  
**Files affected**: .github/workflows/preview.yml, .github/workflows/terraform-deploy.yml

## Root-Cause Analysis

Two steps violate the GitOps contract in the E2E job (Phase 9):
1. Pauses the ESO reconciler on openai-credentials
2. Directly patches K8s Secret Azure OpenAI fields

**True root cause**: Terraform does NOT pass TF_VAR_azure_openai_* env vars, so Key Vault is overwritten with empty strings. The workaround compensates by patching the K8s Secret directly before tests run.

## Correct GitOps-Aligned Fix

### Part 1: Fix Terraform
- Add four secrets to 	erraform-deploy.yml on.workflow_call.secrets block
- Pass as TF_VAR_azure_openai_* env vars to terraform jobs

### Part 2: Remove AKS mutation steps
- Remove **lines 597–684** from .github/workflows/preview.yml entirely

---

# Parker Finding: Preview Azure OpenAI ESO State Leak (2026-04-04)

**Date**: 2026-04-04
**Reported by**: Parker (DevOps)
**Affects**: Preview CI and existing preview namespaces

## Summary

The old AKS mutation workaround in preview.yml had a critical state leak: it paused the ESO reconciler on openai-credentials and **never unpaused it**. Any preview namespace created while that code was active now has its ESO reconciler permanently paused.

Even though Terraform now correctly writes Azure OpenAI credentials to Key Vault (fix in commit 8766386b), ESO won't sync those values to the K8s secret in paused namespaces.

## Fix Applied

Added "Unpause openai-credentials ESO" step in sync-argocd-manifests job (commit 7ee3255b):
- Checks if ExternalSecret exists in preview namespace (skip if fresh)
- Removes econcile.external-secrets.io/paused annotation
- Annotates with orce-sync=<timestamp> to trigger immediate reconciliation

---

# Kane E2E Triage — PR #186 (2026-04-04)

**Date**: 2026-04-04  
**Branch**: test/e2e-env-verification  
**Run**: 23973764059  
**E2E Job ID**: 69927853225  
**Result**: ❌ 10 failures

## Summary

10 tests failed across 3 spec files. All failures are infrastructure/environment issues — no test code bugs found. The Terraform job was **SKIPPED** (no infra changes detected), meaning TF_VAR_azure_openai_* env vars were never applied to Key Vault. This is the primary blocker.

### Failure Group 1: chat-responses.spec.ts — 8 tests
**Error**: Expected at least 2 assistant messages, found 1
**Root Cause**: **Terraform was SKIPPED.** Key Vault was never updated, and the preview pod has wrong/missing LLM credentials.
**Fix**: Parker to force Terraform or decouple secrets update.

### Failure Group 2: auth-signout.spec.ts — 1 test
**Error**: 
et::ERR_ABORTED at sign-in page
**Root Cause**: TEST CODE issue — test navigates to /sign-in which may not exist as static page.
**Fix**: Kane to investigate actual sign-in URL.

### Failure Group 3: channel-ingest.spec.ts — 2 tests
**Error**: YouTube Channel URL input not visible (fails in beforeEach)
**Root Cause**: **KNOWN CORS MISMATCH** — hardcoded SWA URL fallback doesn't match actual preview SWA.
**Fix**: Parker to fix generate_preview_kustomization.sh.

---

# E2E Coverage Audit — Kane (2026-04-03)

## Context
Branch: 	est/e2e-env-verification
Purpose: Verify preview AND production environments are functional.

## Root Cause: Cross-Domain Cookie Issue

**Persistent blocker** — Auth cookies are set on the API domain, SWA frontend loads from different domain. Browser does not send auth cookies cross-domain → frontend sees unauthenticated → redirects to Auth0.

This causes 	est.fixme(!!process.env.CI, 'Cross-domain cookie issue...') on **~80% of all tests**.

## Critical Gaps

- **Relationship graph**: Zero coverage — no test asserts videos are related
- **Copilot / LLM**: Zero CI coverage — all tests have fixme(CI)
- **Transcription + Summarization**: Zero CI coverage — require LIVE_PROCESSING or fixme(CI)
- **Library page**: Zero CI coverage — fixme(CI) due to CopilotKit redirect
- **RBAC**: Zero CI coverage — all fixme(CI) due to cross-domain cookies
- **Channel ingest**: Zero CI coverage — entire spec fixme(CI)

## Tests ACTIVE in CI

| Test File | What Runs |
|---|---|
| smoke.spec.ts | Navigation smoke tests (landing page, CTAs, feature cards, page titles) |
| health-indicator.spec.ts | Health banner visibility, ARIA attributes, message content |
| uth.setup.ts | Authenticates admin+user via Auth0 using Key Vault creds |
| xplain.spec.ts | Runs but assertions are soft (LLM-dependent) |
