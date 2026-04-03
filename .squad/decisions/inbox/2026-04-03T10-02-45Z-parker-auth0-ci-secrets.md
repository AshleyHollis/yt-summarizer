# Action Required: Auth0 CI Secrets & OpenAI Key Verification

**From:** Parker (DevOps)  
**Date:** 2026-04-03  
**Priority:** Medium

---

## Summary

Two items need your attention before E2E tests can fully succeed in CI.

---

## Item 1: `AUTH0_TEST_EMAIL` / `AUTH0_TEST_PASSWORD` — Fixed in workflow ✅

The `injectAuth0Token()` function in `apps/web/e2e/global-setup.ts` reads
`AUTH0_TEST_EMAIL` and `AUTH0_TEST_PASSWORD` (singular, not the `ADMIN/USER` variants).
These were not being passed to the E2E step — causing the log message:

```
[global-setup] AUTH0_TEST_EMAIL/PASSWORD not set — skipping token injection
```

**Fix applied:** `preview-e2e.yml` now maps the user credentials to those vars:
```yaml
AUTH0_TEST_EMAIL:    ${{ env.AUTH0_USER_TEST_EMAIL }}
AUTH0_TEST_PASSWORD: ${{ env.AUTH0_USER_TEST_PASSWORD }}
```

The values are already in Key Vault (`auth0-user-test-email`, `auth0-user-test-password`)
and are fetched by the existing "Retrieve Auth0 test credentials from Key Vault" step.

**No action needed from you** — the GitHub secrets (`AUTH0_USER_TEST_EMAIL`,
`AUTH0_USER_TEST_PASSWORD`) already exist and are synced.

---

## Item 2: `OPENAI_API_KEY` GitHub Secret — Action Required ⚠️

The "Patch OpenAI key and restart workers in preview namespace" step in `preview.yml`
sources the key from the **GitHub secret** `OPENAI_API_KEY` (set ~2 months ago), NOT
from Key Vault at runtime.

You updated Key Vault with the new key (`GIFSaev7...`), but if the GitHub secret still
holds the stale value (`F0FbNSNv...`), the preview step will patch K8s with the wrong key
and workers will fail.

**Action required:**  
Update the GitHub secret `OPENAI_API_KEY` to match the current Key Vault value:

```bash
# Get current Key Vault value
az keyvault secret show \
  --vault-name kv-ytsumm-prd-ci \
  --name openai-api-key \
  --query value -o tsv

# Update GitHub secret (replace <VALUE> with the output above)
gh secret set OPENAI_API_KEY --repo AshleyHollis/yt-summarizer --body "<VALUE>"
```

---

## Item 3: Note on ROPC vs browser-auth

The `injectAuth0Token()` function (ROPC) is a **fallback** only — it skips writing
`user.json` if `auth.setup.ts` already created it. Since browser-based auth IS working
in CI (`✓ normal user authenticated successfully`), the 652 tests Kane is enabling will
use `storageState` from auth.setup and are NOT blocked by the ROPC gap.

The ROPC fix (Item 1) is a belt-and-suspenders improvement for edge cases where
auth.setup fails and ROPC is the only fallback available.
