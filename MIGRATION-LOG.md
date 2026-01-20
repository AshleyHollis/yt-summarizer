# Migration Log

**Purpose**: Track all migration attempts, successes, and failures  
**Baseline**: Commit `f1f21a4` on branch `fix/swa-working-baseline`

---

## Log Format

Each entry should include:
- **Date/Time**: When the migration attempt occurred
- **Phase**: Which migration phase (1-8)
- **Changes**: What files were changed
- **Commit**: Git commit SHA
- **Deployment**: GitHub Actions run ID
- **Result**: Success/Failure with details
- **Rollback**: Whether rollback was needed

---

## Migration Entries

### Entry 1: Baseline Establishment
**Date**: 2026-01-21 06:20 UTC  
**Phase**: Pre-migration  
**Changes**: 
- Created fresh SWA instance `white-meadow-0b8e2e000.6.azurestaticapps.net`
- Updated `SWA_DEPLOYMENT_TOKEN` in GitHub Secrets
- Created branch `fix/swa-working-baseline` from commit `f1f21a4`

**Commit**: `cb962dd` - "chore: add fix/swa-working-baseline to baseline workflow triggers"  
**Deployment**: Run #21185824990  
**Duration**: 32 seconds  
**Result**: ✅ **SUCCESS**

**Details**:
- Deployment succeeded to production environment
- Production URL: https://white-meadow-0b8e2e000.6.azurestaticapps.net
- Preview URL: https://white-meadow-0b8e2e000-fixswaworkingbas.eastasia.6.azurestaticapps.net
- SWA deployment logs show "Status: Succeeded. Time: 32.2839363(s)"
- No errors, no timeouts, no cancellations

**Verification**:
```bash
curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
# HTTP/1.1 200 OK
```

**Notes**:
- This is our baseline that ALL future migrations must maintain
- If any migration breaks this, we rollback immediately
- Key success factor: Fresh SWA instance with no previous corruption

**Rollback**: N/A (this is the baseline)

---

### Entry 2: Phase 1 v2 - Add Auth0 Placeholder Environment Variables
**Date**: 2026-01-20 20:38 UTC  
**Phase**: 1  
**Changes**: 
- Modified `.github/workflows/swa-baseline-deploy.yml`
  - Added placeholder Auth0 environment variables to build step
  - Added `migration/phase-1-env-vars-v2` to push triggers
- No Azure login step (avoided OIDC federation issue from v1)

**Commit**: `4a11f0c` - "migration: phase 1 v2 - add Auth0 placeholder env vars (no Azure login)"  
**Deployment**: Run #21186299177  
**Duration**: 3m49s (229 seconds)  
**Result**: ✅ **SUCCESS**

**Details**:
- Added 5 placeholder Auth0 environment variables to Next.js build
- Variables are build-time placeholders, not functional Auth0 integration yet
- Deployment succeeded but took significantly longer than baseline (229s vs 32s)
- Production URL still responds with 200 OK
- No errors, no timeouts, no cancellations

**Environment Variables Added**:
```yaml
AUTH0_SECRET: "placeholder-session-secret-min-32-chars-long-for-auth0"
AUTH0_BASE_URL: "https://white-meadow-0b8e2e000.6.azurestaticapps.net"
AUTH0_ISSUER_BASE_URL: "https://placeholder.auth0.com"
AUTH0_CLIENT_ID: "placeholder-client-id"
AUTH0_CLIENT_SECRET: "placeholder-client-secret"
```

**Verification**:
```bash
curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
# HTTP/1.1 200 OK
# Content-Type: text/html
# Date: Tue, 20 Jan 2026 20:38:26 GMT
```

**Notes**:
- **Performance degradation observed**: Deployment took 7x longer than baseline (229s vs 32s)
- This increase is concerning and may indicate:
  - Env vars causing longer build times
  - SWA processing overhead with more environment variables
  - Need to monitor if this persists in Phase 2
- First attempt (v1) failed due to Azure OIDC federation constraints (branch name not allowed)
- v2 approach succeeded by avoiding Azure login altogether
- Auth0 integration is NOT functional yet - these are placeholders for build validation only

**Rollback**: Not needed - deployment successful

---

## Template for Future Entries

```markdown
### Entry {N}: Phase {X} - {Name}
**Date**: YYYY-MM-DD HH:MM UTC  
**Phase**: {1-8}  
**Changes**: 
- File 1 changed
- File 2 added
- Environment variable X updated

**Commit**: `{sha}` - "{commit message}"  
**Deployment**: Run #{run_id}  
**Duration**: {X} seconds  
**Result**: ✅ SUCCESS / ❌ FAILURE

**Details**:
- What was tested
- What worked
- Any warnings or issues observed

**Verification**:
```bash
# Commands run to verify
curl -I https://...
# Output
```

**Notes**:
- Important observations
- Edge cases discovered
- Future considerations

**Rollback**: 
- If rollback was needed, document the commands used
- Document the state after rollback
```

---

## Quick Reference: Successful States

| Tag | Commit | Description | SWA Instance |
|-----|--------|-------------|--------------|
| baseline-working-swa-v1 | f1f21a4 | Initial working baseline | white-meadow-0b8e2e000 |
| migration-phase-1-complete | 4a11f0c | Phase 1: Auth0 placeholder env vars | white-meadow-0b8e2e000 |

---

## Known Issues Log

### Issue 1: SWA Instance Corruption
**Discovered**: 2026-01-21  
**Symptoms**: Deployments canceled after 15 seconds with "Deployment Canceled"  
**Affected Instances**: `proud-smoke-05b9a9c00`  
**Root Cause**: Unknown - Azure SWA platform rejecting deployments  
**Solution**: Delete and recreate SWA instance  
**Prevention**: Avoid deleting/recreating SWA unless absolutely necessary

### Issue 2: Old SWA Tokens After Recreation
**Discovered**: 2026-01-21  
**Symptoms**: Deployment failures with 401/403 errors  
**Root Cause**: GitHub secret still has old SWA deployment token  
**Solution**: Regenerate token and update GitHub secret immediately after creating new instance  
**Prevention**: Always update `SWA_DEPLOYMENT_TOKEN` secret after creating new SWA instance

### Issue 3: Azure OIDC Federation Branch Name Constraints
**Discovered**: 2026-01-20  
**Symptoms**: `AADSTS700213: No matching federated identity record found` during Azure login  
**Affected Branches**: `migration/phase-1-env-vars`  
**Root Cause**: Azure OIDC federated identity credentials only allow specific branch patterns  
**Solution**: Avoid Azure login in workflows for feature branches; use placeholder values or allow branch patterns in Azure federation config  
**Prevention**: Either configure Azure federation to allow `migration/*` pattern, or avoid Azure login steps in non-main/preview branches

---

## Statistics

**Total Migration Attempts**: 3 (1 baseline + 1 failed + 1 successful)  
**Successful Migrations**: 2  
**Failed Migrations**: 1 (Phase 1 v1 - OIDC issue)  
**Rollbacks Performed**: 0  
**Current Uptime**: 100%

**Average Deployment Time**: 130.5 seconds  
**Fastest Deployment**: 32 seconds (Run #21185824990 - Baseline)  
**Slowest Deployment**: 229 seconds (Run #21186299177 - Phase 1 v2)

---

## Next Steps

1. ✅ ~~Create git tag for baseline: `baseline-working-swa-v1`~~
2. ✅ ~~Begin Phase 1: Environment Variables & Secrets~~
3. ✅ ~~Document Phase 1 results in this log~~
4. ✅ ~~Update statistics after each migration~~
5. **TODO**: Investigate Phase 1 v2 performance degradation (229s vs 32s baseline)
6. **TODO**: Merge `migration/phase-1-env-vars-v2` to `fix/swa-working-baseline`
7. **TODO**: Create git tag: `migration-phase-1-complete`
8. **TODO**: Begin Phase 2: Fetch real Auth0 secrets from Key Vault
