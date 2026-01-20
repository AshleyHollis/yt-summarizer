# Systematic Migration Plan

**Baseline**: `fix/swa-working-baseline` (Commit `f1f21a4`)  
**Target**: Full Auth0 integration with working SWA deployment  
**Strategy**: Incremental changes with verification at each step

---

## Migration Philosophy

1. **One change at a time** - Test each change independently
2. **Verify before proceeding** - Each step must have successful deployment
3. **Document everything** - Record what worked and what didn't
4. **Easy rollback** - Git commits allow reverting to last known-good state
5. **Avoid Terraform** - Manual SWA management to avoid recreating instance

---

## Migration Phases

### Phase 1: Environment Variables & Secrets ✅ COMPLETE
**Goal**: Add Auth0 environment variables without code changes  
**Risk**: Low (just configuration)  
**Status**: ✅ Completed on 2026-01-20 20:38 UTC

**Completed Steps**:
1. ✅ Added Auth0 environment variable placeholders to workflow
2. ✅ Tested deployment works with placeholder values
3. ⚠️ Skipped Azure Key Vault fetch (due to OIDC branch constraints)

**Changes Made**:
- Modified `.github/workflows/swa-baseline-deploy.yml`
- Added 5 placeholder Auth0 environment variables
- Added `migration/phase-1-env-vars-v2` to push triggers

**Result**: 
- Deployment successful (Run #21186299177)
- Production URL working: https://white-meadow-0b8e2e000.6.azurestaticapps.net
- ⚠️ Performance degradation: 229s vs 32s baseline (needs investigation)

**Commit**: `4a11f0c` - "migration: phase 1 v2 - add Auth0 placeholder env vars (no Azure login)"  
**Tag**: `migration-phase-1-complete`

**Notes**:
- Phase 1 v1 failed due to Azure OIDC federation not allowing `migration/*` branch pattern
- Phase 1 v2 succeeded by using placeholder values instead of fetching from Key Vault
- Will address real Auth0 secrets in Phase 2

**Rollback**: Not needed (successful deployment)

---

### Phase 2: Backend Infrastructure Integration
**Goal**: Add Auth0 backend infrastructure without frontend changes  
**Risk**: Medium (backend changes only)

**Steps**:
1. Merge backend Terraform state (Auth0 resources in Key Vault)
2. Add API backend URL configuration
3. Update workflow to fetch real Auth0 credentials
4. Configure SWA runtime app settings (AFTER successful deployment)
5. Test that app still deploys without Auth0 frontend code

**Files to Change**:
- `.github/workflows/swa-baseline-deploy.yml` (add Auth0 app settings step)
- `apps/web/next.config.ts` (if API URL config needed)

**Verification**:
- Deployment still succeeds
- SWA app settings configured correctly (check Azure Portal)
- Frontend still works (no Auth0 UI yet, so no login)

**Rollback**: `git revert HEAD` or `git reset --hard {previous-commit}`

---

### Phase 3: API Proxy Route
**Goal**: Add backend API proxy without Auth0 authentication  
**Risk**: Low (existing code from baseline)

**Steps**:
1. Add `apps/web/src/app/api/proxy/[...path]/route.ts`
2. Configure API_BASE_URL or use placeholder
3. Test API proxy works with backend

**Files to Change**:
- `apps/web/src/app/api/proxy/[...path]/route.ts`
- Environment variables in workflow

**Verification**:
- Deployment succeeds
- API proxy routes work (test with curl)
- No Auth0 required yet

**Rollback**: `git revert HEAD`

---

### Phase 4: Auth0 Frontend Dependencies
**Goal**: Add Auth0 packages to package.json  
**Risk**: Low (just dependencies, no code)

**Steps**:
1. Add `@auth0/nextjs-auth0` to package.json
2. Run `npm install` locally to verify
3. Commit package.json and package-lock.json
4. Test deployment with new dependencies

**Files to Change**:
- `apps/web/package.json`
- `apps/web/package-lock.json`

**Verification**:
- Deployment succeeds
- Build completes with new dependencies
- Production URL still works (no Auth0 code yet)

**Rollback**: `git revert HEAD && npm install`

---

### Phase 5: Auth0 API Routes
**Goal**: Add Auth0 callback routes  
**Risk**: Medium (new API routes)

**Steps**:
1. Add `apps/web/src/app/api/auth/[auth0]/route.ts`
2. Configure Auth0 environment variables from Key Vault
3. Test Auth0 login flow works

**Files to Change**:
- `apps/web/src/app/api/auth/[auth0]/route.ts`
- `.github/workflows/swa-baseline-deploy.yml` (update env vars)

**Verification**:
- Deployment succeeds
- Auth0 login redirects work
- Can log in and see session

**Rollback**: `git revert HEAD`

---

### Phase 6: Auth0 Frontend UI Components
**Goal**: Add login/logout UI components  
**Risk**: Low (UI only)

**Steps**:
1. Add Auth0 context provider
2. Add login/logout buttons
3. Add protected routes
4. Test full Auth0 flow

**Files to Change**:
- `apps/web/src/components/auth/*` (Auth0 UI components)
- `apps/web/src/app/layout.tsx` (wrap with Auth0 provider)

**Verification**:
- Deployment succeeds
- Can log in, see protected content, log out
- Session persists across page reloads

**Rollback**: `git revert HEAD`

---

### Phase 7: Preview Workflow Integration
**Goal**: Integrate complex preview workflow with PR deployments  
**Risk**: High (complex orchestration)

**Steps**:
1. Copy preview workflow from PR #69
2. Simplify to remove unnecessary complexity
3. Test with a test PR
4. Add backend health checks and ingress URL fetching

**Files to Change**:
- `.github/workflows/preview.yml`
- Preview cleanup scripts

**Verification**:
- Preview deployments work for PRs
- SWA staging environments created correctly
- Backend URL fetched and injected correctly

**Rollback**: `git revert HEAD` or disable preview workflow

---

### Phase 8: Production Workflow
**Goal**: Update production workflow with Auth0 support  
**Risk**: Medium (production deployments)

**Steps**:
1. Update `deploy-prod.yml` with Auth0 app settings
2. Test production deployment from main branch
3. Verify production Auth0 credentials work

**Files to Change**:
- `.github/workflows/deploy-prod.yml`

**Verification**:
- Production deployment succeeds
- Production Auth0 login works
- No disruption to existing users

**Rollback**: `git revert HEAD` or deploy previous main commit

---

## Migration Checklist Template

For each phase, use this checklist:

```markdown
### Phase X: {Name}

- [ ] Read phase description and understand changes
- [ ] Checkout fix/swa-working-baseline and pull latest
- [ ] Create feature branch: `git checkout -b migration/phase-{X}-{name}`
- [ ] Make file changes as documented
- [ ] Test locally: `cd apps/web && npm run build`
- [ ] Commit changes: `git commit -m "migration: phase {X} - {description}"`
- [ ] Push and trigger deployment: `git push origin migration/phase-{X}-{name}`
- [ ] Monitor deployment: `gh run watch`
- [ ] Verify deployment succeeded (<60s, no errors)
- [ ] Test production URL works
- [ ] Test specific phase functionality
- [ ] Document results in MIGRATION-LOG.md
- [ ] If SUCCESS: Merge to fix/swa-working-baseline
- [ ] If FAILURE: Document error, rollback, analyze
- [ ] Tag successful state: `git tag migration-phase-{X}-complete`
```

---

## Rollback Commands Reference

### Undo Last Commit (Not Pushed)
```bash
git reset --soft HEAD~1  # Keep changes staged
git reset --hard HEAD~1  # Discard changes completely
```

### Revert Pushed Commit
```bash
git revert HEAD          # Creates new commit that undoes changes
git push origin fix/swa-working-baseline
```

### Emergency Rollback to Known-Good State
```bash
# Reset to baseline tag
git checkout fix/swa-working-baseline
git reset --hard baseline-working-swa-v1
git push origin fix/swa-working-baseline --force

# Or reset to specific commit
git reset --hard f1f21a4
git push origin fix/swa-working-baseline --force
```

### Test Deployment After Rollback
```bash
gh run watch --workflow=swa-baseline-deploy.yml
curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
```

---

## Pre-Migration Setup

Before starting Phase 1:

1. **Create git tag for baseline**
   ```bash
   git checkout fix/swa-working-baseline
   git tag -a baseline-working-swa-v1 -m "Working SWA baseline - white-meadow instance"
   git push origin baseline-working-swa-v1
   ```

2. **Create migration log file**
   ```bash
   touch MIGRATION-LOG.md
   git add MIGRATION-LOG.md
   git commit -m "docs: initialize migration log"
   git push origin fix/swa-working-baseline
   ```

3. **Verify baseline still works**
   ```bash
   gh run watch --workflow=swa-baseline-deploy.yml
   curl -I https://white-meadow-0b8e2e000.6.azurestaticapps.net
   ```

4. **Document all branch states**
   ```bash
   # List all branches and their last commits
   git branch -a --format='%(refname:short) - %(committermessage)' > BRANCH-SNAPSHOT.txt
   ```

---

## Success Criteria

Migration is complete when:

- ✅ Auth0 login works on production
- ✅ Auth0 login works on preview environments
- ✅ All deployments succeed in <60 seconds
- ✅ No timeout errors
- ✅ No deployment cancellations
- ✅ Backend API integration works
- ✅ Frontend UI fully functional
- ✅ All tests pass
- ✅ Documentation up to date

---

## Emergency Contacts / Resources

- **SWA Documentation**: https://learn.microsoft.com/azure/static-web-apps/
- **Auth0 Next.js SDK**: https://auth0.com/docs/quickstart/webapp/nextjs
- **Working Baseline Doc**: `WORKING-BASELINE.md`
- **Troubleshooting Doc**: `SWA-DEPLOYMENT-TROUBLESHOOTING.md`
- **GitHub Actions**: https://github.com/AshleyHollis/yt-summarizer/actions

---

## Migration Status

**Current Phase**: Pre-migration setup  
**Last Known Good State**: `baseline-working-swa-v1` (Commit `f1f21a4`)  
**Next Phase**: Phase 1 - Environment Variables & Secrets

**Overall Progress**: 0/8 phases complete

| Phase | Status | Date | Notes |
|-------|--------|------|-------|
| Phase 1: Env Vars | ⏳ Pending | - | - |
| Phase 2: Backend | ⏳ Pending | - | - |
| Phase 3: API Proxy | ⏳ Pending | - | - |
| Phase 4: Auth0 Deps | ⏳ Pending | - | - |
| Phase 5: Auth0 Routes | ⏳ Pending | - | - |
| Phase 6: Auth0 UI | ⏳ Pending | - | - |
| Phase 7: Preview Workflow | ⏳ Pending | - | - |
| Phase 8: Production | ⏳ Pending | - | - |
