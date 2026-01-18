#!/bin/bash

################################################################################
# Action: wait-for-argocd-sync / script.sh
#
# Purpose: Wait for Argo CD to sync and create the preview namespace.
#          Includes comprehensive diagnostics for common deployment issues.
#
# Inputs (Environment Variables):
#   NAMESPACE           - Kubernetes namespace to wait for (e.g., "preview-pr-123")
#   PR_NUMBER           - Pull request number for diagnostics
#   TIMEOUT_SECONDS     - Maximum time to wait in seconds (default: 180)
#   INTERVAL            - Check interval in seconds (default: 5)
#
# Process:
#   1. Check Argo CD Application status upfront for early diagnostics
#   2. Wait for namespace creation and Argo CD sync
#   3. Every 30 seconds, check for common deployment issues:
#      - ExternalSecret failures (Key Vault access)
#      - ImagePullBackOff errors (ACR access)
#      - CreateContainerConfigError (missing secrets)
#      - CrashLoopBackOff (application errors)
#   4. Monitor sync hooks (e.g., database migrations)
#   5. On timeout, provide comprehensive diagnostics
#
# Critical Checks:
#   - Verify Argo CD targets branch (not commit SHA)
#   - Detect stale synced versions
#   - Fail fast on image pull or config errors
#   - Provide remediation suggestions
#
################################################################################

set -euo pipefail

APP_NAME="${APP_NAME:-}"
NAMESPACE="${NAMESPACE:-}"
PR_NUMBER="${PR_NUMBER:-}"
TIMEOUT="${TIMEOUT_SECONDS:-180}"
INTERVAL="${INTERVAL:-5}"
MAX_ATTEMPTS=$((TIMEOUT / INTERVAL))

if [[ -z "$APP_NAME" ]] || [[ -z "$NAMESPACE" ]] || [[ -z "$PR_NUMBER" ]]; then
  echo "::error::APP_NAME, NAMESPACE, and PR_NUMBER are required"
  exit 1
fi

# Determine environment type based on app name
if [[ "$APP_NAME" == "preview-pr-"* ]]; then
  ENV_TYPE="preview"
elif [[ "$APP_NAME" == *"-prod"* ]]; then
  ENV_TYPE="production"
else
  ENV_TYPE="unknown"
fi

echo "🔄 Waiting for Argo CD to sync ${ENV_TYPE} environment..."
echo "  Namespace: ${NAMESPACE}"
echo "  Application: ${APP_NAME}"
echo "  Timeout: ${TIMEOUT}s (${MAX_ATTEMPTS} attempts)"

# Check Argo CD Application status FIRST (proactive diagnostics)
echo ""
echo "::group::📋 Argo CD Application Status"
if kubectl get applications.argoproj.io ${APP_NAME} -n argocd &>/dev/null; then
  echo "✅ Application ${APP_NAME} exists in Argo CD"

  # Get sync status
  SYNC_STATUS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
  HEALTH_STATUS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")
  TARGET_REVISION=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "Unknown")
  SYNCED_REVISION=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.revision}' 2>/dev/null || echo "Unknown")

  echo "  Sync Status: ${SYNC_STATUS}"
  echo "  Health Status: ${HEALTH_STATUS}"
  echo "  Target Revision: ${TARGET_REVISION}"
  echo "  Synced Revision: ${SYNCED_REVISION}"

  # CRITICAL CHECK: Verify Argo CD is tracking branch, not commit SHA
  if [[ "${TARGET_REVISION}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::❌ Application is tracking commit SHA instead of branch!"
    echo "  This means Argo CD won't detect overlay updates pushed to the PR branch."
    echo "  Expected: branch name (e.g., 'fix/my-feature')"
    echo "  Actual: commit SHA '${TARGET_REVISION}'"
    echo "  Fix: Update ApplicationSet to use '{{branch}}' instead of '{{head_sha}}'"
    exit 1
  fi

  # Show sync errors if any
  SYNC_ERRORS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.conditions[?(@.type=="SyncError")].message}' 2>/dev/null || echo "")
  if [ -n "$SYNC_ERRORS" ]; then
    echo "::warning::Argo CD Sync Errors detected:"
    echo "${SYNC_ERRORS}"
  fi

  # Show operation state
  OPERATION_STATE=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "")
  if [ -n "$OPERATION_STATE" ]; then
    echo "  Operation Phase: ${OPERATION_STATE}"
  fi
else
  echo "::warning::Application ${APP_NAME} not found in Argo CD"
  echo "This may indicate an issue with the ApplicationSet or Application creation"
fi
echo "::endgroup::"

# Wait for namespace creation AND verify Argo CD syncs to latest commit
echo ""
echo "⏳ Waiting for namespace creation and Argo CD sync..."
NAMESPACE_CREATED=false
ARGOCD_SYNCED=false
SYNC_LOOP_DETECTED=0
LAST_OPERATION_PHASE=""
SYNC_FLIP_COUNT=0

for i in $(seq 1 $MAX_ATTEMPTS); do
  # Step 1: Check if namespace exists
  if ! $NAMESPACE_CREATED && kubectl get namespace ${NAMESPACE} 2>/dev/null; then
    echo "✅ Namespace ${NAMESPACE} exists"

    # Verify namespace has Argo CD labels
    MANAGED_BY=$(kubectl get namespace ${NAMESPACE} -o jsonpath='{.metadata.labels.argocd\.argoproj\.io/instance}' 2>/dev/null || echo "")
    if [ -n "$MANAGED_BY" ]; then
      echo "  ✅ Managed by Argo CD application: ${MANAGED_BY}"
    else
      echo "  ::warning::Namespace exists but not labeled as managed by Argo CD"
    fi

    NAMESPACE_CREATED=true
  fi

  # Step 2: Once namespace exists, verify Argo CD has synced the latest commit
  if $NAMESPACE_CREATED && ! $ARGOCD_SYNCED; then
    CURRENT_SYNC_STATUS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
    CURRENT_SYNCED_REV=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.revision}' 2>/dev/null || echo "")
    CURRENT_TARGET_REV=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "")
    CURRENT_OPERATION_PHASE=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "")
    
    # CRITICAL: Detect sync loop (Synced -> OutOfSync -> Synced -> OutOfSync repeatedly)
    # This indicates a configuration issue where resources keep being modified after sync
    if [ "$CURRENT_OPERATION_PHASE" = "Succeeded" ] && [ "$CURRENT_SYNC_STATUS" = "OutOfSync" ]; then
      SYNC_FLIP_COUNT=$((SYNC_FLIP_COUNT + 1))
      
      if [ $SYNC_FLIP_COUNT -ge 3 ]; then
        echo "::error::❌ SYNC LOOP DETECTED (fail-fast at ${i}/${MAX_ATTEMPTS})!"
        echo ""
        echo "Argo CD is repeatedly syncing successfully but immediately returning to OutOfSync."
        echo "This indicates a configuration issue where resources are being modified after sync."
        echo ""
        echo "Pattern detected:"
        echo "  - Operation completes successfully (Succeeded)"
        echo "  - Sync status briefly becomes 'Synced'"
        echo "  - Immediately flips back to 'OutOfSync'"
        echo "  - This has repeated ${SYNC_FLIP_COUNT} times"
        echo ""
        echo "Common causes:"
        echo "  1. Resource has fields that are modified by controllers/admission webhooks"
        echo "  2. Spec in git doesn't match actual desired state"
        echo "  3. ignoreDifferences configuration needed for certain fields"
        echo "  4. Resource is managed by multiple controllers (conflict)"
        echo ""
        echo "::group::🔍 Application Events (last 10)"
        kubectl describe application ${APP_NAME} -n argocd | grep -A 20 "Events:" | tail -20 || echo "Cannot get events"
        echo "::endgroup::"
        echo ""
        echo "::group::🔍 Full Application Status"
        kubectl get application ${APP_NAME} -n argocd -o yaml | grep -A 100 "status:" || echo "Cannot get status"
        echo "::endgroup::"
        echo ""
        echo "::group::🔍 Resource Health Details"
        kubectl get application ${APP_NAME} -n argocd -o jsonpath='{.status.resources}' | jq . 2>/dev/null || \
          kubectl get application ${APP_NAME} -n argocd -o jsonpath='{.status.resources}' || \
          echo "Cannot get resource details"
        echo "::endgroup::"
        exit 1
      fi
    else
      # Reset counter if we're not in the problematic state
      SYNC_FLIP_COUNT=0
    fi

    if [ "$CURRENT_SYNC_STATUS" = "Synced" ]; then
      echo "✅ Argo CD sync complete"
      echo "  Synced to revision: ${CURRENT_SYNCED_REV:0:8}..."
      echo "  Target branch: ${CURRENT_TARGET_REV}"

      # CRITICAL: Verify we're not using a stale cached version
      # If target is a branch name, we can't validate exact commit match,
      # but we can check that the sync is recent (within last 60s)
      if [[ ! "${CURRENT_TARGET_REV}" =~ ^[0-9a-f]{40}$ ]]; then
        LAST_SYNC=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.finishedAt}' 2>/dev/null || echo "")
        if [ -n "$LAST_SYNC" ]; then
          SYNC_AGE=$(($(date +%s) - $(date -d "$LAST_SYNC" +%s 2>/dev/null || echo "0")))
          if [ $SYNC_AGE -gt 60 ]; then
            echo "  ⚠️ Warning: Last sync was ${SYNC_AGE}s ago - may be stale"
            echo "  Triggering hard refresh..."
            kubectl patch application ${APP_NAME} -n argocd -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}' --type=merge 2>/dev/null || true
            # Don't exit yet, give it one more cycle
            continue
          fi
        fi
      fi

      ARGOCD_SYNCED=true
      exit 0
    fi
  fi

  # Both checks complete
  if $NAMESPACE_CREATED && $ARGOCD_SYNCED; then
    echo "✅ Preview environment ready!"
    exit 0
  fi

  # Proactive check: Show why namespace might not be created yet or why sync is pending
  if [ $((i % 6)) -eq 0 ]; then  # Every 30s (6 * 5s interval)
    echo "::group::🔍 Argo CD Status Update (${i}/${MAX_ATTEMPTS})"
    SYNC_STATUS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
    SYNCED_REV=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.sync.revision}' 2>/dev/null || echo "None")
    TARGET_REV=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "Unknown")

    echo "  Current Sync Status: ${SYNC_STATUS}"
    echo "  Target Branch/Revision: ${TARGET_REV}"
    echo "  Synced to Commit: ${SYNCED_REV:0:8}..."

    # CRITICAL: Check for Argo CD manifest/comparison errors EARLY
    # These indicate the overlay/manifest is invalid and sync will never succeed
    echo ""
    echo "  🔍 Checking for manifest generation errors..."
    
    # Check if Argo CD comparison phase failed (invalid manifest)
    COMPARISON_ERROR=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.conditions[?(@.type=="ComparisonError")].message}' 2>/dev/null || echo "")
    if [ -n "$COMPARISON_ERROR" ]; then
      echo "::error::❌ MANIFEST GENERATION ERROR DETECTED (fail-fast):"
      echo "  ${COMPARISON_ERROR}"
      echo ""
      echo "This means the YAML/Kustomize overlay has invalid syntax."
      echo "Argo CD cannot sync until this is fixed."
      exit 1
    fi
    
    # Check for resource creation errors in the status
    RESOURCE_ERRORS=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.conditions[?(@.type=="InvalidResourcePath")].message}' 2>/dev/null || echo "")
    if [ -n "$RESOURCE_ERRORS" ]; then
      echo "::error::❌ INVALID RESOURCE PATH (fail-fast):"
      echo "  ${RESOURCE_ERRORS}"
      exit 1
    fi
    
    # Check if operational state indicates sync error
    OPERATION_STATE=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "")
    OPERATION_MSG=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.message}' 2>/dev/null || echo "")
    
    if [ "$OPERATION_STATE" = "Failed" ]; then
      echo "::error::❌ SYNC OPERATION FAILED (fail-fast):"
      echo "  Message: ${OPERATION_MSG}"
      echo ""
      
      # Try to extract the actual error
      SYNC_RESULT=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.syncResult}' 2>/dev/null || echo "")
      if [ -n "$SYNC_RESULT" ]; then
        echo "Sync result details:"
        echo "$SYNC_RESULT" | jq . 2>/dev/null || echo "$SYNC_RESULT"
      fi
      
      exit 1
    fi
    
    # Check for any hook job failures
    if [[ "$OPERATION_MSG" == *"hook"* ]]; then
      HOOK_JOB=$(echo "$OPERATION_MSG" | grep -oP '(?<=hook batch/Job/)[^ ]+' || echo "")
      if [ -n "$HOOK_JOB" ]; then
        # If namespace exists, check hook job status
        if kubectl get namespace ${NAMESPACE} &>/dev/null; then
          if kubectl get job ${HOOK_JOB} -n ${NAMESPACE} &>/dev/null; then
            JOB_FAILED=$(kubectl get job ${HOOK_JOB} -n ${NAMESPACE} -o jsonpath='{.status.failed}' 2>/dev/null || echo "0")
            JOB_ACTIVE=$(kubectl get job ${HOOK_JOB} -n ${NAMESPACE} -o jsonpath='{.status.active}' 2>/dev/null || echo "0")
            
            if [ "$JOB_FAILED" -gt 0 ]; then
              echo "::error::❌ HOOK JOB FAILED (fail-fast):"
              # Get pod logs
              POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l job-name=${HOOK_JOB} --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || echo "")
              if [ -n "$POD_NAME" ]; then
                echo ""
                echo "Pod logs:"
                kubectl logs ${POD_NAME} -n ${NAMESPACE} --all-containers=true --tail=30 2>/dev/null || echo "Cannot get logs"
              fi
              exit 1
            fi
          fi
        fi
      fi
    fi
    
    echo "  ✅ No manifest errors detected"

    # EARLY FAILURE DETECTION: Check for common issues in the namespace
    if kubectl get namespace ${NAMESPACE} &>/dev/null; then
      echo ""
      echo "  🔍 Checking for common deployment issues..."

      # Check 1: ExternalSecret failures (missing secrets, Key Vault access issues)
      FAILED_EXTERNALSECRETS=$(kubectl get externalsecrets -n ${NAMESPACE} -o json 2>/dev/null | jq -r '.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="False")) | .metadata.name' 2>/dev/null || echo "")
      if [ -n "$FAILED_EXTERNALSECRETS" ]; then
        echo "  ❌ FAILED EXTERNALSECRETS DETECTED:"
        for ES in $FAILED_EXTERNALSECRETS; do
          ES_MSG=$(kubectl get externalsecret ${ES} -n ${NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "Unknown error")
          echo "::error::ExternalSecret '${ES}' failed: ${ES_MSG}"
          echo "  - ${ES}: ${ES_MSG}"

          # Provide helpful troubleshooting based on error message
          if [[ "$ES_MSG" == *"could not get secret data from provider"* ]]; then
            echo "::error::Possible causes:"
            echo "::error::  1. Secret does not exist in Azure Key Vault"
            echo "::error::  2. Workload Identity does not have 'Get' permission on Key Vault secrets"
            echo "::error::  3. SecretStore is not configured for this namespace"
            echo "::error::  4. Key Vault firewall is blocking access"
          elif [[ "$ES_MSG" == *"SecretStore"* ]]; then
            echo "::error::Possible causes:"
            echo "::error::  1. SecretStore '${ES_MSG}' does not exist in namespace ${NAMESPACE}"
            echo "::error::  2. SecretStore is misconfigured"
          fi
        done
        exit 1
      fi

      # Check 2: ImagePullBackOff errors (ACR access, missing images)
      IMAGEPULL_ERRORS=$(kubectl get pods -n ${NAMESPACE} -o json 2>/dev/null | jq -r '.items[] | select(.status.containerStatuses[]? | select(.state.waiting.reason? | test("ImagePullBackOff|ErrImagePull"))) | .metadata.name' 2>/dev/null || echo "")
      if [ -n "$IMAGEPULL_ERRORS" ]; then
        echo "  ❌ IMAGE PULL ERRORS DETECTED:"
        for POD in $IMAGEPULL_ERRORS; do
          echo "::error::Pod '${POD}' cannot pull image"

          # Get the specific image and error
          IMAGE=$(kubectl get pod ${POD} -n ${NAMESPACE} -o jsonpath='{.status.containerStatuses[0].image}' 2>/dev/null || echo "Unknown")
          REASON=$(kubectl get pod ${POD} -n ${NAMESPACE} -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' 2>/dev/null || echo "")

          echo "  - Pod: ${POD}"
          echo "  - Image: ${IMAGE}"
          echo "  - Error: ${REASON}"

          # Show pod events for more context
          echo ""
          echo "::group::Pod Events for ${POD}"
          kubectl describe pod ${POD} -n ${NAMESPACE} 2>/dev/null | grep -A 20 "Events:" || echo "Cannot get events"
          echo "::endgroup::"
        done

        echo "::error::Possible causes:"
        echo "::error::  1. Image does not exist in ACR (check CI build succeeded)"
        echo "::error::  2. AKS kubelet identity lacks 'AcrPull' role on ACR"
        echo "::error::  3. ACR firewall is blocking AKS cluster"
        echo "::error::  4. Image pull secrets are missing or expired"
        exit 1
      fi

      # Check 3: CreateContainerConfigError (missing secrets, invalid env vars)
      CONFIG_ERRORS=$(kubectl get pods -n ${NAMESPACE} -o json 2>/dev/null | jq -r '.items[] | select(.status.containerStatuses[]? | select(.state.waiting.reason? | test("CreateContainerConfigError"))) | .metadata.name' 2>/dev/null || echo "")
      if [ -n "$CONFIG_ERRORS" ]; then
        echo "  ❌ CONTAINER CONFIG ERRORS DETECTED:"
        for POD in $CONFIG_ERRORS; do
          ERROR_MSG=$(kubectl get pod ${POD} -n ${NAMESPACE} -o jsonpath='{.status.containerStatuses[0].state.waiting.message}' 2>/dev/null || echo "")
          echo "::error::Pod '${POD}' has container config error: ${ERROR_MSG}"

          # Show pod events
          echo ""
          echo "::group::Pod Events for ${POD}"
          kubectl describe pod ${POD} -n ${NAMESPACE} 2>/dev/null | grep -A 20 "Events:" || echo "Cannot get events"
          echo "::endgroup::"
        done

        echo "::error::Possible causes:"
        echo "::error::  1. Missing Kubernetes Secret referenced in deployment"
        echo "::error::  2. ExternalSecret failed to create the required secret"
        echo "::error::  3. Invalid environment variable reference"
        echo "::error::  4. ConfigMap is missing"
        exit 1
      fi

      # Check 4: CrashLoopBackOff (application errors, missing dependencies)
      CRASHLOOP_PODS=$(kubectl get pods -n ${NAMESPACE} -o json 2>/dev/null | jq -r '.items[] | select(.status.containerStatuses[]? | select(.state.waiting.reason? | test("CrashLoopBackOff"))) | .metadata.name' 2>/dev/null || echo "")
      if [ -n "$CRASHLOOP_PODS" ]; then
        echo "  ❌ CRASH LOOP DETECTED:"
        for POD in $CRASHLOOP_PODS; do
          echo "::error::Pod '${POD}' is crash looping"

          # Get logs from previous container run
          echo ""
          echo "::group::Logs for ${POD} (previous run)"
          kubectl logs ${POD} -n ${NAMESPACE} --previous --tail=50 2>/dev/null || kubectl logs ${POD} -n ${NAMESPACE} --tail=50 2>/dev/null || echo "Cannot get logs"
          echo "::endgroup::"
        done

        echo "::error::Possible causes:"
        echo "::error::  1. Application code is failing at startup"
        echo "::error::  2. Missing required environment variables"
        echo "::error::  3. Cannot connect to database/dependencies"
        echo "::error::  4. Configuration error in the application"
        exit 1
      fi

      echo "  ✅ No common deployment issues detected"
    fi

    # Check if application is even running a sync operation
    OPERATION_RUNNING=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "None")
    OPERATION_MSG=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.operationState.message}' 2>/dev/null || echo "")

    if [ "$OPERATION_RUNNING" = "Running" ]; then
      echo "  ⏳ Sync operation in progress..."

      # CRITICAL: Check if stuck waiting for hook job
      if [[ "$OPERATION_MSG" == *"waiting for completion of hook"* ]]; then
        echo "  ⚠️ Waiting for sync hook to complete: ${OPERATION_MSG}"

        # Extract hook job name from message (e.g., "waiting for completion of hook batch/Job/db-migration")
        HOOK_JOB=$(echo "$OPERATION_MSG" | grep -oP '(?<=hook batch/Job/)[^ ]+' || echo "")
        if [ -n "$HOOK_JOB" ]; then
          echo "  🔍 Checking hook job status: ${HOOK_JOB}"

          # Check job status in the namespace
          if kubectl get job ${HOOK_JOB} -n ${NAMESPACE} &>/dev/null; then
            JOB_SUCCEEDED=$(kubectl get job ${HOOK_JOB} -n ${NAMESPACE} -o jsonpath='{.status.succeeded}' 2>/dev/null || echo "0")
            JOB_FAILED=$(kubectl get job ${HOOK_JOB} -n ${NAMESPACE} -o jsonpath='{.status.failed}' 2>/dev/null || echo "0")
            JOB_ACTIVE=$(kubectl get job ${HOOK_JOB} -n ${NAMESPACE} -o jsonpath='{.status.active}' 2>/dev/null || echo "0")

            echo "    Job Status: Succeeded=${JOB_SUCCEEDED}, Failed=${JOB_FAILED}, Active=${JOB_ACTIVE}"

            # FAIL FAST: If job has failed pods, get pod logs immediately
            if [ "$JOB_FAILED" -gt 0 ] || [ "$JOB_ACTIVE" -eq 0 -a "$JOB_SUCCEEDED" -eq 0 ]; then
              echo "::error::❌ Hook job ${HOOK_JOB} has failed or is not progressing!"

              # Get pod logs to understand the failure
              echo ""
              echo "::group::🔴 Hook Job Pod Logs"
              POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l job-name=${HOOK_JOB} --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null || echo "")
              if [ -n "$POD_NAME" ]; then
                echo "Pod: ${POD_NAME}"
                kubectl describe pod ${POD_NAME} -n ${NAMESPACE} 2>/dev/null || echo "Cannot describe pod"
                echo ""
                echo "--- Container Logs ---"
                kubectl logs ${POD_NAME} -n ${NAMESPACE} --all-containers=true 2>/dev/null || echo "Cannot get logs"
              else
                echo "Cannot find pod for job ${HOOK_JOB}"
              fi
              echo "::endgroup::"

              # Get job details
              echo ""
              echo "::group::🔴 Hook Job Details"
              kubectl describe job ${HOOK_JOB} -n ${NAMESPACE} 2>/dev/null || echo "Cannot describe job"
              echo "::endgroup::"

              exit 1
            fi

            # Show pod status for active jobs
            if [ "$JOB_ACTIVE" -gt 0 ]; then
              POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l job-name=${HOOK_JOB} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
              if [ -n "$POD_NAME" ]; then
                POD_PHASE=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
                POD_REASON=$(kubectl get pod ${POD_NAME} -n ${NAMESPACE} -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || echo "")
                echo "    Active Pod: ${POD_NAME} (Phase: ${POD_PHASE})"
                if [ -n "$POD_REASON" ]; then
                  echo "    Container State: ${POD_REASON}"

                  # FAIL FAST: Detect common fatal errors
                  case "$POD_REASON" in
                    ImagePullBackOff|ErrImagePull)
                      echo "::error::❌ Hook job pod cannot pull image!"
                      kubectl describe pod ${POD_NAME} -n ${NAMESPACE} 2>/dev/null | grep -A 10 "Events:" || true
                      exit 1
                      ;;
                    CrashLoopBackOff)
                      echo "::error::❌ Hook job pod is crash looping!"
                      kubectl logs ${POD_NAME} -n ${NAMESPACE} --previous 2>/dev/null || kubectl logs ${POD_NAME} -n ${NAMESPACE} 2>/dev/null || echo "Cannot get logs"
                      exit 1
                      ;;
                    CreateContainerConfigError)
                      echo "::error::❌ Hook job pod has container config error!"
                      kubectl describe pod ${POD_NAME} -n ${NAMESPACE} 2>/dev/null | grep -A 10 "Events:" || true
                      exit 1
                      ;;
                  esac
                fi
              fi
            fi
          else
            echo "  ⚠️ Hook job ${HOOK_JOB} not found in namespace ${NAMESPACE}"
          fi
        fi
      fi
    elif [ "$OPERATION_RUNNING" = "Succeeded" ]; then
      echo "  ✅ Last sync operation succeeded"
    elif [ "$OPERATION_RUNNING" = "None" ] && [ "$SYNC_STATUS" != "Synced" ]; then
      echo "  ::warning::No sync operation running but status is ${SYNC_STATUS}"
      echo "  This may indicate Argo CD hasn't detected changes yet (polling interval: 30s)"
    fi
    echo "::endgroup::"
  fi

  STATUS_MSG="Attempt $i/${MAX_ATTEMPTS}"
  [ ! $NAMESPACE_CREATED ] && STATUS_MSG="${STATUS_MSG} - Waiting for namespace..."
  [ $NAMESPACE_CREATED ] && [ ! $ARGOCD_SYNCED ] && STATUS_MSG="${STATUS_MSG} - Waiting for Argo CD sync..."
  echo "  ${STATUS_MSG}"
  sleep $INTERVAL
done

# Sync timeout - COMPREHENSIVE diagnostics
if $NAMESPACE_CREATED && ! $ARGOCD_SYNCED; then
  echo "::error::Argo CD did not complete sync after ${TIMEOUT}s (namespace exists but sync incomplete)"
else
  echo "::error::Namespace ${NAMESPACE} was not created by Argo CD after ${TIMEOUT}s"
fi
echo ""

echo "::group::🔴 FAILURE DIAGNOSTICS"
echo "--- Argo CD Application Full Status ---"
kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o yaml 2>/dev/null || echo "Application not found"

echo ""
echo "--- Argo CD Application Events ---"
kubectl describe application ${APP_NAME} -n argocd 2>/dev/null || echo "Cannot describe application"

echo ""
echo "--- Target Revision Configuration ---"
TARGET_REV=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "Unknown")
echo "  Target Revision: ${TARGET_REV}"
if [[ "${TARGET_REV}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "  ⚠️ WARNING: Using commit SHA - overlay updates won't be detected!"
  echo "  ApplicationSet should use '{{branch}}' not '{{head_sha}}'"
fi

echo ""
echo "--- All Preview Applications ---"
kubectl get applications.argoproj.io -n argocd | grep "preview-pr-" || echo "No preview applications found"

echo ""
echo "--- Argo CD ApplicationSet Status ---"
kubectl get applicationsets.argoproj.io -n argocd -o yaml | grep -A 50 "name: preview" || echo "Cannot get ApplicationSet"

echo ""
echo "--- Recent Argo CD Server Logs ---"
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-server --tail=50 || echo "Cannot get Argo CD logs"
echo "::endgroup::"

exit 1
