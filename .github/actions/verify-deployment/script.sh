#!/bin/bash

# Verify Deployment Image Script
# This script verifies that a Kubernetes deployment is using the expected image tag

set -e

NAMESPACE="${INPUT_NAMESPACE}"
DEPLOYMENT="${INPUT_DEPLOYMENT_NAME}"
EXPECTED_TAG="${INPUT_EXPECTED_TAG}"
REGISTRY="${INPUT_REGISTRY}"
IMAGE_NAME="${INPUT_IMAGE_NAME}"
APP_NAME="${INPUT_APP_NAME:-}"
TIMEOUT=${INPUT_TIMEOUT_SECONDS:-300}
INTERVAL=5
MAX_ATTEMPTS=$((TIMEOUT / INTERVAL))
CHECK_INTERVAL=6
WAIT_FOR_READY="${INPUT_WAIT_FOR_READY:-true}"

echo "🔍 Verifying ${DEPLOYMENT} deployment with fail-fast diagnostics..."
echo "  Expected image: ${REGISTRY}/${IMAGE_NAME}:${EXPECTED_TAG}"
echo "  Namespace: ${NAMESPACE}"
echo "  Timeout: ${TIMEOUT}s"
echo ""

# CRITICAL PRE-CHECK: Verify overlay actually contains expected image tag
# If APP_NAME not provided, derive it from namespace
if [ -z "$APP_NAME" ]; then
  if [[ "${NAMESPACE}" == "preview-pr-"* ]]; then
    APP_NAME="${NAMESPACE}"
  elif [[ "${NAMESPACE}" == "preview-"* ]]; then
    APP_NAME=$(echo ${NAMESPACE} | sed 's/^preview-/preview-pr-/')
  elif [[ "${NAMESPACE}" == "prod" ]]; then
    APP_NAME="yt-summarizer-prod"
  elif [[ "${NAMESPACE}" == "yt-summarizer" ]]; then
    APP_NAME="yt-summarizer-prod"
  else
    # Fallback for unknown namespaces
    echo "::warning::Cannot derive APP_NAME from namespace ${NAMESPACE}, skipping pre-check"
  fi
fi
echo "::group::📋 Pre-check: Verify Argo CD has correct image tag in manifest"
if kubectl get applications.argoproj.io ${APP_NAME} -n argocd &>/dev/null; then
  MANIFEST=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.summary.images}' 2>/dev/null || echo "")

  if [[ "$MANIFEST" == *"${EXPECTED_TAG}"* ]]; then
    echo "✅ Argo CD manifest contains expected tag: ${EXPECTED_TAG}"
  else
    echo "::error::❌ CRITICAL: Argo CD manifest does NOT contain expected tag!"
    echo "  Expected tag: ${EXPECTED_TAG}"
    echo "  Current images in manifest: ${MANIFEST}"
    echo ""
    echo "  This indicates Argo CD synced a STALE overlay version."
    kubectl patch application ${APP_NAME} -n argocd -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}' --type=merge 2>/dev/null || true
    sleep 30
    MANIFEST=$(kubectl get applications.argoproj.io ${APP_NAME} -n argocd -o jsonpath='{.status.summary.images}' 2>/dev/null || echo "")
    if [[ "$MANIFEST" == *"${EXPECTED_TAG}"* ]]; then
      echo "✅ Manifest updated after refresh"
    else
      echo "::error::❌ Manifest still stale after refresh - failing fast"
      kubectl describe application ${APP_NAME} -n argocd
      exit 1
    fi
  fi
fi
echo "::endgroup::"
echo ""

check_argocd_health() {
  local app_name=$1
  local fail_on_error=${2:-false}

  if ! kubectl get applications.argoproj.io ${app_name} -n argocd &>/dev/null; then
    echo "  ⚠️ Argo CD application ${app_name} not found"
    return 1
  fi

  local health=$(kubectl get applications.argoproj.io ${app_name} -n argocd -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")
  local sync=$(kubectl get applications.argoproj.io ${app_name} -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
  local target_rev=$(kubectl get applications.argoproj.io ${app_name} -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || "")

  echo "  Argo CD Health: ${health} | Sync: ${sync}"

  if [[ "${target_rev}" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::❌ FATAL: Application locked to commit SHA!"
    echo "  Target revision '${target_rev}' is a commit SHA, not a branch."
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  if [ "$health" = "Degraded" ]; then
    echo "::error::❌ Application health is Degraded!"
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  if [ "$health" = "Missing" ]; then
    echo "::error::❌ Application resources are Missing!"
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  return 0
}

check_deployment_health() {
  local namespace=$1
  local deployment=$2
  local fail_on_error=${3:-false}

  if ! kubectl get deployment ${deployment} -n ${namespace} &>/dev/null; then
    return 1
  fi

  local desired=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
  local ready=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
  local available=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.availableReplicas}' 2>/dev/null || echo "0")
  local updated=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.updatedReplicas}' 2>/dev/null || echo "0")

  echo "  Deployment Status: ${ready}/${desired} ready, ${available}/${desired} available, ${updated}/${desired} updated"

  local replica_failure=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.conditions[?(@.type=="ReplicaFailure")].status}' 2>/dev/null)
  if [ "$replica_failure" = "True" ]; then
    echo "::error::❌ FATAL: Deployment has ReplicaFailure condition!"
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  local progressing=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.conditions[?(@.type=="Progressing")].status}' 2>/dev/null)
  local prog_reason=$(kubectl get deployment ${deployment} -n ${namespace} -o jsonpath='{.status.conditions[?(@.type=="Progressing")].reason}' 2>/dev/null)
  if [ "$progressing" = "False" ] && [ "$prog_reason" = "ProgressDeadlineExceeded" ]; then
    echo "::error::❌ FATAL: Deployment progress deadline exceeded!"
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  return 0
}

check_pod_issues() {
  local namespace=$1
  local deployment=$2
  local fail_on_error=${3:-false}

  local pods=$(kubectl get pods -n ${namespace} -l app=${deployment} -o name 2>/dev/null)
  if [ -z "$pods" ]; then
    return 0
  fi

  local fatal_error=false

  for pod in $pods; do
    local pod_name=$(echo $pod | cut -d'/' -f2)
    local waiting_reason=$(kubectl get ${pod} -n ${namespace} -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null)

    if [ "$waiting_reason" = "ImagePullBackOff" ] || [ "$waiting_reason" = "ErrImagePull" ]; then
      echo "::error::❌ FATAL: Pod ${pod_name} cannot pull image!"
      fatal_error=true
    fi

    if [ "$waiting_reason" = "CrashLoopBackOff" ]; then
      echo "::error::❌ FATAL: Pod ${pod_name} in CrashLoopBackOff!"
      local restart_count=$(kubectl get ${pod} -n ${namespace} -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
      echo "  Restart count: ${restart_count}"
      kubectl logs ${pod} -n ${namespace} --tail=20 2>&1 | sed 's/^/    /' || true
      fatal_error=true
    fi

    local term_reason=$(kubectl get ${pod} -n ${namespace} -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null)
    if [ "$term_reason" = "OOMKilled" ]; then
      echo "::error::❌ Pod ${pod_name} was OOMKilled!"
      fatal_error=true
    fi
  done

  if [ "$fatal_error" = "true" ]; then
    [ "$fail_on_error" = "true" ] && exit 1
    return 1
  fi

  return 0
}

echo "Starting verification with fail-fast enabled..."
echo ""

# Determine app name: use provided env var, or derive from deployment labels, or default to preview pattern
if [ -z "$APP_NAME" ]; then
  APP_NAME=$(kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o jsonpath='{.metadata.labels.argocd\.argoproj\.io/instance}' 2>/dev/null || echo "")
  if [ -z "$APP_NAME" ]; then
    APP_NAME=$(echo ${NAMESPACE} | sed 's/^/preview-/')
  fi
fi

for i in $(seq 1 $MAX_ATTEMPTS); do
  if [ $((i % CHECK_INTERVAL)) -eq 1 ] || [ $i -eq 1 ]; then
    echo "::group::🔍 Phase 1: Argo CD Health Check (Attempt $i/${MAX_ATTEMPTS})"
    if ! check_argocd_health "${APP_NAME}" "true"; then
      echo "::endgroup::"
      exit 1
    fi
    echo "::endgroup::"
  fi

  if ! kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} &>/dev/null; then
    if [ $i -eq 1 ]; then
      echo "⏳ Waiting for deployment ${DEPLOYMENT} to be created..."
    elif [ $((i % CHECK_INTERVAL)) -eq 0 ]; then
      echo "  Still waiting... (${i}/${MAX_ATTEMPTS})"
    fi
    sleep $INTERVAL
    continue
  fi

  if [ $i -eq 1 ] || [ $((i % CHECK_INTERVAL)) -eq 0 ]; then
    echo "::group::🔍 Phase 2: Deployment Health Check"
    if ! check_deployment_health "${NAMESPACE}" "${DEPLOYMENT}" "true"; then
      echo "::endgroup::"
      exit 1
    fi
    echo "::endgroup::"
  fi

  if [ $((i % CHECK_INTERVAL)) -eq 0 ]; then
    echo "::group::🔍 Phase 3: Pod Health Check"
    if ! check_pod_issues "${NAMESPACE}" "${DEPLOYMENT}" "true"; then
      echo "::endgroup::"
      exit 1
    fi
    echo "::endgroup::"
  fi

  CURRENT_IMAGE=$(kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null)

  if [[ "${CURRENT_IMAGE}" == "${REGISTRY}/${IMAGE_NAME}:${EXPECTED_TAG}" ]]; then
    echo "✅ Deployment ${DEPLOYMENT} has correct image: ${CURRENT_IMAGE}"

    echo "::group::🔍 Pod Image Verification"
    POD_IMAGES=$(kubectl get pods -n ${NAMESPACE} -l app=${DEPLOYMENT} -o jsonpath='{.items[*].spec.containers[0].image}' 2>/dev/null)
    if [ -n "$POD_IMAGES" ]; then
      echo "  Pod images: ${POD_IMAGES}"
      if echo "${POD_IMAGES}" | grep -q "${EXPECTED_TAG}"; then
        echo "  ✅ Pods are using expected tag"
      fi
    fi
    echo "::endgroup::"

    if [ "$WAIT_FOR_READY" = "true" ]; then
      echo ""
      echo "⏳ Waiting for deployment rollout to complete..."

      if timeout 120s kubectl rollout status deployment/${DEPLOYMENT} -n ${NAMESPACE}; then
        echo "✅ ${DEPLOYMENT} deployment is ready"
        echo "::group::📋 Final Status Summary"
        kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o wide
        echo ""
        kubectl get pods -n ${NAMESPACE} -l app=${DEPLOYMENT} -o wide
        echo "::endgroup::"
        echo ""
        echo "🎉 Verification complete! Deployment is healthy and using correct image."
        exit 0
      else
        echo "::error::❌ Deployment rollout timed out after 120s"
        echo "::group::🔴 Rollout Failure Diagnostics"
        kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o wide
        echo "::endgroup::"
        exit 1
      fi
    else
      echo ""
      echo "✅ Image verification complete (not waiting for rollout)"
      exit 0
    fi

  else
    if [ $i -eq 1 ]; then
      echo "⚠️ Image tag mismatch detected"
      echo "  Expected: ${REGISTRY}/${IMAGE_NAME}:${EXPECTED_TAG}"
      echo "  Current:  ${CURRENT_IMAGE}"
      echo "  Waiting for Argo CD to sync..."
    fi
  fi

  if [ $i -lt $MAX_ATTEMPTS ]; then
    sleep $INTERVAL
  fi
done

echo ""
echo "::error::❌ Verification timed out after ${TIMEOUT}s"
echo "::group::🔴 Timeout Diagnostics"
echo "Expected: ${REGISTRY}/${IMAGE_NAME}:${EXPECTED_TAG}"
FINAL_IMAGE=$(kubectl get deployment ${DEPLOYMENT} -n ${NAMESPACE} -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "N/A")
echo "Current:  ${FINAL_IMAGE}"
kubectl get applications.argoproj.io ${APP_NAME} -n argocd 2>/dev/null || true
kubectl describe deployment ${DEPLOYMENT} -n ${NAMESPACE} 2>/dev/null || true
echo "::endgroup::"
exit 1
