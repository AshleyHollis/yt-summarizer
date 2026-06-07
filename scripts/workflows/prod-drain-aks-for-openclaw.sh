#!/bin/bash
# =============================================================================
# Drain AKS production workloads during OpenClaw cutover
# =============================================================================
# Used by: .github/workflows/deploy-prod.yml
#
# This is intentionally scoped to the one-time AKS -> OpenClaw migration path.
# It disables Argo CD automated self-heal for the old AKS production app before
# scaling workloads down, so Argo does not immediately restore the replicas.
# =============================================================================

set -euo pipefail

MODE="${1:-workers}"
NAMESPACE="${NAMESPACE_PROD:-yt-summarizer}"
ARGOCD_NAMESPACE="${NAMESPACE_ARGOCD:-argocd}"
ARGOCD_APP_NAME="${ARGOCD_APP_NAME_PROD:-yt-summarizer-prod}"
TIMEOUT_SECONDS="${AKS_DRAIN_TIMEOUT_SECONDS:-180}"

WORKER_DEPLOYMENTS=(
  transcribe-worker
  summarize-worker
  embed-worker
  relationships-worker
)

usage() {
  echo "Usage: $0 workers|api|all|status"
}

log_info() {
  echo "[INFO] $*"
}

log_warn() {
  echo "::warning::$*"
}

log_error() {
  echo "::error::$*"
}

require_kubectl_context() {
  if ! kubectl cluster-info >/dev/null 2>&1; then
    log_error "kubectl is not connected to the AKS production cluster"
    exit 1
  fi
}

namespace_exists() {
  kubectl get namespace "$NAMESPACE" >/dev/null 2>&1
}

deployment_exists() {
  local deployment="$1"
  kubectl -n "$NAMESPACE" get deployment "$deployment" >/dev/null 2>&1
}

pause_argocd_self_heal() {
  if ! kubectl -n "$ARGOCD_NAMESPACE" get application "$ARGOCD_APP_NAME" >/dev/null 2>&1; then
    log_warn "Argo CD application $ARGOCD_APP_NAME was not found; continuing with direct scaling"
    return
  fi

  local automated_sync
  automated_sync="$(
    kubectl -n "$ARGOCD_NAMESPACE" get application "$ARGOCD_APP_NAME" \
      -o jsonpath='{.spec.syncPolicy.automated}' 2>/dev/null || true
  )"

  if [[ -n "$automated_sync" ]]; then
    log_info "Disabling automated sync/self-heal on $ARGOCD_APP_NAME in old AKS"
    kubectl -n "$ARGOCD_NAMESPACE" patch application "$ARGOCD_APP_NAME" \
      --type=json \
      -p='[{"op":"remove","path":"/spec/syncPolicy/automated"}]'
  else
    log_info "Automated sync/self-heal is already disabled on $ARGOCD_APP_NAME"
  fi

  kubectl -n "$ARGOCD_NAMESPACE" annotate application "$ARGOCD_APP_NAME" \
    migration.yt-summarizer/openclaw-drained-at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --overwrite >/dev/null
}

desired_deployments() {
  case "$MODE" in
    workers)
      printf '%s\n' "${WORKER_DEPLOYMENTS[@]}"
      ;;
    api)
      printf '%s\n' api
      ;;
    all)
      printf '%s\n' api "${WORKER_DEPLOYMENTS[@]}"
      ;;
    status)
      return 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

scale_to_zero() {
  local deployments=("$@")

  if [[ ${#deployments[@]} -eq 0 ]]; then
    return
  fi

  for deployment in "${deployments[@]}"; do
    if deployment_exists "$deployment"; then
      log_info "Scaling $NAMESPACE/$deployment to 0 replicas"
      kubectl -n "$NAMESPACE" scale deployment "$deployment" --replicas=0
    else
      log_warn "Deployment $NAMESPACE/$deployment was not found; skipping"
    fi
  done
}

wait_for_zero_replicas() {
  local deployments=("$@")
  local deadline=$((SECONDS + TIMEOUT_SECONDS))

  while ((SECONDS < deadline)); do
    local still_running=()

    for deployment in "${deployments[@]}"; do
      if ! deployment_exists "$deployment"; then
        continue
      fi

      local ready_replicas
      local current_replicas
      ready_replicas="$(
        kubectl -n "$NAMESPACE" get deployment "$deployment" \
          -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true
      )"
      current_replicas="$(
        kubectl -n "$NAMESPACE" get deployment "$deployment" \
          -o jsonpath='{.status.replicas}' 2>/dev/null || true
      )"

      ready_replicas="${ready_replicas:-0}"
      current_replicas="${current_replicas:-0}"

      if [[ "$ready_replicas" != "0" || "$current_replicas" != "0" ]]; then
        still_running+=("$deployment=${ready_replicas}/${current_replicas}")
      fi
    done

    if [[ ${#still_running[@]} -eq 0 ]]; then
      log_info "Selected AKS workloads are drained"
      return
    fi

    log_info "Waiting for AKS workloads to drain: ${still_running[*]}"
    sleep 5
  done

  log_error "Timed out waiting for selected AKS workloads to drain"
  kubectl -n "$NAMESPACE" get deployment -o wide
  exit 1
}

print_status() {
  if namespace_exists; then
    kubectl -n "$NAMESPACE" get deployment \
      api transcribe-worker summarize-worker embed-worker relationships-worker \
      -o wide --ignore-not-found
  else
    log_warn "Namespace $NAMESPACE does not exist"
  fi
}

main() {
  require_kubectl_context

  if [[ "$MODE" == "status" ]]; then
    print_status
    return
  fi

  if ! namespace_exists; then
    log_warn "Namespace $NAMESPACE does not exist; AKS production already appears drained"
    return
  fi

  mapfile -t deployments < <(desired_deployments)
  pause_argocd_self_heal
  scale_to_zero "${deployments[@]}"
  wait_for_zero_replicas "${deployments[@]}"
  print_status
}

main "$@"
