#!/bin/bash
# Shared Argo CD utilities for deployment workflows
# Provides health checking, auto-recovery, and diagnostic functions

set -euo pipefail

# Configuration
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
MAX_SYNC_DURATION="${MAX_SYNC_DURATION:-300}"  # 5 minutes
OPERATION_CHECK_INTERVAL="${OPERATION_CHECK_INTERVAL:-10}"  # 10 seconds

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Get Argo CD application status
get_app_status() {
    local app_name="$1"
    kubectl get application "$app_name" -n "$ARGOCD_NAMESPACE" -o json 2>/dev/null || echo "{}"
}

# Get sync status (Synced, OutOfSync, Unknown)
get_sync_status() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.status.sync.status // "Unknown"'
}

# Get health status (Healthy, Progressing, Degraded, Missing, Suspended, Unknown)
get_health_status() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.status.health.status // "Unknown"'
}

# Get operation state (Running, Succeeded, Failed, Error, Terminating)
get_operation_state() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.status.operationState.phase // "None"'
}

# Get operation message
get_operation_message() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.status.operationState.message // ""'
}

# Get sync revision
get_sync_revision() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.status.sync.revision // ""'
}

# Get target revision
get_target_revision() {
    local app_name="$1"
    get_app_status "$app_name" | jq -r '.spec.source.targetRevision // ""'
}

# Check if operation is stuck (running for too long)
is_operation_stuck() {
    local app_name="$1"
    local max_duration="$2"

    local started_at=$(get_app_status "$app_name" | jq -r '.status.operationState.startedAt // ""')
    if [ -z "$started_at" ] || [ "$started_at" = "null" ]; then
        echo "false"
        return
    fi

    local start_epoch=$(date -d "$started_at" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$started_at" +%s 2>/dev/null || echo "0")
    local now_epoch=$(date +%s)
    local duration=$((now_epoch - start_epoch))

    if [ "$duration" -gt "$max_duration" ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Clear stuck Argo CD operation
clear_stuck_operation() {
    local app_name="$1"

    log_warn "Clearing stuck operation for $app_name..."

    # Remove operation
    kubectl patch application "$app_name" -n "$ARGOCD_NAMESPACE" \
        --type json -p='[{"op": "remove", "path": "/operation"}]' 2>/dev/null || true

    # Remove operation state
    kubectl patch application "$app_name" -n "$ARGOCD_NAMESPACE" \
        --type json -p='[{"op": "remove", "path": "/status/operationState"}]' 2>/dev/null || true

    log_info "Operation cleared for $app_name"
}

# Trigger hard refresh
trigger_hard_refresh() {
    local app_name="$1"

    log_info "Triggering hard refresh for $app_name..."
    kubectl annotate application "$app_name" -n "$ARGOCD_NAMESPACE" \
        argocd.argoproj.io/refresh=hard --overwrite
}

# Check for common failure patterns
detect_failure_pattern() {
    local app_name="$1"
    local message="$2"

    # Pattern 1: Resource quota exceeded
    if echo "$message" | grep -qi "exceeded quota"; then
        echo "QUOTA_EXCEEDED"
        return
    fi

    # Pattern 2: Invalid container name
    if echo "$message" | grep -qi "Invalid value.*name"; then
        echo "INVALID_YAML"
        return
    fi

    # Pattern 3: Image pull errors
    if echo "$message" | grep -qi "ImagePullBackOff\|ErrImagePull"; then
        echo "IMAGE_PULL_FAILED"
        return
    fi

    # Pattern 4: Missing dependencies (service account, secret, etc.)
    if echo "$message" | grep -qi "not found"; then
        echo "MISSING_DEPENDENCY"
        return
    fi

    # Pattern 5: Timeout waiting for hook
    if echo "$message" | grep -qi "timed out.*waiting.*hook"; then
        echo "HOOK_TIMEOUT"
        return
    fi

    echo "UNKNOWN"
}

# Collect diagnostic information
collect_diagnostics() {
    local app_name="$1"
    local namespace="$2"
    local output_file="${3:-/tmp/argocd-diagnostics.log}"

    log_info "Collecting diagnostics for $app_name..."

    {
        echo "=== Argo CD Application Status ==="
        get_app_status "$app_name" | jq '.'

        echo ""
        echo "=== Operation State ==="
        echo "Phase: $(get_operation_state "$app_name")"
        echo "Message: $(get_operation_message "$app_name")"

        echo ""
        echo "=== Sync Status ==="
        echo "Status: $(get_sync_status "$app_name")"
        echo "Revision: $(get_sync_revision "$app_name")"

        echo ""
        echo "=== Health Status ==="
        echo "Status: $(get_health_status "$app_name")"

        echo ""
        echo "=== Deployments ==="
        kubectl get deployments -n "$namespace" -o wide 2>&1 || echo "No deployments found"

        echo ""
        echo "=== Pods ==="
        kubectl get pods -n "$namespace" -o wide 2>&1 || echo "No pods found"

        echo ""
        echo "=== Events (last 50) ==="
        kubectl get events -n "$namespace" --sort-by='.lastTimestamp' | tail -50 2>&1 || echo "No events found"

        echo ""
        echo "=== Resource Quota ==="
        kubectl get resourcequota -n "$namespace" -o yaml 2>&1 || echo "No quotas found"

    } > "$output_file"

    log_info "Diagnostics saved to $output_file"
    cat "$output_file"
}

# Auto-recovery based on failure pattern
auto_recover() {
    local app_name="$1"
    local pattern="$2"

    log_warn "Attempting auto-recovery for pattern: $pattern"

    case "$pattern" in
        QUOTA_EXCEEDED)
            log_error "Resource quota exceeded - cannot auto-recover"
            log_error "Manual intervention required: increase quota or reduce resource requests"
            return 1
            ;;
        INVALID_YAML)
            log_error "Invalid YAML structure - cannot auto-recover"
            log_error "Manual intervention required: fix kustomization template"
            return 1
            ;;
        IMAGE_PULL_FAILED)
            log_error "Image pull failed - cannot auto-recover"
            log_error "Manual intervention required: verify image exists in registry"
            return 1
            ;;
        MISSING_DEPENDENCY)
            log_warn "Missing dependency detected - retrying sync..."
            clear_stuck_operation "$app_name"
            sleep 5
            trigger_hard_refresh "$app_name"
            return 0
            ;;
        HOOK_TIMEOUT)
            log_warn "Hook timeout detected - clearing operation and retrying..."
            clear_stuck_operation "$app_name"
            sleep 5
            trigger_hard_refresh "$app_name"
            return 0
            ;;
        *)
            log_warn "Unknown failure pattern - attempting generic recovery..."
            clear_stuck_operation "$app_name"
            sleep 5
            trigger_hard_refresh "$app_name"
            return 0
            ;;
    esac
}

# Wait for Argo CD sync with health checks and auto-recovery
wait_for_sync() {
    local app_name="$1"
    local namespace="$2"
    local timeout="${3:-$MAX_SYNC_DURATION}"
    local check_interval="${4:-$OPERATION_CHECK_INTERVAL}"

    log_info "Waiting for Argo CD sync: $app_name (timeout: ${timeout}s)"

    local elapsed=0
    local last_recovery_attempt=0
    local recovery_attempts=0
    local max_recovery_attempts=3

    while [ $elapsed -lt "$timeout" ]; do
        local sync_status=$(get_sync_status "$app_name")
        local health_status=$(get_health_status "$app_name")
        local operation_state=$(get_operation_state "$app_name")

        log_info "[$elapsed/${timeout}s] Sync: $sync_status | Health: $health_status | Operation: $operation_state"

        # Success condition
        if [ "$sync_status" = "Synced" ] && [ "$health_status" = "Healthy" ]; then
            log_info "✅ Deployment successful!"
            return 0
        fi

        # Check for stuck operation
        if [ "$operation_state" = "Running" ]; then
            local is_stuck=$(is_operation_stuck "$app_name" "$MAX_SYNC_DURATION")
            if [ "$is_stuck" = "true" ]; then
                log_error "❌ Operation has been running for more than ${MAX_SYNC_DURATION}s - likely stuck!"

                # Collect diagnostics
                collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-stuck.log"

                # Attempt recovery if we haven't exceeded max attempts
                if [ $recovery_attempts -lt $max_recovery_attempts ]; then
                    log_warn "Attempting auto-recovery (attempt $((recovery_attempts + 1))/$max_recovery_attempts)..."

                    local message=$(get_operation_message "$app_name")
                    local pattern=$(detect_failure_pattern "$app_name" "$message")

                    if auto_recover "$app_name" "$pattern"; then
                        recovery_attempts=$((recovery_attempts + 1))
                        last_recovery_attempt=$elapsed
                        sleep 10
                        continue
                    else
                        log_error "Auto-recovery failed - manual intervention required"
                        return 1
                    fi
                else
                    log_error "Max recovery attempts ($max_recovery_attempts) exceeded"
                    return 1
                fi
            fi
        fi

        # Check for explicit failure
        if [ "$operation_state" = "Failed" ] || [ "$operation_state" = "Error" ]; then
            log_error "❌ Sync operation failed!"

            local message=$(get_operation_message "$app_name")
            log_error "Error: $message"

            # Collect diagnostics
            collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-failed.log"

            # Attempt recovery
            local pattern=$(detect_failure_pattern "$app_name" "$message")
            log_error "Detected failure pattern: $pattern"

            if [ $recovery_attempts -lt $max_recovery_attempts ] && [ $((elapsed - last_recovery_attempt)) -gt 30 ]; then
                if auto_recover "$app_name" "$pattern"; then
                    recovery_attempts=$((recovery_attempts + 1))
                    last_recovery_attempt=$elapsed
                    sleep 10
                    continue
                else
                    return 1
                fi
            else
                return 1
            fi
        fi

        # Check for Degraded health
        if [ "$health_status" = "Degraded" ] || [ "$health_status" = "Missing" ]; then
            log_warn "⚠️  Application health is $health_status"

            # If degraded for too long, collect diagnostics
            if [ $elapsed -gt 60 ]; then
                local message=$(get_operation_message "$app_name")
                local pattern=$(detect_failure_pattern "$app_name" "$message")

                if [ "$pattern" != "UNKNOWN" ]; then
                    log_warn "Detected issue pattern: $pattern"

                    # Only attempt recovery if we haven't tried recently
                    if [ $recovery_attempts -lt $max_recovery_attempts ] && [ $((elapsed - last_recovery_attempt)) -gt 30 ]; then
                        if auto_recover "$app_name" "$pattern"; then
                            recovery_attempts=$((recovery_attempts + 1))
                            last_recovery_attempt=$elapsed
                            sleep 10
                            continue
                        fi
                    fi
                fi
            fi
        fi

        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))
    done

    log_error "❌ Timeout waiting for sync after ${timeout}s"
    collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-timeout.log"
    return 1
}

# Export functions for use in other scripts
if [ "${BASH_SOURCE[0]}" != "${0}" ]; then
    export -f log_info log_warn log_error
    export -f get_app_status get_sync_status get_health_status get_operation_state
    export -f get_operation_message get_sync_revision get_target_revision
    export -f is_operation_stuck clear_stuck_operation trigger_hard_refresh
    export -f detect_failure_pattern collect_diagnostics auto_recover wait_for_sync
fi
