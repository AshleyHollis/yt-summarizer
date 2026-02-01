#!/bin/bash
# Shared Argo CD utilities for deployment workflows
# Provides health checking, auto-recovery, and diagnostic functions

set -euo pipefail

# Validate required tools
for tool in kubectl jq curl; do
  if ! command -v "$tool" &>/dev/null; then
    echo "::error::Required tool '$tool' not found in PATH" >&2
    exit 1
  fi
done

# Configuration
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
MAX_SYNC_DURATION="${MAX_SYNC_DURATION:-300}"  # 5 minutes - overall timeout
STUCK_OPERATION_THRESHOLD="${STUCK_OPERATION_THRESHOLD:-120}"  # 2 minutes - detect stuck operations faster
OPERATION_CHECK_INTERVAL="${OPERATION_CHECK_INTERVAL:-10}"  # 10 seconds
RECOVERY_TIMEOUT_EXTENSION="${RECOVERY_TIMEOUT_EXTENSION:-120}"  # 2 minutes - extra time after recovery
MISSING_APP_TIMEOUT="${MISSING_APP_TIMEOUT:-180}"  # 3 minutes - wait for app to appear

# GitHub API configuration
GITHUB_TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"

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

# Check if PR is still open
# Usage: check_pr_open <pr_number>
# Returns: 0 if open/unknown/no-pr, 1 if closed
# Note: Caller should handle return code appropriately (e.g., exit gracefully if PR closed)
check_pr_open() {
    local pr_number="$1"

    # Skip check if no PR number or production deployment
    if [[ -z "$pr_number" || "$pr_number" == "0" ]]; then
        return 0
    fi

    # Skip check if GitHub API not configured
    if [[ -z "$GITHUB_TOKEN" || -z "$GITHUB_REPOSITORY" ]]; then
        log_warn "Cannot check PR state: GITHUB_TOKEN or GITHUB_REPOSITORY not set"
        return 0
    fi

    # Query GitHub API with error handling
    local http_code
    local response
    response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$pr_number" 2>&1)

    http_code=$(echo "$response" | tail -n1)
    local body=$(echo "$response" | head -n-1)

    # Handle HTTP errors (assume open on error to avoid false positives)
    if [[ "$http_code" != "200" ]]; then
        log_warn "Failed to check PR $pr_number state (HTTP $http_code), assuming open"
        return 0
    fi

    # Parse PR state safely
    local pr_state=$(echo "$body" | jq -r '.state // empty' 2>/dev/null || echo "")

    if [[ "$pr_state" == "closed" ]]; then
        log_info "PR $pr_number is closed"
        return 1
    fi

    return 0
}

# Get Argo CD application status
get_app_status() {
    local app_name="$1"
    kubectl get application "$app_name" -n "$ARGOCD_NAMESPACE" -o json 2>/dev/null || echo "{}"
}

# Check if application exists
app_exists() {
    local app_name="$1"
    local app_found=$(get_app_status "$app_name" | jq -r '.metadata.name // ""')
    if [ -n "$app_found" ]; then
        echo "true"
    else
        echo "false"
    fi
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

    # Remove operation (silently)
    kubectl patch application "$app_name" -n "$ARGOCD_NAMESPACE" \
        --type json -p='[{"op": "remove", "path": "/operation"}]' 2>/dev/null || true

    # Remove operation state (silently)
    kubectl patch application "$app_name" -n "$ARGOCD_NAMESPACE" \
        --type json -p='[{"op": "remove", "path": "/status/operationState"}]' 2>/dev/null || true
}

# Trigger hard refresh
trigger_hard_refresh() {
    local app_name="$1"

    kubectl annotate application "$app_name" -n "$ARGOCD_NAMESPACE" \
        argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1
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

    case "$pattern" in
        QUOTA_EXCEEDED)
            log_error "   Cannot recover: Resource quota exceeded"
            return 1
            ;;
        INVALID_YAML)
            log_error "   Cannot recover: Invalid YAML structure"
            return 1
            ;;
        IMAGE_PULL_FAILED)
            log_error "   Cannot recover: Image pull failed"
            return 1
            ;;
        MISSING_DEPENDENCY|HOOK_TIMEOUT|*)
            log_info "   Clearing operation and refreshing..."
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
    local expected_image="${EXPECTED_IMAGE_TAG:-}"

    # Print header with deployment context
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "🚀 ArgoCD Sync: $app_name"
    log_info "   Namespace: $namespace"
    log_info "   Timeout: ${timeout}s"
    if [ -n "$expected_image" ]; then
        log_info "   Expected Image: $expected_image"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    local elapsed=0
    local missing_elapsed=0
    local last_recovery_attempt=0
    local recovery_attempts=0
    local max_recovery_attempts=3
    local last_status=""
    local same_status_count=0
    local stuck_warning_shown=false

    while [ $elapsed -lt "$timeout" ]; do
        # Check if PR is still open (for preview deployments)
        # If PR is closed, exit gracefully as deployment is no longer needed
        if [[ -n "${PR_NUMBER:-}" ]]; then
            if ! check_pr_open "${PR_NUMBER}"; then
                echo "::notice::PR ${PR_NUMBER} closed during sync - deployment no longer needed"
                log_info "✅ Deployment skipped (PR closed)"
                return 0
            fi
        fi

        local app_present=$(app_exists "$app_name")
        if [ "$app_present" = "false" ]; then
            log_warn "⏳ [${missing_elapsed}s] Waiting for application to be created..."

            if [ $missing_elapsed -ge "$MISSING_APP_TIMEOUT" ]; then
                # Before failing, check if PR was closed (common cause of app disappearance)
                if [[ -n "${PR_NUMBER:-}" ]]; then
                    if ! check_pr_open "${PR_NUMBER}"; then
                        echo "::notice::PR ${PR_NUMBER} closed - app removal expected"
                        log_info "✅ Deployment skipped (PR closed, app not found)"
                        return 0
                    fi
                fi

                log_error "❌ Application $app_name not found after ${MISSING_APP_TIMEOUT}s"
                collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-missing.log"
                return 1
            fi

            sleep "$check_interval"
            missing_elapsed=$((missing_elapsed + check_interval))
            elapsed=$((elapsed + check_interval))
            continue
        fi

        if [ $missing_elapsed -gt 0 ]; then
            log_info "✓ Application detected after ${missing_elapsed}s"
            missing_elapsed=0
        fi

        local sync_status=$(get_sync_status "$app_name")
        local health_status=$(get_health_status "$app_name")
        local operation_state=$(get_operation_state "$app_name")
        local current_status="${sync_status}|${health_status}|${operation_state}"

        # Track repeated status for stuck detection
        if [ "$current_status" = "$last_status" ]; then
            same_status_count=$((same_status_count + 1))
        else
            same_status_count=0
            stuck_warning_shown=false
        fi
        last_status="$current_status"

        # Format status line with visual indicators
        local sync_icon="⏳"
        local health_icon="⏳"
        [ "$sync_status" = "Synced" ] && sync_icon="✓"
        [ "$sync_status" = "OutOfSync" ] && sync_icon="↻"
        [ "$health_status" = "Healthy" ] && health_icon="✓"
        [ "$health_status" = "Progressing" ] && health_icon="⏳"
        [ "$health_status" = "Degraded" ] && health_icon="✗"

        # Only log status changes or every 30s to reduce noise
        if [ "$current_status" != "$last_status" ] || [ $((elapsed % 30)) -eq 0 ] || [ $elapsed -eq 0 ]; then
            log_info "[${elapsed}s] Sync: ${sync_icon} ${sync_status} | Health: ${health_icon} ${health_status} | Op: ${operation_state}"
        fi

        # Success condition
        if [ "$sync_status" = "Synced" ] && [ "$health_status" = "Healthy" ]; then
            # If expected image tag is provided, verify it matches before declaring success
            if [ -n "$expected_image" ]; then
                local actual_tag=""
                # Get the actual deployed image tag from the api deployment
                actual_tag=$(kubectl get deployment api -n "$namespace" \
                    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null | sed 's/.*://' || echo "")
                
                if [ "$actual_tag" != "$expected_image" ]; then
                    # ArgoCD shows synced but with wrong image tag - it hasn't synced the new overlay yet
                    if [ $((elapsed % 30)) -eq 0 ] || [ $elapsed -eq 0 ]; then
                        log_info "[${elapsed}s] Waiting for image tag update: current=$actual_tag, expected=$expected_image"
                    fi
                    sleep "$check_interval"
                    elapsed=$((elapsed + check_interval))
                    continue
                fi
                log_info "   ✓ Image tag verified: $actual_tag"
            fi
            
            echo ""
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_info "✅ Deployment successful! (${elapsed}s)"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            return 0
        fi

        # Stuck detection: same status for 90s+ with OutOfSync + Running (increased from 60s)
        if [ "$sync_status" = "OutOfSync" ] && [ "$operation_state" = "Running" ] && [ $same_status_count -ge 9 ] && [ "$stuck_warning_shown" = "false" ]; then
            log_warn "⚠️  Sync appears stuck (no progress for $((same_status_count * check_interval))s)"
            stuck_warning_shown=true

            # Check if refresh annotation is already present
            local has_refresh=$(kubectl get application "$app_name" -n "$ARGOCD_NAMESPACE" \
                -o jsonpath='{.metadata.annotations.argocd\.argoproj\.io/refresh}' 2>/dev/null || echo "")

            if [ -n "$has_refresh" ] && [ $((elapsed - last_recovery_attempt)) -gt 30 ] && [ $recovery_attempts -lt $max_recovery_attempts ]; then
                log_warn "Triggering recovery (attempt $((recovery_attempts + 1))/$max_recovery_attempts)..."

                # Clear stuck operation and re-trigger refresh
                if auto_recover "$app_name" "UNKNOWN"; then
                    recovery_attempts=$((recovery_attempts + 1))
                    last_recovery_attempt=$elapsed

                    # Extend timeout for recovery
                    timeout=$((timeout + RECOVERY_TIMEOUT_EXTENSION))
                    log_info "⏱️  Timeout extended to ${timeout}s for recovery"

                    sleep 10
                    continue
                fi
            fi
        fi

        # Check for stuck operation (using STUCK_OPERATION_THRESHOLD)
        if [ "$operation_state" = "Running" ]; then
            local is_stuck=$(is_operation_stuck "$app_name" "$STUCK_OPERATION_THRESHOLD")
            if [ "$is_stuck" = "true" ]; then
                log_warn "⚠️  Operation running for >${STUCK_OPERATION_THRESHOLD}s - triggering recovery"

                # Attempt recovery if we haven't exceeded max attempts
                if [ $recovery_attempts -lt $max_recovery_attempts ]; then
                    local message=$(get_operation_message "$app_name")
                    local pattern=$(detect_failure_pattern "$app_name" "$message")

                    if auto_recover "$app_name" "$pattern"; then
                        recovery_attempts=$((recovery_attempts + 1))
                        last_recovery_attempt=$elapsed
                        timeout=$((timeout + RECOVERY_TIMEOUT_EXTENSION))
                        log_info "⏱️  Timeout extended to ${timeout}s (recovery $recovery_attempts/$max_recovery_attempts)"
                        sleep 10
                        continue
                    else
                        log_error "Auto-recovery failed - manual intervention required"
                        collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-stuck.log"
                        return 1
                    fi
                else
                    log_error "Max recovery attempts ($max_recovery_attempts) exceeded"
                    collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-stuck.log"
                    return 1
                fi
            fi
        fi

        # Check for explicit failure
        if [ "$operation_state" = "Failed" ] || [ "$operation_state" = "Error" ]; then
            local message=$(get_operation_message "$app_name")
            local pattern=$(detect_failure_pattern "$app_name" "$message")

            log_error "❌ Sync failed: $pattern"
            [ -n "$message" ] && log_error "   $message"

            if [ $recovery_attempts -lt $max_recovery_attempts ] && [ $((elapsed - last_recovery_attempt)) -gt 30 ]; then
                if auto_recover "$app_name" "$pattern"; then
                    recovery_attempts=$((recovery_attempts + 1))
                    last_recovery_attempt=$elapsed
                    sleep 10
                    continue
                fi
            fi

            collect_diagnostics "$app_name" "$namespace" "/tmp/argocd-diagnostics-failed.log"
            return 1
        fi

        # Check for Degraded health (only warn once per degraded period)
        if [ "$health_status" = "Degraded" ] || [ "$health_status" = "Missing" ]; then
            if [ $same_status_count -eq 0 ]; then
                log_warn "⚠️  Health: $health_status"
            fi

            # If degraded for >60s, attempt recovery
            if [ $elapsed -gt 60 ] && [ $recovery_attempts -lt $max_recovery_attempts ] && [ $((elapsed - last_recovery_attempt)) -gt 30 ]; then
                local message=$(get_operation_message "$app_name")
                local pattern=$(detect_failure_pattern "$app_name" "$message")

                if [ "$pattern" != "UNKNOWN" ]; then
                    log_warn "Detected issue: $pattern - attempting recovery"
                    if auto_recover "$app_name" "$pattern"; then
                        recovery_attempts=$((recovery_attempts + 1))
                        last_recovery_attempt=$elapsed
                        sleep 10
                        continue
                    fi
                fi
            fi
        fi

        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))
    done

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_error "❌ Timeout after ${timeout}s"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
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
