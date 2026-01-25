#!/bin/bash
# Pre-deployment validation for Kubernetes manifests
# Catches common issues before Argo CD deploys them

set -euo pipefail

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

# Validation results
VALIDATION_ERRORS=0
VALIDATION_WARNINGS=0

# Validate kustomization builds successfully
validate_kustomize_build() {
    local kustomize_dir="$1"
    
    log_info "Validating kustomize build: $kustomize_dir"
    
    if ! kubectl kustomize "$kustomize_dir" > /tmp/manifests.yaml 2>&1; then
        log_error "❌ Kustomize build failed!"
        cat /tmp/manifests.yaml
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
        return 1
    fi
    
    log_info "✅ Kustomize build successful"
    return 0
}

# Validate YAML syntax and structure
validate_yaml_structure() {
    local manifests_file="$1"
    
    log_info "Validating YAML structure..."
    
    # Check for common YAML issues
    local errors=$(kubectl apply --dry-run=client -f "$manifests_file" 2>&1 | grep -i "error\|invalid" || true)
    
    if [ -n "$errors" ]; then
        log_error "❌ YAML validation failed:"
        echo "$errors"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
        return 1
    fi
    
    log_info "✅ YAML structure valid"
    return 0
}

# Extract resource requests/limits from manifests
calculate_resource_requirements() {
    local manifests_file="$1"
    
    log_info "Calculating resource requirements..."
    
    local total_cpu_requests=0
    local total_cpu_limits=0
    local total_memory_requests=0
    local total_memory_limits=0
    
    # Extract all Deployments, StatefulSets, DaemonSets, Jobs
    local resource_types=("Deployment" "StatefulSet" "DaemonSet" "Job")
    
    for kind in "${resource_types[@]}"; do
        # Get all resources of this kind
        local resources=$(kubectl get -f "$manifests_file" --ignore-not-found -o json 2>/dev/null | \
            jq -r ".items[] | select(.kind == \"$kind\") | .metadata.name" || true)
        
        for resource in $resources; do
            # Get replicas (default to 1 for Jobs)
            local replicas=1
            if [ "$kind" != "Job" ]; then
                replicas=$(kubectl get -f "$manifests_file" -o json 2>/dev/null | \
                    jq -r ".items[] | select(.kind == \"$kind\" and .metadata.name == \"$resource\") | .spec.replicas // 1" || echo "1")
            fi
            
            # Get container resources
            local containers=$(kubectl get -f "$manifests_file" -o json 2>/dev/null | \
                jq -r ".items[] | select(.kind == \"$kind\" and .metadata.name == \"$resource\") | .spec.template.spec.containers[] | .resources" || true)
            
            # Parse CPU requests/limits (convert m to millicores)
            local cpu_request=$(echo "$containers" | jq -r '.requests.cpu // "0"' | sed 's/m$//' || echo "0")
            local cpu_limit=$(echo "$containers" | jq -r '.limits.cpu // "0"' | sed 's/m$//' || echo "0")
            
            # Parse memory requests/limits (convert to MiB)
            local mem_request=$(echo "$containers" | jq -r '.requests.memory // "0"' | sed 's/Mi$//' || echo "0")
            local mem_limit=$(echo "$containers" | jq -r '.limits.memory // "0"' | sed 's/Mi$//' || echo "0")
            
            # Multiply by replicas
            total_cpu_requests=$((total_cpu_requests + cpu_request * replicas))
            total_cpu_limits=$((total_cpu_limits + cpu_limit * replicas))
            total_memory_requests=$((total_memory_requests + mem_request * replicas))
            total_memory_limits=$((total_memory_limits + mem_limit * replicas))
            
            log_info "  $kind/$resource (×$replicas): CPU ${cpu_request}m-${cpu_limit}m, Memory ${mem_request}Mi-${mem_limit}Mi"
        done
    done
    
    log_info "Total resource requirements:"
    log_info "  CPU requests: ${total_cpu_requests}m, limits: ${total_cpu_limits}m"
    log_info "  Memory requests: ${total_memory_requests}Mi, limits: ${total_memory_limits}Mi"
    
    # Export for quota validation
    echo "$total_cpu_requests $total_cpu_limits $total_memory_requests $total_memory_limits"
}

# Validate against namespace quota
validate_quota() {
    local namespace="$1"
    local total_cpu_limits="$2"
    local total_memory_limits="$3"
    
    log_info "Validating against namespace quota: $namespace"
    
    # Get quota (if exists)
    local quota=$(kubectl get resourcequota -n "$namespace" -o json 2>/dev/null || echo '{"items":[]}')
    
    if [ "$(echo "$quota" | jq '.items | length')" -eq 0 ]; then
        log_warn "⚠️  No resource quota found in namespace $namespace"
        VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1))
        return 0
    fi
    
    # Get quota limits
    local quota_cpu=$(echo "$quota" | jq -r '.items[0].spec.hard["limits.cpu"] // "0"' | sed 's/m$//')
    local quota_memory=$(echo "$quota" | jq -r '.items[0].spec.hard["limits.memory"] // "0"' | sed 's/Mi$//')
    
    log_info "Namespace quota: CPU ${quota_cpu}m, Memory ${quota_memory}Mi"
    
    # Check if deployment would exceed quota
    if [ "$total_cpu_limits" -gt "$quota_cpu" ]; then
        log_error "❌ CPU limit ($total_cpu_limits m) exceeds quota ($quota_cpu m)"
        log_error "   Deficit: $((total_cpu_limits - quota_cpu))m"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
        return 1
    fi
    
    if [ "$total_memory_limits" -gt "$quota_memory" ]; then
        log_error "❌ Memory limit ($total_memory_limits Mi) exceeds quota ($quota_memory Mi)"
        log_error "   Deficit: $((total_memory_limits - quota_memory))Mi"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
        return 1
    fi
    
    # Warn if over 80% quota usage
    local cpu_usage_pct=$((total_cpu_limits * 100 / quota_cpu))
    local mem_usage_pct=$((total_memory_limits * 100 / quota_memory))
    
    if [ "$cpu_usage_pct" -gt 80 ]; then
        log_warn "⚠️  CPU usage at ${cpu_usage_pct}% of quota"
        VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1))
    fi
    
    if [ "$mem_usage_pct" -gt 80 ]; then
        log_warn "⚠️  Memory usage at ${mem_usage_pct}% of quota"
        VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1))
    fi
    
    log_info "✅ Resource requirements within quota limits"
    log_info "   CPU: ${cpu_usage_pct}% (${total_cpu_limits}m / ${quota_cpu}m)"
    log_info "   Memory: ${mem_usage_pct}% (${total_memory_limits}Mi / ${quota_memory}Mi)"
    
    return 0
}

# Validate images exist in registry
validate_images() {
    local manifests_file="$1"
    local acr_server="${2:-acrytsummprd.azurecr.io}"
    
    log_info "Validating container images exist in registry..."
    
    # Extract all images from manifests
    local images=$(kubectl get -f "$manifests_file" -o json 2>/dev/null | \
        jq -r '.items[].spec.template.spec.containers[]?.image // empty' | sort -u || true)
    
    if [ -z "$images" ]; then
        log_warn "⚠️  No container images found in manifests"
        VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1))
        return 0
    fi
    
    local missing_images=0
    
    for image in $images; do
        # Only validate ACR images
        if [[ "$image" == *"$acr_server"* ]]; then
            # Extract repository and tag
            local repo=$(echo "$image" | sed "s|$acr_server/||" | cut -d: -f1)
            local tag=$(echo "$image" | cut -d: -f2)
            
            log_info "  Checking $repo:$tag..."
            
            # Check if image exists
            if ! az acr repository show-tags --name "${acr_server%%.*}" \
                --repository "$repo" --output tsv 2>/dev/null | grep -q "^$tag$"; then
                log_error "❌ Image not found: $image"
                missing_images=$((missing_images + 1))
            else
                log_info "  ✅ $repo:$tag exists"
            fi
        else
            log_info "  Skipping non-ACR image: $image"
        fi
    done
    
    if [ $missing_images -gt 0 ]; then
        log_error "❌ $missing_images image(s) not found in registry"
        VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
        return 1
    fi
    
    log_info "✅ All images exist in registry"
    return 0
}

# Validate required secrets exist
validate_secrets() {
    local manifests_file="$1"
    local namespace="$2"
    
    log_info "Validating required secrets exist..."
    
    # Extract secret references from ExternalSecrets
    local external_secrets=$(kubectl get -f "$manifests_file" --ignore-not-found -o json 2>/dev/null | \
        jq -r '.items[] | select(.kind == "ExternalSecret") | .spec.target.name' || true)
    
    if [ -z "$external_secrets" ]; then
        log_info "  No ExternalSecrets found - skipping validation"
        return 0
    fi
    
    local missing_secrets=0
    
    for secret in $external_secrets; do
        log_info "  Checking secret: $secret"
        
        if ! kubectl get secret "$secret" -n "$namespace" &>/dev/null; then
            log_warn "⚠️  Secret not yet created (will be created by ExternalSecret operator): $secret"
            VALIDATION_WARNINGS=$((VALIDATION_WARNINGS + 1))
        else
            log_info "  ✅ $secret exists"
        fi
    done
    
    return 0
}

# Validate resource dependencies (ServiceAccounts, ConfigMaps, etc.)
validate_dependencies() {
    local manifests_file="$1"
    local namespace="$2"
    
    log_info "Validating resource dependencies..."
    
    # Check for ServiceAccount references in Pods/Jobs
    local service_accounts=$(kubectl get -f "$manifests_file" -o json 2>/dev/null | \
        jq -r '.items[].spec.template.spec.serviceAccountName // empty' | sort -u || true)
    
    for sa in $service_accounts; do
        if [ "$sa" = "default" ]; then
            continue
        fi
        
        log_info "  Checking ServiceAccount: $sa"
        
        # Check if SA exists in manifests
        local sa_exists=$(kubectl get -f "$manifests_file" --ignore-not-found -o json 2>/dev/null | \
            jq -r ".items[] | select(.kind == \"ServiceAccount\" and .metadata.name == \"$sa\") | .metadata.name" || true)
        
        if [ -z "$sa_exists" ]; then
            # Check if SA exists in cluster
            if ! kubectl get serviceaccount "$sa" -n "$namespace" &>/dev/null; then
                log_error "❌ ServiceAccount not found in manifests or cluster: $sa"
                VALIDATION_ERRORS=$((VALIDATION_ERRORS + 1))
            else
                log_info "  ✅ $sa exists in cluster"
            fi
        else
            log_info "  ✅ $sa defined in manifests"
        fi
    done
    
    return 0
}

# Main validation function
validate_deployment() {
    local kustomize_dir="$1"
    local namespace="$2"
    local acr_server="${3:-acrytsummprd.azurecr.io}"
    
    log_info "==== Pre-Deployment Validation ===="
    log_info "Kustomize directory: $kustomize_dir"
    log_info "Target namespace: $namespace"
    log_info "====================================="
    
    # Step 1: Validate kustomize builds
    if ! validate_kustomize_build "$kustomize_dir"; then
        log_error "Kustomize build validation failed - aborting"
        return 1
    fi
    
    local manifests_file="/tmp/manifests.yaml"
    
    # Step 2: Validate YAML structure
    validate_yaml_structure "$manifests_file" || true
    
    # Step 3: Calculate resource requirements
    local resource_totals=$(calculate_resource_requirements "$manifests_file")
    local cpu_requests=$(echo "$resource_totals" | awk '{print $1}')
    local cpu_limits=$(echo "$resource_totals" | awk '{print $2}')
    local mem_requests=$(echo "$resource_totals" | awk '{print $3}')
    local mem_limits=$(echo "$resource_totals" | awk '{print $4}')
    
    # Step 4: Validate against quota
    validate_quota "$namespace" "$cpu_limits" "$mem_limits" || true
    
    # Step 5: Validate images exist
    validate_images "$manifests_file" "$acr_server" || true
    
    # Step 6: Validate secrets
    validate_secrets "$manifests_file" "$namespace" || true
    
    # Step 7: Validate dependencies
    validate_dependencies "$manifests_file" "$namespace" || true
    
    # Summary
    log_info "====================================="
    log_info "Validation Summary:"
    log_info "  Errors: $VALIDATION_ERRORS"
    log_info "  Warnings: $VALIDATION_WARNINGS"
    log_info "====================================="
    
    if [ $VALIDATION_ERRORS -gt 0 ]; then
        log_error "❌ Validation failed with $VALIDATION_ERRORS error(s)"
        return 1
    fi
    
    if [ $VALIDATION_WARNINGS -gt 0 ]; then
        log_warn "⚠️  Validation passed with $VALIDATION_WARNINGS warning(s)"
    else
        log_info "✅ All validations passed!"
    fi
    
    return 0
}

# If script is executed directly (not sourced)
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    if [ $# -lt 2 ]; then
        echo "Usage: $0 <kustomize_dir> <namespace> [acr_server]"
        echo "Example: $0 k8s/overlays/preview preview-pr-110 acrytsummprd.azurecr.io"
        exit 1
    fi
    
    validate_deployment "$@"
fi
