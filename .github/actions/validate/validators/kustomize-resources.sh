#!/usr/bin/env bash
# =============================================================================
# Kustomize Resources Validator
# =============================================================================
# Validates that kustomize manifest CPU/memory requests don't exceed AKS quotas
# Optionally queries AKS cluster for actual quota limits

set -uo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
OVERLAY_PATHS_STR="${OVERLAY_PATHS:-}"
MAX_CPU_MILLICORES="${MAX_CPU_MILLICORES:-}"
MAX_MEMORY_MI="${MAX_MEMORY_MI:-}"
AKS_RESOURCE_GROUP="${AKS_RESOURCE_GROUP:-}"
AKS_CLUSTER_NAME="${AKS_CLUSTER_NAME:-}"
AKS_NAMESPACE="${AKS_NAMESPACE:-default}"
QUERY_AKS="${QUERY_AKS:-false}"

# Validation header
log_info "Kustomize Resources Validator"
echo ""

# Check prerequisites
require_command "kustomize" "https://kubectl.docs.kubernetes.io/installation/kustomize/"

# If QUERY_AKS is enabled, check for Azure CLI and kubectl
if [[ "$QUERY_AKS" == "true" ]]; then
    require_command "az" "https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    require_command "kubectl" "https://kubernetes.io/docs/tasks/tools/"
    
    if [[ -z "$AKS_RESOURCE_GROUP" ]] || [[ -z "$AKS_CLUSTER_NAME" ]]; then
        log_error "AKS_RESOURCE_GROUP and AKS_CLUSTER_NAME required when QUERY_AKS=true"
        exit 1
    fi
    
    log_info "Querying AKS cluster for resource quotas..."
    
    # Get AKS credentials
    if ! az aks get-credentials --resource-group "$AKS_RESOURCE_GROUP" --name "$AKS_CLUSTER_NAME" --overwrite-existing &>/dev/null; then
        log_error "Failed to get AKS credentials"
        exit 1
    fi
    
    # Query ResourceQuota in namespace
    quota_output=$(kubectl get resourcequota -n "$AKS_NAMESPACE" -o json 2>/dev/null || echo "{}")
    
    if [[ "$quota_output" != "{}" ]] && [[ -n "$quota_output" ]]; then
        # Extract CPU and memory limits (if set)
        cpu_limit=$(echo "$quota_output" | jq -r '.items[0].spec.hard["requests.cpu"] // empty' 2>/dev/null || echo "")
        memory_limit=$(echo "$quota_output" | jq -r '.items[0].spec.hard["requests.memory"] // empty' 2>/dev/null || echo "")
        
        if [[ -n "$cpu_limit" ]]; then
            # Convert CPU limit to millicores
            if [[ "$cpu_limit" =~ ^([0-9]+)m$ ]]; then
                MAX_CPU_MILLICORES="${BASH_REMATCH[1]}"
            elif [[ "$cpu_limit" =~ ^([0-9]+)$ ]]; then
                MAX_CPU_MILLICORES=$((${BASH_REMATCH[1]} * 1000))
            fi
            log_info "AKS CPU quota: $cpu_limit (${MAX_CPU_MILLICORES}m)"
        fi
        
        if [[ -n "$memory_limit" ]]; then
            # Convert memory limit to Mi
            if [[ "$memory_limit" =~ ^([0-9]+)Mi$ ]]; then
                MAX_MEMORY_MI="${BASH_REMATCH[1]}"
            elif [[ "$memory_limit" =~ ^([0-9]+)Gi$ ]]; then
                MAX_MEMORY_MI=$((${BASH_REMATCH[1]} * 1024))
            fi
            log_info "AKS memory quota: $memory_limit (${MAX_MEMORY_MI}Mi)"
        fi
    else
        log_warning "No ResourceQuota found in namespace $AKS_NAMESPACE"
    fi
fi

# Check if we have limits to validate against
if [[ -z "$MAX_CPU_MILLICORES" ]] && [[ -z "$MAX_MEMORY_MI" ]]; then
    log_warning "No resource limits specified (MAX_CPU_MILLICORES or MAX_MEMORY_MI)"
    log_warning "Skipping resource validation - set limits or enable QUERY_AKS=true"
    exit 0
fi

# Parse overlay paths
if [[ -z "$OVERLAY_PATHS_STR" ]]; then
    log_error "OVERLAY_PATHS required for resource validation"
    exit 1
fi

IFS=',' read -ra OVERLAY_PATHS <<< "$OVERLAY_PATHS_STR"

ERRORS=0

# Function to parse CPU string to millicores
parse_cpu() {
    local cpu_str="$1"
    [[ -z "$cpu_str" ]] && echo "0" && return
    
    if [[ "$cpu_str" =~ ^([0-9]+)m$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$cpu_str" =~ ^([0-9.]+)$ ]]; then
        # Convert to millicores (e.g., "0.5" -> 500)
        echo "$(awk "BEGIN {print int(${BASH_REMATCH[1]} * 1000)}")"
    else
        log_warning "Unrecognized CPU format: $cpu_str"
        echo "0"
    fi
}

# Function to parse memory string to Mi
parse_memory() {
    local mem_str="$1"
    [[ -z "$mem_str" ]] && echo "0" && return
    
    if [[ "$mem_str" =~ ^([0-9]+)Mi$ ]]; then
        echo "${BASH_REMATCH[1]}"
    elif [[ "$mem_str" =~ ^([0-9]+)Gi$ ]]; then
        echo "$((${BASH_REMATCH[1]} * 1024))"
    elif [[ "$mem_str" =~ ^([0-9]+)M$ ]]; then
        # MB to Mi (approximately)
        echo "$((${BASH_REMATCH[1]} * 95 / 100))"
    else
        log_warning "Unrecognized memory format: $mem_str"
        echo "0"
    fi
}

# Validate each overlay
for overlay_path in "${OVERLAY_PATHS[@]}"; do
    [[ -z "$overlay_path" ]] && continue
    
    log_info "Validating resources: $overlay_path"
    
    # Build kustomize manifest
    manifest_file="/tmp/kustomize_resources_$$.yaml"
    if ! kustomize build "$overlay_path" > "$manifest_file" 2>&1; then
        log_error "Failed to build kustomize overlay: $overlay_path"
        ERRORS=$((ERRORS + 1))
        rm -f "$manifest_file"
        continue
    fi
    
    # Parse YAML and sum resources
    total_cpu=0
    total_memory=0
    
    # Use Python for YAML parsing (more reliable than bash)
    python3 - "$manifest_file" "$MAX_CPU_MILLICORES" "$MAX_MEMORY_MI" <<'EOF'
import sys
import yaml

manifest_file = sys.argv[1]
max_cpu = int(sys.argv[2]) if sys.argv[2] else 0
max_mem = int(sys.argv[3]) if sys.argv[3] else 0

def parse_cpu(cpu_str):
    if not cpu_str:
        return 0
    cpu_str = str(cpu_str)
    if cpu_str.endswith('m'):
        return int(cpu_str[:-1])
    try:
        return int(float(cpu_str) * 1000)
    except ValueError:
        return 0

def parse_memory(mem_str):
    if not mem_str:
        return 0
    mem_str = str(mem_str)
    if mem_str.endswith('Mi'):
        return int(mem_str[:-2])
    if mem_str.endswith('Gi'):
        return int(mem_str[:-2]) * 1024
    if mem_str.endswith('M'):
        return int(mem_str[:-1]) * 95 // 100
    return 0

total_cpu = 0
total_memory = 0
resources = []

with open(manifest_file, 'r') as f:
    docs = list(yaml.safe_load_all(f))
    
for doc in docs:
    if not isinstance(doc, dict):
        continue
    
    kind = doc.get('kind')
    if kind not in ('Deployment', 'StatefulSet', 'DaemonSet', 'ReplicaSet'):
        continue
    
    name = doc.get('metadata', {}).get('name', '<unnamed>')
    replicas = doc.get('spec', {}).get('replicas', 1)
    
    template = doc.get('spec', {}).get('template', {})
    spec = template.get('spec', {})
    containers = spec.get('containers', [])
    
    pod_cpu = 0
    pod_memory = 0
    
    for container in containers:
        requests = container.get('resources', {}).get('requests', {})
        cpu = requests.get('cpu')
        memory = requests.get('memory')
        
        pod_cpu += parse_cpu(cpu)
        pod_memory += parse_memory(memory)
    
    resource_cpu = pod_cpu * replicas
    resource_memory = pod_memory * replicas
    
    total_cpu += resource_cpu
    total_memory += resource_memory
    
    resources.append({
        'kind': kind,
        'name': name,
        'replicas': replicas,
        'pod_cpu_m': pod_cpu,
        'pod_memory_mi': pod_memory,
        'total_cpu_m': resource_cpu,
        'total_memory_mi': resource_memory
    })

# Print results
print(f"TOTAL_CPU={total_cpu}")
print(f"TOTAL_MEMORY={total_memory}")

if resources:
    print("RESOURCES:")
    for r in resources:
        print(f"  {r['kind']}/{r['name']}: replicas={r['replicas']} pod_cpu={r['pod_cpu_m']}m pod_mem={r['pod_memory_mi']}Mi total_cpu={r['total_cpu_m']}m total_mem={r['total_memory_mi']}Mi")

# Validate
exit_code = 0
if max_cpu > 0 and total_cpu > max_cpu:
    print(f"ERROR: Total CPU {total_cpu}m exceeds limit {max_cpu}m", file=sys.stderr)
    exit_code = 1

if max_mem > 0 and total_memory > max_mem:
    print(f"ERROR: Total memory {total_memory}Mi exceeds limit {max_mem}Mi", file=sys.stderr)
    exit_code = 1

sys.exit(exit_code)
EOF
    
    validation_exit=$?
    
    if [[ $validation_exit -ne 0 ]]; then
        log_error "Resource validation failed for $overlay_path"
        ERRORS=$((ERRORS + 1))
    else
        log_success "Resource validation passed for $overlay_path"
    fi
    
    rm -f "$manifest_file"
    echo ""
done

# Summary
echo "=========================================="

if [[ $ERRORS -eq 0 ]]; then
    log_success "All overlays passed resource validation"
    exit 0
else
    log_error "Found $ERRORS overlay(s) exceeding resource limits"
    exit 1
fi
