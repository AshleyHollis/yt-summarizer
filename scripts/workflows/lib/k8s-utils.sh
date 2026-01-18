#!/bin/bash
# =============================================================================
# Kubernetes Operations Utilities
# =============================================================================
# Purpose:
#   Provides reusable functions for Kubernetes operations in CI/CD workflows,
#   including deployment verification, pod readiness checks, and debugging
#   operations.
#
# Functions:
#   - kubectl_wait_ready(resource_type, name, timeout)
#                                    Wait for deployment/pod to be ready
#   - kubectl_check_image(namespace, deployment, expected_image)
#                                    Verify image deployed correctly
#   - kubectl_get_deployment(namespace, name)
#                                    Get deployment information
#   - kubectl_get_service(namespace, name)
#                                    Get service information
#   - kubectl_port_forward(namespace, pod, local_port, remote_port)
#                                    Setup port forwarding
#   - kubectl_get_pod_logs(namespace, pod, container)
#                                    Get pod logs for debugging
#   - kubectl_get_events(namespace, limit)
#                                    Get recent K8s events
#
# Usage:
#   source ./lib/k8s-utils.sh
#   kubectl_wait_ready "deployment" "api" 300
#   kubectl_check_image "production" "api" "sha-abc1234"
#   kubectl_get_pod_logs "production" "api-xyz" "app"
#
# Dependencies:
#   - kubectl: Must be configured and authenticated
#   - KUBECONFIG: Must point to valid K8s cluster
#
# Exit codes:
#   Functions return 0 for success, 1 for failure
#
# =============================================================================

# Wait for a Kubernetes resource to be ready
# Args:
#   $1: Resource type (deployment|statefulset|daemonset|pod) (required)
#   $2: Resource name (required)
#   $3: Timeout in seconds (optional, defaults to 300)
#   $4: Namespace (optional, defaults to default)
# Returns: 0 if ready, 1 if timeout
# Example: kubectl_wait_ready "deployment" "api-service" 300 "production"
kubectl_wait_ready() {
  local resource_type="${1:-}"
  local resource_name="${2:-}"
  local timeout="${3:-300}"
  local namespace="${4:-default}"

  if [ -z "$resource_type" ] || [ -z "$resource_name" ]; then
    echo "::error::kubectl_wait_ready requires resource_type and name"
    return 1
  fi

  echo "⏳ Waiting for $resource_type/$resource_name to be ready..."

  if kubectl wait --for=condition=available \
    --timeout="${timeout}s" \
    "$resource_type/$resource_name" \
    -n "$namespace" 2>/dev/null; then
    echo "✅ $resource_type/$resource_name is ready"
    return 0
  else
    echo "::error::Timeout waiting for $resource_type/$resource_name"
    return 1
  fi
}

# Check that expected image was deployed to a deployment
# Args:
#   $1: Namespace (required)
#   $2: Deployment name (required)
#   $3: Expected image tag (required)
# Returns: 0 if image matches, 1 if mismatch
# Example: kubectl_check_image "production" "api" "sha-abc1234"
kubectl_check_image() {
  local namespace="${1:-}"
  local deployment="${2:-}"
  local expected_image="${3:-}"

  if [ -z "$namespace" ] || [ -z "$deployment" ] || [ -z "$expected_image" ]; then
    echo "::error::kubectl_check_image requires namespace, deployment, and image"
    return 1
  fi

  echo "🔍 Checking deployed image for $deployment..."

  # Get the actual image deployed
  local actual_image
  actual_image=$(kubectl get deployment "$deployment" \
    -n "$namespace" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null) || {
    echo "::error::Failed to get image for deployment: $deployment"
    return 1
  }

  if [[ "$actual_image" == *"$expected_image"* ]]; then
    echo "✅ Correct image deployed: $actual_image"
    return 0
  else
    echo "::error::Image mismatch for $deployment"
    echo "::error::Expected: $expected_image"
    echo "::error::Actual: $actual_image"
    return 1
  fi
}

# Get deployment information
# Args:
#   $1: Namespace (required)
#   $2: Deployment name (required)
# Returns: Deployment info on stdout
# Example: info=$(kubectl_get_deployment "production" "api")
kubectl_get_deployment() {
  local namespace="${1:-}"
  local name="${2:-}"

  if [ -z "$namespace" ] || [ -z "$name" ]; then
    echo "::error::kubectl_get_deployment requires namespace and name"
    return 1
  fi

  kubectl get deployment "$name" -n "$namespace" -o wide 2>/dev/null || {
    echo "::error::Failed to get deployment: $name"
    return 1
  }
}

# Get service information
# Args:
#   $1: Namespace (required)
#   $2: Service name (required)
# Returns: Service info on stdout
# Example: info=$(kubectl_get_service "production" "api")
kubectl_get_service() {
  local namespace="${1:-}"
  local name="${2:-}"

  if [ -z "$namespace" ] || [ -z "$name" ]; then
    echo "::error::kubectl_get_service requires namespace and name"
    return 1
  fi

  kubectl get service "$name" -n "$namespace" -o wide 2>/dev/null || {
    echo "::error::Failed to get service: $name"
    return 1
  }
}

# Setup port forwarding to a pod
# Args:
#   $1: Namespace (required)
#   $2: Pod name (required)
#   $3: Local port (required)
#   $4: Remote/container port (required)
# Returns: 0 on success (runs in background)
# Example: kubectl_port_forward "production" "api-xyz" 8000 8000
# Note: This runs kubectl port-forward in the background
kubectl_port_forward() {
  local namespace="${1:-}"
  local pod="${2:-}"
  local local_port="${3:-}"
  local remote_port="${4:-}"

  if [ -z "$namespace" ] || [ -z "$pod" ] || [ -z "$local_port" ] \
    || [ -z "$remote_port" ]; then
    echo "::error::kubectl_port_forward requires namespace, pod, and ports"
    return 1
  fi

  echo "🔌 Setting up port forward $local_port:$remote_port for $pod..."

  kubectl port-forward \
    -n "$namespace" \
    "pod/$pod" \
    "${local_port}:${remote_port}" \
    >/dev/null 2>&1 &

  sleep 2
  echo "✅ Port forwarding established"
  return 0
}

# Get logs from a pod container
# Args:
#   $1: Namespace (required)
#   $2: Pod name (required)
#   $3: Container name (optional, defaults to first container)
#   $4: Number of lines (optional, defaults to 50)
# Returns: Logs on stdout
# Example: logs=$(kubectl_get_pod_logs "production" "api-xyz" "app" 100)
kubectl_get_pod_logs() {
  local namespace="${1:-}"
  local pod="${2:-}"
  local container="${3:-}"
  local lines="${4:-50}"

  if [ -z "$namespace" ] || [ -z "$pod" ]; then
    echo "::error::kubectl_get_pod_logs requires namespace and pod name"
    return 1
  fi

  local kubectl_args="logs $pod -n $namespace --tail=$lines"

  if [ -n "$container" ]; then
    kubectl_args="$kubectl_args -c $container"
  fi

  kubectl $kubectl_args 2>/dev/null || {
    echo "::error::Failed to get logs for pod: $pod"
    return 1
  }
}

# Get recent Kubernetes events
# Args:
#   $1: Namespace (optional, defaults to all namespaces)
#   $2: Number of events to show (optional, defaults to 20)
# Returns: Event list on stdout
# Example: events=$(kubectl_get_events "production" 50)
kubectl_get_events() {
  local namespace="${1:-}"
  local limit="${2:-20}"

  local kubectl_args="get events"

  if [ -n "$namespace" ]; then
    kubectl_args="$kubectl_args -n $namespace"
  else
    kubectl_args="$kubectl_args -A"
  fi

  kubectl_args="$kubectl_args --sort-by='.lastTimestamp' | tail -n $limit"

  kubectl $kubectl_args 2>/dev/null || {
    echo "::error::Failed to get events"
    return 1
  }
}
