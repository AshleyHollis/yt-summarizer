#!/bin/bash
# =============================================================================
# Get AKS Ingress IP
# =============================================================================
# PURPOSE:
#   Gets the external IP of the AKS ingress controller using kubectl
#
# INPUTS (via environment variables):
#   INGRESS_NAMESPACE    Namespace where ingress controller is deployed
#   INGRESS_SERVICE      Ingress controller service name
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   ip                   External IP address of the ingress controller
#
# LOGIC:
#   1. Query kubernetes service for LoadBalancer external IP
#   2. If IP not found, emit warning and output empty value
#   3. If IP found, output to GITHUB_OUTPUT
#
# =============================================================================
set -euo pipefail

INGRESS_IP=$(kubectl get svc \
  -n "${INGRESS_NAMESPACE}" \
  "${INGRESS_SERVICE}" \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

if [ -z "${INGRESS_IP}" ]; then
  echo "::warning::Ingress IP not found"
  echo "ip=" >> "$GITHUB_OUTPUT"
else
  echo "Found Ingress IP: ${INGRESS_IP}"
  echo "ip=${INGRESS_IP}" >> "$GITHUB_OUTPUT"
fi
