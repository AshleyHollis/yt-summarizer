# Gateway & HTTPRoute Troubleshooting Runbook

## Overview

This runbook covers troubleshooting for NGINX Gateway Fabric and Gateway API HTTPRoutes used by preview, staging, and production traffic.

## Key Resources

- GatewayClass: `nginx`
- Gateway: `main-gateway` in `gateway-system`
- Wildcard certificate: `yt-summarizer-wildcard-tls`

## Quick Status Checks

```bash
kubectl get gatewayclass
kubectl get gateway -n gateway-system
kubectl get httproute -A
```

## Gateway Not Programmed

**Symptom:** `PROGRAMMED=False` or no external IP.

```bash
kubectl describe gateway main-gateway -n gateway-system
kubectl get svc -n gateway-system
kubectl logs -n gateway-system -l app.kubernetes.io/name=nginx-gateway-fabric --tail=200
```

**Common Causes**:

- GatewayClass not installed or controller not running
- LoadBalancer provisioning failure (check Azure events)
- TLS secret missing or invalid

## HTTPRoute Not Attached

**Symptom:** HTTPRoute status shows `Accepted=False` or `ResolvedRefs=False`.

```bash
kubectl describe httproute api-route -n <namespace>
```

**Checks**:

- `parentRefs` match `main-gateway` in `gateway-system`
- Gateway listener hostname matches the route hostname
- Backend service exists in the same namespace

## TLS Certificate Errors

**Symptom:** HTTPS requests fail or browser shows certificate warnings.

```bash
kubectl get secret yt-summarizer-wildcard-tls -n gateway-system
kubectl describe certificate yt-summarizer-wildcard -n gateway-system
```

**Resolution**:

- Ensure certificate is `READY=True`
- Confirm Gateway listener references `yt-summarizer-wildcard-tls`
- Restart Gateway controller if certificate was recently rotated

```bash
kubectl rollout restart deployment ngf-nginx-gateway-fabric -n gateway-system
```

## 404 or Routing Errors

**Symptom:** Hostname resolves but returns 404.

```bash
kubectl describe httproute api-route -n <namespace>
kubectl get endpoints -n <namespace>
```

**Resolution**:

- Verify backend service name/port in HTTPRoute
- Confirm service endpoints exist
- Check Gateway controller logs for attachment errors

## Debug Checklist

- GatewayClass installed and controller running
- Gateway `PROGRAMMED=True` with external IP
- Wildcard certificate ready and secret present
- HTTPRoute accepted and attached
- DNS points to Gateway IP

## References

- https://gateway-api.sigs.k8s.io/
- https://docs.nginx.com/nginx-gateway-fabric/

## Change Log

- **2026-01-17:** Initial Gateway troubleshooting runbook
