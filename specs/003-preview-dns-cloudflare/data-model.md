# Data Model: Preview DNS/TLS Migration to Cloudflare

**Feature**: 003-preview-dns-cloudflare  
**Date**: January 11, 2026  
**Status**: Complete

---

## Overview

This document defines the Kubernetes resources and their relationships for the Gateway API, cert-manager, and ExternalDNS infrastructure.

---

## Kubernetes Resources

### 1. GatewayClass

**Purpose**: Defines the controller that manages Gateway resources.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: nginx
spec:
  controllerName: gateway.nginx.org/nginx-gateway-controller
  description: NGINX Gateway Fabric controller for yt-summarizer
```

**Relationships**:
- Referenced by: Gateway

---

### 2. Gateway

**Purpose**: Defines listeners for TLS termination and HTTP routing.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: main-gateway
  namespace: gateway-system
  annotations:
    external-dns.alpha.kubernetes.io/hostname: "*.yt-summarizer.apps.ashleyhollis.com"
spec:
  gatewayClassName: nginx
  listeners:
    - name: https-yt-summarizer
      port: 443
      protocol: HTTPS
      hostname: "*.yt-summarizer.apps.ashleyhollis.com"
      tls:
        mode: Terminate
        certificateRefs:
          - name: yt-summarizer-wildcard-tls
            kind: Secret
      allowedRoutes:
        namespaces:
          from: All
    - name: http-yt-summarizer
      port: 80
      protocol: HTTP
      hostname: "*.yt-summarizer.apps.ashleyhollis.com"
      allowedRoutes:
        namespaces:
          from: All
```

**Relationships**:
- References: GatewayClass (`nginx`), Secret (`yt-summarizer-wildcard-tls`)
- Referenced by: HTTPRoute (via `parentRefs`)

---

### 3. Certificate (Wildcard)

**Purpose**: Requests a wildcard TLS certificate from Let's Encrypt via DNS-01.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: yt-summarizer-wildcard
  namespace: gateway-system
spec:
  secretName: yt-summarizer-wildcard-tls
  duration: 2160h    # 90 days
  renewBefore: 720h  # 30 days
  issuerRef:
    name: letsencrypt-cloudflare
    kind: ClusterIssuer
  dnsNames:
    - "*.yt-summarizer.apps.ashleyhollis.com"
    - "yt-summarizer.apps.ashleyhollis.com"
```

**Relationships**:
- References: ClusterIssuer (`letsencrypt-cloudflare`)
- Creates: Secret (`yt-summarizer-wildcard-tls`)

---

### 4. ClusterIssuer (DNS-01 Cloudflare)

**Purpose**: Configures ACME DNS-01 challenge via Cloudflare for certificate issuance.

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-cloudflare
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ops@ashleyhollis.com
    privateKeySecretRef:
      name: letsencrypt-cloudflare-key
    solvers:
      - dns01:
          cloudflare:
            apiTokenSecretRef:
              name: cloudflare-api-token
              key: api-token
        selector:
          dnsZones:
            - "apps.ashleyhollis.com"
```

**Relationships**:
- References: Secret (`cloudflare-api-token` in `cert-manager` namespace)
- Creates: Secret (`letsencrypt-cloudflare-key`)
- Referenced by: Certificate

---

### 5. HTTPRoute (Production)

**Purpose**: Routes production API traffic to the API service.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api-route
  namespace: yt-summarizer
spec:
  parentRefs:
    - name: main-gateway
      namespace: gateway-system
  hostnames:
    - "api.yt-summarizer.apps.ashleyhollis.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: api
          port: 80
```

**Relationships**:
- References: Gateway (`main-gateway`), Service (`api`)
- Triggers: ExternalDNS record creation

---

### 6. HTTPRoute (Preview Template)

**Purpose**: Routes preview API traffic to the preview API service.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: api-route
  namespace: preview-pr-${PR_NUMBER}
spec:
  parentRefs:
    - name: main-gateway
      namespace: gateway-system
  hostnames:
    - "api-pr-${PR_NUMBER}.yt-summarizer.apps.ashleyhollis.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /
      backendRefs:
        - name: api
          port: 80
```

**Variables** (substituted by Kustomize/CI):
- `${PR_NUMBER}`: Pull request number

---

### 7. ExternalDNS Deployment

**Purpose**: Automatically manages DNS records in Cloudflare based on HTTPRoute hostnames.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
  namespace: gateway-system
spec:
  replicas: 1
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.14.0
          args:
            - --source=gateway-httproute
            - --provider=cloudflare
            - --cloudflare-proxied=false
            - --domain-filter=apps.ashleyhollis.com
            - --policy=sync
            - --registry=txt
            - --txt-owner-id=yt-summarizer-aks
            - --interval=30s
            - --log-level=info
          env:
            - name: CF_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: cloudflare-api-token
                  key: api-token
```

**Relationships**:
- References: Secret (`cloudflare-api-token`), ServiceAccount (`external-dns`)
- Watches: HTTPRoute (all namespaces)
- Manages: Cloudflare DNS A records

---

### 8. ExternalDNS RBAC

**Purpose**: Grants ExternalDNS permission to read HTTPRoutes across all namespaces.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-dns
  namespace: gateway-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
rules:
  - apiGroups: ["gateway.networking.k8s.io"]
    resources: ["gateways", "httproutes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["endpoints", "services"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: external-dns
subjects:
  - kind: ServiceAccount
    name: external-dns
    namespace: gateway-system
roleRef:
  kind: ClusterRole
  name: external-dns
  apiGroup: rbac.authorization.k8s.io
```

---

### 9. Cloudflare API Token Secret (via ExternalSecret)

**Purpose**: Provides Cloudflare API token to cert-manager and ExternalDNS.

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: cloudflare-api-token
  namespace: gateway-system
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: azure-keyvault
    kind: ClusterSecretStore
  target:
    name: cloudflare-api-token
    creationPolicy: Owner
  data:
    - secretKey: api-token
      remoteRef:
        key: cloudflare-api-token
```

---

## Resource Relationships Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      ClusterSecretStore                          │
│                     (azure-keyvault)                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │ references
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ExternalSecret                              │
│               (cloudflare-api-token)                             │
│                  gateway-system ns                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │ creates
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Secret                                   │
│                (cloudflare-api-token)                            │
│                  gateway-system ns                               │
└───────────────────────────┬─────────────────────────────────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
            ▼                               ▼
┌─────────────────────┐         ┌─────────────────────────────────┐
│    ClusterIssuer    │         │        ExternalDNS              │
│(letsencrypt-cloud)  │         │      gateway-system ns          │
└──────────┬──────────┘         └─────────────────────────────────┘
           │ references                     │ watches
           ▼                                ▼
┌─────────────────────┐         ┌─────────────────────────────────┐
│     Certificate     │         │         HTTPRoute               │
│ (yt-summarizer-wc)  │         │   (api-route in app ns)         │
│  gateway-system ns  │         └─────────────────────────────────┘
└──────────┬──────────┘                     │
           │ creates                        │ parentRefs
           ▼                                ▼
┌─────────────────────┐         ┌─────────────────────────────────┐
│       Secret        │◄────────│          Gateway                │
│(yt-summarizer-wc-tls│         │       (main-gateway)            │
│  gateway-system ns  │         │      gateway-system ns          │
└─────────────────────┘         └─────────────────────────────────┘
                                            │ references
                                            ▼
                                ┌─────────────────────────────────┐
                                │        GatewayClass             │
                                │          (nginx)                │
                                └─────────────────────────────────┘
```

---

## State Transitions

### Preview Lifecycle

```
PR Opened
    │
    ▼
┌─────────────────────────────────────────┐
│ 1. GitHub Actions creates namespace     │
│    preview-pr-N                         │
└─────────────────────┬───────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ 2. Deploy API, Workers, HTTPRoute       │
│    HTTPRoute references main-gateway    │
└─────────────────────┬───────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ 3. ExternalDNS detects HTTPRoute        │
│    Creates A record in Cloudflare       │
│    api-pr-N.yt-summarizer.apps...       │
└─────────────────────┬───────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ 4. Gateway routes traffic using         │
│    wildcard cert (already exists)       │
└─────────────────────┬───────────────────┘
                      │
                      ▼
              Preview is live!

PR Closed/Merged
    │
    ▼
┌─────────────────────────────────────────┐
│ 1. GitHub Actions deletes namespace     │
│    preview-pr-N                         │
└─────────────────────┬───────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ 2. HTTPRoute deleted (cascade)          │
└─────────────────────┬───────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────┐
│ 3. ExternalDNS detects deletion         │
│    Removes A record from Cloudflare     │
└─────────────────────┬───────────────────┘
                      │
                      ▼
              Preview cleaned up!
```

---

## Validation Rules

### Gateway

- Must be in `gateway-system` namespace
- Must reference existing GatewayClass
- Must reference existing TLS secret
- Listener hostname must match certificate SAN

### HTTPRoute

- Must reference existing Gateway via `parentRefs`
- Hostname must be covered by Gateway listener hostname pattern
- Backend service must exist in same namespace

### Certificate

- Must reference existing ClusterIssuer
- DNS names must be resolvable zones in Cloudflare
- Must include wildcard and optionally base domain

### ExternalDNS

- Domain filter must match managed zone
- TXT owner ID must be unique per cluster
- Policy must be `sync` for automatic cleanup
