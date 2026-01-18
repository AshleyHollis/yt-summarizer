# Certificate Validation Guide

This document explains the different approaches to TLS certificate validation used in this repository's GitHub Actions workflows.

## Overview

There are **two complementary approaches** to certificate validation, each serving a different purpose:

1. **Kubernetes Certificate Resource Validation** (kubectl-based)
2. **Live TLS Certificate Validation** (OpenSSL-based)

## When to Use Each Approach

### 1. Kubernetes Certificate Resource Validation

**Purpose**: Verify that cert-manager has successfully provisioned a certificate in the cluster.

**Use Cases**:
- Preview environment setup validation
- Pre-flight checks before attempting external connections
- Detecting cert-manager provisioning issues
- Identifying Let's Encrypt rate limiting

**How it Works**:
- Checks the Kubernetes Certificate custom resource status
- Uses `kubectl get certificate` to read cert-manager status
- Validates the `.status.conditions[?(@.type=="Ready")].status` field
- Does NOT validate the actual certificate being served

**Actions**:
- `.github/actions/health-check-preview/check-gateway-cert.sh`

**Example**:
```bash
kubectl get certificate yt-summarizer-wildcard -n gateway-system \
  -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'
```

**When to Use**:
- ✅ Preview environment health checks (before external access)
- ✅ Detecting rate limit issues early
- ✅ Validating cert-manager configuration
- ❌ NOT for production verification (doesn't validate actual served cert)

### 2. Live TLS Certificate Validation

**Purpose**: Verify the actual certificate being served by a live endpoint.

**Use Cases**:
- Production deployment verification
- Post-deployment smoke tests
- Validating certificate expiry dates
- Verifying certificate issuer (Let's Encrypt vs staging vs other)

**How it Works**:
- Connects to `host:443` using OpenSSL
- Retrieves the actual certificate chain being served
- Validates certificate dates and expiry
- Checks certificate will be valid for at least 7 days
- Shows issuer information

**Actions**:
- `.github/actions/verify-certificate/verify-tls.sh`
- `.github/actions/verify-certificate/action.yml`

**Example**:
```bash
echo | openssl s_client -connect api.example.com:443 \
  -servername api.example.com 2>/dev/null | openssl x509 -noout -dates
```

**When to Use**:
- ✅ Production deployment verification
- ✅ Validating actual certificate being served
- ✅ Checking certificate expiry warnings
- ✅ Post-deployment smoke tests
- ❌ NOT for preview environments (may not be accessible yet)

## Comparison Table

| Feature | kubectl Validation | OpenSSL Validation |
|---------|-------------------|-------------------|
| **What it checks** | K8s Certificate resource | Actual served certificate |
| **Requires connectivity** | No (cluster-internal) | Yes (external HTTPS) |
| **Detects rate limits** | Yes | No |
| **Validates expiry** | No (only status) | Yes (actual dates) |
| **Shows issuer** | No | Yes |
| **Use in preview** | ✅ Yes | ❌ No (may not be ready) |
| **Use in production** | ⚠️ Limited value | ✅ Yes |
| **Fail-fast** | Yes | Yes |

## Workflow Integration

### Preview Environment Workflow

```yaml
# Step 1: Check cert-manager provisioned the certificate
- name: Check gateway certificate readiness
  run: .github/actions/health-check-preview/check-gateway-cert.sh

# Step 2: Wait for DNS propagation
- name: Wait for DNS propagation
  run: sleep 30

# Step 3: Check external health (includes TLS handshake)
- uses: ./.github/actions/health-check
  with:
    url: https://api.preview-pr-4.example.com/health/live
```

### Production Deployment Workflow

```yaml
# Step 1: Check API is healthy (includes TLS handshake)
- uses: ./.github/actions/health-check
  with:
    url: https://api.yt-summarizer.apps.ashleyhollis.com/health/live

# Step 2: Validate actual certificate being served
- uses: ./.github/actions/verify-certificate
  with:
    host: api.yt-summarizer.apps.ashleyhollis.com
```

## Common Issues

### Let's Encrypt Rate Limiting

**Symptom**: kubectl validation shows "rateLimited" in certificate message

**Solution**:
- Wait for rate limit to expire (168 hours)
- Use Let's Encrypt staging environment for testing
- Reduce number of preview environments created

**Detection**: Only visible via kubectl validation (check-gateway-cert.sh)

### Certificate Expired

**Symptom**: OpenSSL validation shows certificate is expired

**Solution**:
- Check cert-manager renewal configuration
- Verify ACME challenge configuration
- Check gateway-system namespace for cert-manager logs

**Detection**: Only visible via OpenSSL validation (verify-tls.sh)

### Certificate Not Ready vs Not Valid

**kubectl shows "Ready: False"**:
- cert-manager hasn't provisioned the certificate yet
- May be rate limited, misconfigured, or ACME challenge failing
- External access will NOT work

**OpenSSL shows expired/invalid**:
- Certificate exists but is expired or invalid
- May indicate renewal failure
- External access may partially work (browser warnings)

## Best Practices

1. **Preview Environments**: Use kubectl validation first (fail-fast), then check external connectivity
2. **Production**: Use OpenSSL validation after deployment to verify actual certificate
3. **Diagnostics**: Use both approaches to distinguish cert-manager issues from certificate issues
4. **Rate Limits**: Always check kubectl validation in preview environments to detect rate limiting early
5. **Expiry Warnings**: Use OpenSSL validation in production to get 7-day expiry warnings

## Implementation Notes

### Removed Duplication

Previously, `check-dns-and-tls.sh` duplicated the kubectl certificate check logic. This has been:
- ✅ Removed from `check-dns-and-tls.sh` (now `check-dns-resolution.sh`)
- ✅ Consolidated into `check-gateway-cert.sh`
- ✅ Called separately in action.yml with clear separation of concerns

### File Locations

```
.github/actions/
├── verify-certificate/
│   ├── action.yml          # Production certificate validation (OpenSSL)
│   └── verify-tls.sh       # OpenSSL implementation
│
└── health-check-preview/
    ├── action.yml          # Preview environment health checks
    ├── check-gateway-cert.sh       # K8s certificate validation (kubectl)
    ├── check-dns-resolution.sh     # DNS resolution checks
    └── check-external-diagnostics.sh  # Failure diagnostics
```

## References

- cert-manager docs: https://cert-manager.io/docs/
- Let's Encrypt rate limits: https://letsencrypt.org/docs/rate-limits/
- OpenSSL s_client: https://www.openssl.org/docs/man1.1.1/man1/s_client.html
- Gateway API: https://gateway-api.sigs.k8s.io/
