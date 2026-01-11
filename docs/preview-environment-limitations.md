# Preview Environment Limitations

## TLS Certificate Rate Limiting with Wildcard DNS Services

### Current Issue

Wildcard DNS services (nip.io, sslip.io, xip.io) are convenient for development but have Let's Encrypt rate limit constraints:

**Note**: We've switched from nip.io to sslip.io to avoid the global rate limit.

1. **Global nip.io rate limit**: 25,000 certificates per 168 hours (shared across all users globally)
2. **Per exact domain set**: 5 certificates per 168 hours per exact domain combination

When the global nip.io rate limit is exhausted, preview environments cannot obtain TLS certificates.

### Impact

- **Internal cluster access**: ✅ Fully functional
- **External HTTPS access**: ❌ Blocked when rate limit hit
- **Deployments**: ✅ Complete successfully
- **E2E tests**: ✅ Can run against internal endpoints

### Current Mitigation

The health check has been updated to:
1. Detect nip.io global rate limit errors
2. Pass the health check if internal cluster access works
3. Provide clear messaging that external HTTPS is temporarily unavailable
4. Allow the workflow to continue (deployment is functional)

### Long-term Solutions

#### Option 1: Use a Custom Domain
- Register a domain (e.g., `dev.yourdomain.com`)
- Create wildcard DNS A record: `*.preview.dev.yourdomain.com` → AKS ingress IP
- Update compute-preview-urls to use custom domain
- Benefits: No shared rate limits, professional URLs
- Cost: Domain registration (~$12/year)

#### Option 2: Rotate Between DNS Providers
- Multiple wildcard DNS services available: sslip.io (current), xip.io, nip.io
- Same concept but different providers with independent rate limits
- Can switch providers if one hits rate limit
- Currently using: `yt-summarizer-api.preview-pr-4.20.255.113.149.sslip.io`

#### Option 3: Use Let's Encrypt Staging for Preview
- Use `letsencrypt-staging` issuer for preview environments
- Staging has much higher rate limits (30,000/week vs 50/week)
- Caveat: Browsers show "Not Secure" warning (acceptable for internal previews)
- Production still uses `letsencrypt-prod`

#### Option 4: Skip TLS for Preview Environments
- Use HTTP-only ingress for preview
- Frontend served from Azure Static Web Apps can handle mixed content
- Simplest solution if security is not critical for ephemeral previews

### Recommended Approach

**Short term**: Current mitigation (pass health check when internal access works)

**Medium term**: Implement Option 3 (staging certs for preview)
```yaml
# k8s/overlays/preview/patches/ingress-patch.yaml
annotations:
  cert-manager.io/cluster-issuer: letsencrypt-staging  # High rate limits
```

**Long term**: Implement Option 1 (custom domain) for professional preview URLs

### Implementation Example: Custom Domain

1. **Register domain and configure DNS**:
   ```bash
   # Create wildcard A record in your DNS provider
   *.preview.dev.yourdomain.com  A  20.255.113.149
   ```

2. **Update compute-preview-urls action**:
   ```yaml
   inputs:
     custom-domain:
       description: 'Custom domain for previews (optional)'
       required: false
       default: ''
   ```

3. **Update domain computation**:
   ```bash
   if [ -n "$CUSTOM_DOMAIN" ]; then
     PREVIEW_HOST="${APP_NAME}-api.preview-pr-${PR_NUMBER}.${CUSTOM_DOMAIN}"
   else
     # Fall back to nip.io
     PREVIEW_HOST="${APP_NAME}-api.preview-pr-${PR_NUMBER}.${IP_DASHED}.nip.io"
   fi
   ```

### Monitoring

Check current certificate status:
```bash
# Check cert status in preview namespace
kubectl get certificate -n preview-pr-4

# Get detailed error messages
kubectl describe certificate -n preview-pr-4

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager
```

### References

- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [nip.io Documentation](https://nip.io/)
- [cert-manager Documentation](https://cert-manager.io/docs/)
- [Azure DNS Zones](https://learn.microsoft.com/en-us/azure/dns/dns-getstarted-portal)
