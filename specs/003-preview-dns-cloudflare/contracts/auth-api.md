# Auth API Contract

**Feature**: 003-preview-dns-cloudflare  
**Date**: January 11, 2026  
**Status**: Draft

---

## Overview

This document defines the Auth0 BFF (Backend-for-Frontend) API contract for authentication endpoints owned by the API service.

---

## Base URL

| Environment | Base URL |
|-------------|----------|
| Production | `https://api.yt-summarizer.apps.ashleyhollis.com` |
| Staging | `https://api-stg.yt-summarizer.apps.ashleyhollis.com` |
| Preview | `https://api-pr-{N}.yt-summarizer.apps.ashleyhollis.com` |

---

## Endpoints

### 1. Login Initiation

**Endpoint**: `GET /api/auth/login`

**Description**: Initiates Auth0 authorization code flow. Redirects user to Auth0 login page.

**Query Parameters**:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `returnTo` | string | No | URL to redirect after successful login. Must be an allowed origin. Defaults to frontend origin. |

**Responses**:

| Status | Description |
|--------|-------------|
| 302 | Redirect to Auth0 authorization endpoint |

**Example**:
```
GET /api/auth/login?returnTo=https://web.yt-summarizer.apps.ashleyhollis.com/dashboard
```

**Redirect Location**:
```
https://{AUTH0_DOMAIN}/authorize?
  response_type=code&
  client_id={CLIENT_ID}&
  redirect_uri=https://api.yt-summarizer.apps.ashleyhollis.com/api/auth/callback/auth0&
  scope=openid profile email&
  state={encrypted_state}
```

---

### 2. Auth0 Callback

**Endpoint**: `GET /api/auth/callback/auth0`

**Description**: Handles Auth0 callback after user authentication. Exchanges authorization code for tokens and sets session cookie.

**Query Parameters** (provided by Auth0):

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `code` | string | Yes | Authorization code from Auth0 |
| `state` | string | Yes | Encrypted state containing returnTo URL |

**Responses**:

| Status | Description |
|--------|-------------|
| 302 | Redirect to `returnTo` URL with session cookie set |
| 400 | Invalid state or missing code |
| 500 | Token exchange failed |

**Set-Cookie Header**:
```
Set-Cookie: session={encrypted_session};
  HttpOnly;
  Secure;
  Path=/;
  SameSite=None;
  Max-Age=86400
```

**Cookie Properties**:

| Property | Value | Rationale |
|----------|-------|-----------|
| `HttpOnly` | true | Prevent XSS access to cookie |
| `Secure` | true | HTTPS only |
| `Path` | `/` | Available to all API paths |
| `SameSite` | `None` | Required for cross-origin SWA requests |
| `Domain` | (not set) | Host-only cookie |
| `Max-Age` | 86400 | 24 hours (configurable) |

---

### 3. Logout

**Endpoint**: `POST /api/auth/logout`

**Description**: Clears the session cookie (local logout). Does not perform Auth0 global logout.

**Request Body**: None

**Responses**:

| Status | Description |
|--------|-------------|
| 200 | Logout successful |
| 401 | Not authenticated (no session cookie) |

**Response Body**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

**Set-Cookie Header**:
```
Set-Cookie: session=;
  HttpOnly;
  Secure;
  Path=/;
  SameSite=None;
  Max-Age=0
```

---

### 4. Get Current User

**Endpoint**: `GET /api/auth/me`

**Description**: Returns current authenticated user information. Requires valid session cookie.

**Request Headers**:

| Header | Required | Description |
|--------|----------|-------------|
| `Cookie` | Yes | Session cookie |

**Responses**:

| Status | Description |
|--------|-------------|
| 200 | User info returned |
| 401 | Not authenticated |

**Response Body** (200):
```json
{
  "sub": "auth0|abc123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://...",
  "updated_at": "2026-01-11T10:00:00.000Z"
}
```

**Response Body** (401):
```json
{
  "detail": "Not authenticated"
}
```

---

## CORS Configuration

### Allowed Origins

```python
ALLOWED_ORIGINS = [
    # Production web
    "https://web.yt-summarizer.apps.ashleyhollis.com",

    # Staging web  
    "https://web-stg.yt-summarizer.apps.ashleyhollis.com",

    # SWA preview domains (regex pattern in implementation)
    # Pattern: https://*.azurestaticapps.net
]
```

### CORS Headers

**Preflight Request** (`OPTIONS`):
```
Access-Control-Allow-Origin: {reflected origin if in allowlist}
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 86400
```

**Actual Request**:
```
Access-Control-Allow-Origin: {reflected origin if in allowlist}
Access-Control-Allow-Credentials: true
```

### Security Constraints

1. **No wildcard with credentials**: `Access-Control-Allow-Origin: *` MUST NOT be used when `Access-Control-Allow-Credentials: true`
2. **Origin reflection**: When request origin is in allowlist, reflect it exactly in response
3. **Strict allowlist**: Only explicitly allowed origins receive CORS headers

---

## Error Responses

All error responses follow this format:

```json
{
  "detail": "Error message describing the issue"
}
```

### Common Errors

| Status | Detail | Cause |
|--------|--------|-------|
| 400 | Invalid state parameter | Tampered or expired state |
| 400 | Missing authorization code | Auth0 callback without code |
| 401 | Not authenticated | Missing or invalid session cookie |
| 403 | Origin not allowed | CORS violation |
| 500 | Token exchange failed | Auth0 API error |
| 500 | Session creation failed | Internal error |

---

## OpenAPI Specification

```yaml
openapi: 3.0.3
info:
  title: YT Summarizer Auth API
  version: 1.0.0
  description: Authentication endpoints for Auth0 BFF pattern
servers:
  - url: https://api.yt-summarizer.apps.ashleyhollis.com
    description: Production
  - url: https://api-stg.yt-summarizer.apps.ashleyhollis.com
    description: Staging
paths:
  /api/auth/login:
    get:
      summary: Initiate login
      parameters:
        - name: returnTo
          in: query
          schema:
            type: string
            format: uri
          description: Redirect URL after login
      responses:
        '302':
          description: Redirect to Auth0
          headers:
            Location:
              schema:
                type: string
                format: uri
  /api/auth/callback/auth0:
    get:
      summary: Auth0 callback
      parameters:
        - name: code
          in: query
          required: true
          schema:
            type: string
        - name: state
          in: query
          required: true
          schema:
            type: string
      responses:
        '302':
          description: Redirect to returnTo with session cookie
          headers:
            Set-Cookie:
              schema:
                type: string
        '400':
          description: Invalid request
  /api/auth/logout:
    post:
      summary: Logout
      security:
        - cookieAuth: []
      responses:
        '200':
          description: Logged out
          content:
            application/json:
              schema:
                type: object
                properties:
                  success:
                    type: boolean
                  message:
                    type: string
        '401':
          description: Not authenticated
  /api/auth/me:
    get:
      summary: Get current user
      security:
        - cookieAuth: []
      responses:
        '200':
          description: User info
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/UserInfo'
        '401':
          description: Not authenticated
components:
  securitySchemes:
    cookieAuth:
      type: apiKey
      in: cookie
      name: session
  schemas:
    UserInfo:
      type: object
      properties:
        sub:
          type: string
        email:
          type: string
          format: email
        email_verified:
          type: boolean
        name:
          type: string
        picture:
          type: string
          format: uri
        updated_at:
          type: string
          format: date-time
```

---

## Implementation Notes

### Session Storage

- Sessions stored server-side (in-memory or Redis for production)
- Cookie contains encrypted session ID only
- Session data includes: Auth0 tokens, user info, expiry

### State Parameter

- Contains encrypted JSON: `{"returnTo": "...", "nonce": "...", "exp": ...}`
- Encrypted with server secret key
- Expires after 10 minutes
- Nonce prevents replay attacks

### Token Refresh

- Access token refreshed automatically using refresh token
- If refresh fails, user must re-authenticate
- No silent refresh in initial implementation
