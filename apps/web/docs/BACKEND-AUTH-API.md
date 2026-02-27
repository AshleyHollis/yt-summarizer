# Backend API Authentication Endpoints

This document specifies the authentication endpoints that the backend API must implement to support the frontend authentication flow.

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────┐
│   Browser   │────────>│  Backend API │────────>│  Auth0  │
│  (Next.js)  │<────────│  (FastAPI)   │<────────│         │
└─────────────┘         └──────────────┘         └─────────┘
     Cookies              Session Store          OAuth Provider
```

**Flow:**
1. Frontend redirects to backend `/auth/login`
2. Backend redirects to Auth0 for authentication
3. Auth0 redirects back to backend `/auth/callback`
4. Backend creates session and sets secure HTTP-only cookie
5. Frontend receives session cookie for subsequent requests

## Required Endpoints

### 1. **GET `/auth/login`**

**Purpose:** Initiate authentication flow

**Query Parameters:**
- `return_to` (optional): URL to redirect to after successful login (must be validated against allowed origins)

**Response:**
- **Status:** 302 Found
- **Headers:**
  - `Location`: Auth0 authorization URL with appropriate parameters

**Example:**
```
GET /auth/login?return_to=/dashboard
→ 302 Redirect to https://dev-xxx.us.auth0.com/authorize?...
```

**Security:**
- Generate and store PKCE verifier
- Generate state parameter to prevent CSRF
- Validate `return_to` URL against allowlist

---

### 2. **GET `/auth/callback`**

**Purpose:** Handle OAuth callback from Auth0

**Query Parameters:**
- `code`: Authorization code from Auth0
- `state`: State parameter for CSRF validation

**Response:**
- **Status:** 302 Found
- **Headers:**
  - `Location`: Original `return_to` URL or default dashboard
  - `Set-Cookie`: Session cookie (HTTP-only, Secure, SameSite=Lax)

**Example:**
```
GET /auth/callback?code=abc123&state=xyz789
→ 302 Redirect to /dashboard
→ Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax; Max-Age=86400
```

**Security:**
- Validate state parameter
- Exchange authorization code for tokens using PKCE verifier
- Create server-side session
- Set HTTP-only session cookie

---

### 3. **GET `/auth/session`**

**Purpose:** Get current user session information

**Headers:**
- `Cookie`: Session cookie

**Response:**
- **Status:** 200 OK (if authenticated)
- **Status:** 401 Unauthorized (if not authenticated)

**Response Body (authenticated):**
```json
{
  "user": {
    "id": "auth0|12345",
    "email": "user@example.com",
    "name": "John Doe",
    "picture": "https://avatars.example.com/user.jpg"
  },
  "isAuthenticated": true
}
```

**Response Body (not authenticated):**
```json
{
  "isAuthenticated": false
}
```

**Example:**
```
GET /auth/session
Cookie: session=...

→ 200 OK
{
  "user": { ... },
  "isAuthenticated": true
}
```

---

### 4. **POST `/auth/logout`**

**Purpose:** End user session

**Headers:**
- `Cookie`: Session cookie

**Response:**
- **Status:** 302 Found
- **Headers:**
  - `Location`: Auth0 logout URL or home page
  - `Set-Cookie`: Expire session cookie

**Example:**
```
POST /auth/logout
Cookie: session=...

→ 302 Redirect to https://dev-xxx.us.auth0.com/v2/logout?...
→ Set-Cookie: session=; Max-Age=0; Path=/
```

**Security:**
- Invalidate server-side session
- Clear session cookie
- Redirect to Auth0 logout endpoint to clear Auth0 session

---

## Session Cookie Specification

**Cookie Name:** `session` (or configure via environment variable)

**Cookie Attributes:**
- `HttpOnly`: Yes (prevent JavaScript access)
- `Secure`: Yes (HTTPS only, except localhost development)
- `SameSite`: Lax (prevent CSRF while allowing top-level navigation)
- `Path`: `/`
- `Max-Age`: 86400 (24 hours, configurable)
- `Domain`: Not set (restricts to exact domain)

**Example:**
```
Set-Cookie: session=eyJ0eXAiOiJKV1QiLCJhbGc...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400
```

---

## CORS Configuration

The backend API must configure CORS to allow requests from the frontend origin:

**Allowed Origins (environment-specific):**
- Development: `http://localhost:3000`
- Preview: `https://*.azurestaticapps.net`
- Production: `https://white-meadow-0b8e2e000.6.azurestaticapps.net`

**CORS Headers:**
```
Access-Control-Allow-Origin: <frontend-origin>
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
```

**Important:** Set `Access-Control-Allow-Credentials: true` to allow cookies to be sent cross-origin.

---

## Environment Variables (Backend)

The backend API should support the following environment variables:

```bash
# Auth0 Configuration
AUTH0_DOMAIN=dev-xxx.us.auth0.com
AUTH0_CLIENT_ID=abc123
AUTH0_CLIENT_SECRET=secret123
AUTH0_CALLBACK_URL=https://api.example.com/auth/callback

# Session Configuration
SESSION_SECRET=random-secret-at-least-32-chars
SESSION_MAX_AGE=86400  # 24 hours in seconds

# CORS
ALLOWED_ORIGINS=http://localhost:3000,https://white-meadow-0b8e2e000.6.azurestaticapps.net
```

---

## Security Considerations

1. **CSRF Protection:** Use `state` parameter in OAuth flow
2. **PKCE:** Use PKCE flow (not just client secret) for enhanced security
3. **Session Storage:** Store sessions server-side (Redis, database, or in-memory)
4. **Cookie Security:** Always use HttpOnly, Secure, SameSite attributes
5. **Return URL Validation:** Validate `return_to` against allowlist to prevent open redirects
6. **Token Storage:** Never expose access/refresh tokens to frontend; keep them server-side
7. **HTTPS Only:** Enforce HTTPS in production environments

---

## Implementation Checklist

Backend team should implement:

- [ ] Auth0 OAuth client setup (use `authlib` or `auth0-python` SDK)
- [ ] Session storage mechanism (Redis recommended for production)
- [ ] `/auth/login` endpoint with PKCE + state generation
- [ ] `/auth/callback` endpoint with token exchange + session creation
- [ ] `/auth/session` endpoint returning user info
- [ ] `/auth/logout` endpoint with session cleanup
- [ ] CORS middleware configured for frontend origins
- [ ] Secure cookie configuration
- [ ] Return URL validation middleware
- [ ] Environment variable configuration

---

## Testing

**Manual Testing:**
1. Visit `/auth/login` → Should redirect to Auth0
2. Login via Auth0 → Should redirect back with session cookie
3. Visit `/auth/session` → Should return user info
4. Visit `/auth/logout` → Should clear session and redirect

**Automated Testing:**
```bash
# Test login redirect
curl -i http://localhost:8000/auth/login

# Test session endpoint (unauthenticated)
curl -i http://localhost:8000/auth/session

# Test session endpoint (authenticated)
curl -i -H "Cookie: session=..." http://localhost:8000/auth/session

# Test logout
curl -i -X POST -H "Cookie: session=..." http://localhost:8000/auth/logout
```

---

## References

- [Auth0 Regular Web App Quickstart](https://auth0.com/docs/quickstart/webapp/python)
- [OAuth 2.0 PKCE](https://oauth.net/2/pkce/)
- [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [FastAPI Security Tutorial](https://fastapi.tiangolo.com/tutorial/security/)
