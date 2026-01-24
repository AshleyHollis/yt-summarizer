/**
 * Authentication service for communicating with backend API
 *
 * This service handles all authentication-related API calls to the backend.
 * The backend API manages the Auth0 OAuth flow and session cookies.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export interface User {
  id: string;
  email: string;
  name: string;
  picture?: string;
}

export interface Session {
  user: User | null;
  isAuthenticated: boolean;
}

/**
 * Redirect to backend login endpoint
 * Backend will handle Auth0 OAuth flow and redirect back with session cookie
 */
export function login(returnTo?: string): void {
  const params = new URLSearchParams();
  if (returnTo) {
    params.set('return_to', returnTo);
  }

  const loginUrl = `${API_BASE_URL}/api/auth/login${params.toString() ? `?${params}` : ''}`;
  window.location.href = loginUrl;
}

/**
 * Redirect to backend logout endpoint
 * Backend will clear session cookie and redirect to Auth0 logout
 */
export function logout(): void {
  const logoutUrl = `${API_BASE_URL}/api/auth/logout`;
  window.location.href = logoutUrl;
}

/**
 * Get current session from backend API
 * Session cookie is automatically sent with request
 */
export async function getSession(): Promise<Session> {
  // Skip API calls during SSR/SSG (server-side rendering / static site generation)
  // This prevents deployment timeouts when Next.js tries to pre-render pages
  if (typeof window === 'undefined') {
    return {
      user: null,
      isAuthenticated: false,
    };
  }

  try {
    const response = await fetch(`${API_BASE_URL}/api/auth/session`, {
      method: 'GET',
      credentials: 'include', // Send cookies cross-origin
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      // Not authenticated or error
      return {
        user: null,
        isAuthenticated: false,
      };
    }

    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Failed to fetch session:', error);
    return {
      user: null,
      isAuthenticated: false,
    };
  }
}

/**
 * Check if user is authenticated
 * This is a convenience method that calls getSession() and returns boolean
 */
export async function isAuthenticated(): Promise<boolean> {
  const session = await getSession();
  return session.isAuthenticated;
}
