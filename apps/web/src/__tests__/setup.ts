/**
 * Vitest setup file
 */

import '@testing-library/jest-dom/vitest';
import { vi } from 'vitest';

// Mock next/navigation
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
  }),
  useParams: () => ({}),
  useSearchParams: () => new URLSearchParams(),
  usePathname: () => '/',
}));

// Mock fetch globally
global.fetch = vi.fn();

// Mock Auth0 SDK
vi.mock('@auth0/nextjs-auth0', () => ({
  getSession: vi.fn(),
  getAccessToken: vi.fn(),
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  withApiAuthRequired: (handler: any) => handler,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  withPageAuthRequired: (component: any) => component,
  handleAuth: vi.fn(),
  handleLogin: vi.fn(),
  handleLogout: vi.fn(),
  handleCallback: vi.fn(),
  handleProfile: vi.fn(),
}));

// Reset mocks after each test
afterEach(() => {
  vi.clearAllMocks();
});
