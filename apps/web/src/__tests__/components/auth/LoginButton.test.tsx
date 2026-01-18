/**
 * Unit tests for LoginButton component
 * 
 * @module LoginButton.test
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { userEvent } from '@testing-library/user-event';

// Mock the LoginButton component since we're writing tests before implementation
// This will be replaced with the actual component in T019
const MockLoginButton = () => {
  return (
    <div>
      <h2>Sign In</h2>
      <button
        onClick={() => (window.location.href = '/api/auth/login?connection=google-oauth2')}
        data-testid="google-login"
      >
        Sign in with Google
      </button>
      <button
        onClick={() => (window.location.href = '/api/auth/login?connection=github')}
        data-testid="github-login"
      >
        Sign in with GitHub
      </button>
    </div>
  );
};

// Temporarily use mock for testing
const LoginButton = MockLoginButton;

describe('LoginButton Component', () => {
  beforeEach(() => {
    // Reset window.location mock before each test
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (window as any).location;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    window.location = { href: '' } as any;
  });

  describe('Rendering', () => {
    it('should render social login buttons', () => {
      render(<LoginButton />);

      expect(screen.getByText('Sign in with Google')).toBeInTheDocument();
      expect(screen.getByText('Sign in with GitHub')).toBeInTheDocument();
    });

    it('should display login heading', () => {
      render(<LoginButton />);

      expect(screen.getByText('Sign In')).toBeInTheDocument();
    });

    it('should render both provider buttons with correct test IDs', () => {
      render(<LoginButton />);

      expect(screen.getByTestId('google-login')).toBeInTheDocument();
      expect(screen.getByTestId('github-login')).toBeInTheDocument();
    });
  });

  describe('Google OAuth Login', () => {
    it('should navigate to Google OAuth when button is clicked', async () => {
      const user = userEvent.setup();
      render(<LoginButton />);

      const googleButton = screen.getByTestId('google-login');
      await user.click(googleButton);

      expect(window.location.href).toBe('/api/auth/login?connection=google-oauth2');
    });

    it('should have accessible button text for Google', () => {
      render(<LoginButton />);

      const googleButton = screen.getByRole('button', { name: /sign in with google/i });
      expect(googleButton).toBeInTheDocument();
    });
  });

  describe('GitHub OAuth Login', () => {
    it('should navigate to GitHub OAuth when button is clicked', async () => {
      const user = userEvent.setup();
      render(<LoginButton />);

      const githubButton = screen.getByTestId('github-login');
      await user.click(githubButton);

      expect(window.location.href).toBe('/api/auth/login?connection=github');
    });

    it('should have accessible button text for GitHub', () => {
      render(<LoginButton />);

      const githubButton = screen.getByRole('button', { name: /sign in with github/i });
      expect(githubButton).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should have buttons that are keyboard accessible', () => {
      render(<LoginButton />);

      const googleButton = screen.getByTestId('google-login');
      const githubButton = screen.getByTestId('github-login');

      // Buttons should be actual button elements (not links or divs)
      expect(googleButton.tagName).toBe('BUTTON');
      expect(githubButton.tagName).toBe('BUTTON');
    });

    it('should have clear, descriptive button labels', () => {
      render(<LoginButton />);

      // Buttons should clearly indicate the provider
      expect(screen.getByText(/google/i)).toBeInTheDocument();
      expect(screen.getByText(/github/i)).toBeInTheDocument();
    });
  });

  describe('User Story 1 - Social Login Authentication', () => {
    it('should support Google OAuth flow (US1 Scenario 1)', async () => {
      const user = userEvent.setup();
      render(<LoginButton />);

      // User clicks "Sign in with Google"
      const googleButton = screen.getByText('Sign in with Google');
      await user.click(googleButton);

      // User is redirected to Google OAuth consent screen (via Auth0)
      expect(window.location.href).toContain('/api/auth/login');
      expect(window.location.href).toContain('google-oauth2');
    });

    it('should support GitHub OAuth flow', async () => {
      const user = userEvent.setup();
      render(<LoginButton />);

      // User clicks "Sign in with GitHub"
      const githubButton = screen.getByText('Sign in with GitHub');
      await user.click(githubButton);

      // User is redirected to GitHub OAuth consent screen (via Auth0)
      expect(window.location.href).toContain('/api/auth/login');
      expect(window.location.href).toContain('github');
    });
  });

  describe('Error Handling', () => {
    it('should render without errors when no props are provided', () => {
      expect(() => render(<LoginButton />)).not.toThrow();
    });
  });

  describe('Component Structure', () => {
    it('should have semantic HTML structure', () => {
      const { container } = render(<LoginButton />);

      // Should have buttons (not links styled as buttons)
      const buttons = container.querySelectorAll('button');
      expect(buttons.length).toBeGreaterThanOrEqual(2);
    });

    it('should group login options logically', () => {
      render(<LoginButton />);

      // Both social login buttons should be present in the same component
      const googleButton = screen.getByText('Sign in with Google');
      const githubButton = screen.getByText('Sign in with GitHub');

      expect(googleButton.parentElement).toBe(githubButton.parentElement);
    });
  });
});

/**
 * Notes for T019 Implementation:
 * 
 * 1. Component should use Auth0 SDK's handleLogin with connection parameter
 * 2. Buttons should navigate to /api/auth/login?connection={provider}
 * 3. Consider adding loading states for better UX
 * 4. Consider adding error display for failed OAuth attempts (FR-015b)
 * 5. Consider adding provider icons for visual clarity
 * 6. Ensure WCAG 2.1 AA compliance for accessibility
 * 7. Add proper ARIA labels if using icon-only buttons
 * 8. Component should be client-side ('use client') for Next.js
 */
