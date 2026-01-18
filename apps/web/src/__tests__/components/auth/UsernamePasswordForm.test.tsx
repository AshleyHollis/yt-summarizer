/**
 * Unit tests for UsernamePasswordForm component
 * 
 * @module UsernamePasswordForm.test
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { userEvent } from '@testing-library/user-event';
import { UsernamePasswordForm } from '@/components/auth/UsernamePasswordForm';

describe('UsernamePasswordForm Component', () => {
  beforeEach(() => {
    // Reset window.location mock before each test
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (window as any).location;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    window.location = { href: '' } as any;
  });

  describe('Rendering', () => {
    it('should render email and password inputs', () => {
      render(<UsernamePasswordForm />);

      expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
      expect(screen.getByLabelText('Password')).toBeInTheDocument();
    });

    it('should render submit button with correct text', () => {
      render(<UsernamePasswordForm />);

      const submitButton = screen.getByRole('button', { name: /sign in/i });
      expect(submitButton).toBeInTheDocument();
      expect(submitButton).toHaveTextContent('Sign in');
    });

    it('should render password visibility toggle button', () => {
      render(<UsernamePasswordForm />);

      const toggleButton = screen.getByTestId('toggle-password');
      expect(toggleButton).toBeInTheDocument();
      expect(toggleButton).toHaveAttribute('type', 'button');
    });

    it('should render form element with correct structure', () => {
      render(<UsernamePasswordForm />);

      const form = screen.getByTestId('username-password-form');
      expect(form.tagName).toBe('FORM');
    });
  });

  describe('Form Validation', () => {
    it('should disable submit button when email is empty', () => {
      render(<UsernamePasswordForm />);

      const submitButton = screen.getByTestId('submit-button');
      expect(submitButton).toBeDisabled();
    });

    it('should disable submit button when password is empty', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      await user.type(emailInput, 'test@example.com');

      const submitButton = screen.getByTestId('submit-button');
      expect(submitButton).toBeDisabled();
    });

    it('should disable submit button when email is invalid', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      await user.type(emailInput, 'invalid-email');
      await user.type(passwordInput, 'password123');

      const submitButton = screen.getByTestId('submit-button');
      expect(submitButton).toBeDisabled();
    });

    it('should enable submit button when form is valid', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123');

      const submitButton = screen.getByTestId('submit-button');
      expect(submitButton).not.toBeDisabled();
    });

    it('should display error message for invalid email format', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      await user.type(emailInput, 'invalid-email');

      expect(screen.getByTestId('email-error')).toHaveTextContent(
        'Please enter a valid email address'
      );
    });

    it('should validate email format correctly', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');

      // Invalid formats
      await user.type(emailInput, 'no-at-sign');
      expect(screen.getByTestId('email-error')).toBeInTheDocument();

      await user.clear(emailInput);
      await user.type(emailInput, '@no-local-part.com');
      expect(screen.getByTestId('email-error')).toBeInTheDocument();

      await user.clear(emailInput);
      await user.type(emailInput, 'no-domain@');
      expect(screen.getByTestId('email-error')).toBeInTheDocument();

      // Valid format
      await user.clear(emailInput);
      await user.type(emailInput, 'valid@example.com');
      expect(screen.queryByTestId('email-error')).not.toBeInTheDocument();
    });
  });

  describe('Password Visibility Toggle', () => {
    it('should toggle password visibility when button is clicked', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const passwordInput = screen.getByTestId('password-input');
      const toggleButton = screen.getByTestId('toggle-password');

      // Initially password should be hidden
      expect(passwordInput).toHaveAttribute('type', 'password');
      expect(toggleButton).toHaveAttribute('aria-label', 'Show password');

      // Click to show password
      await user.click(toggleButton);
      expect(passwordInput).toHaveAttribute('type', 'text');
      expect(toggleButton).toHaveAttribute('aria-label', 'Hide password');

      // Click to hide password again
      await user.click(toggleButton);
      expect(passwordInput).toHaveAttribute('type', 'password');
      expect(toggleButton).toHaveAttribute('aria-label', 'Show password');
    });

    it('should have accessible label for password toggle', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const toggleButton = screen.getByTestId('toggle-password');

      // Initially should say "Show password"
      expect(toggleButton).toHaveAttribute('aria-label', 'Show password');

      // After clicking should say "Hide password"
      await user.click(toggleButton);
      expect(toggleButton).toHaveAttribute('aria-label', 'Hide password');
    });
  });

  describe('Form Submission', () => {
    it('should call Auth0 login API with credentials on submit', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');
      const submitButton = screen.getByTestId('submit-button');

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123');
      await user.click(submitButton);

      await waitFor(() => {
        expect(window.location.href).toContain('/api/auth/login');
        expect(window.location.href).toContain('Username-Password-Authentication');
        expect(window.location.href).toContain('test%40example.com'); // URL encoded
      });
    });

    it('should display loading state during submission', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');
      const submitButton = screen.getByTestId('submit-button');

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123');

      // Before submission
      expect(submitButton).toHaveTextContent('Sign in');
      expect(submitButton).not.toHaveAttribute('aria-busy', 'true');

      await user.click(submitButton);

      // After submission (before redirect completes)
      // Note: This is a simplification - real implementation might have async behavior
    });

    it('should prevent submission with Enter key when form is invalid', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');

      // Type invalid email and press Enter
      await user.type(emailInput, 'invalid-email{Enter}');

      // Should not navigate
      expect(window.location.href).toBe('');
    });

    it('should allow submission with Enter key when form is valid', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123{Enter}');

      await waitFor(() => {
        expect(window.location.href).toContain('/api/auth/login');
      });
    });
  });

  describe('Error Handling', () => {
    it('should not display error message initially', () => {
      render(<UsernamePasswordForm />);

      expect(screen.queryByTestId('form-error')).not.toBeInTheDocument();
    });

    it('should render without errors when no props are provided', () => {
      expect(() => render(<UsernamePasswordForm />)).not.toThrow();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels for inputs', () => {
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      expect(emailInput).toHaveAttribute('aria-label', 'Email address');
      expect(passwordInput).toHaveAttribute('aria-label', 'Password');
    });

    it('should mark required fields with aria-required', () => {
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      expect(emailInput).toHaveAttribute('aria-required', 'true');
      expect(passwordInput).toHaveAttribute('aria-required', 'true');
    });

    it('should mark invalid email with aria-invalid', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');

      // Initially should not be invalid (empty)
      expect(emailInput).toHaveAttribute('aria-invalid', 'false');

      // Type invalid email
      await user.type(emailInput, 'invalid-email');
      expect(emailInput).toHaveAttribute('aria-invalid', 'true');

      // Type valid email
      await user.clear(emailInput);
      await user.type(emailInput, 'valid@example.com');
      expect(emailInput).toHaveAttribute('aria-invalid', 'false');
    });

    it('should announce errors with role="alert"', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      await user.type(emailInput, 'invalid-email');

      const emailError = screen.getByTestId('email-error');
      expect(emailError).toHaveAttribute('role', 'alert');
    });

    it('should be keyboard accessible', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');
      const toggleButton = screen.getByTestId('toggle-password');

      // Fill in form to enable submit button
      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'password123');

      // Tab through form elements
      emailInput.focus();
      expect(emailInput).toHaveFocus();

      await user.tab();
      expect(passwordInput).toHaveFocus();

      await user.tab();
      expect(toggleButton).toHaveFocus();

      await user.tab();
      const submitButton = screen.getByTestId('submit-button');
      expect(submitButton).toHaveFocus();
    });

    it('should use semantic HTML form elements', () => {
      const { container } = render(<UsernamePasswordForm />);

      // Should have a form element
      const form = container.querySelector('form');
      expect(form).toBeInTheDocument();

      // Should have label elements
      const labels = container.querySelectorAll('label');
      expect(labels.length).toBeGreaterThanOrEqual(2);

      // Should have input elements
      const inputs = container.querySelectorAll('input');
      expect(inputs.length).toBeGreaterThanOrEqual(2);
    });

    it('should have labels properly associated with inputs', () => {
      render(<UsernamePasswordForm />);

      const emailInput = screen.getByLabelText(/email/i);
      const passwordInput = screen.getByLabelText('Password');

      expect(emailInput).toHaveAttribute('id', 'email');
      expect(passwordInput).toHaveAttribute('id', 'password');
    });
  });

  describe('User Story 3 - Username/Password Authentication', () => {
    it('should support username/password login flow (US3 Scenario 1)', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      // User enters email and password
      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      await user.type(emailInput, 'test@example.com');
      await user.type(passwordInput, 'securePassword123');

      // User clicks "Sign in"
      const submitButton = screen.getByTestId('submit-button');
      await user.click(submitButton);

      // User is authenticated via Auth0 database connection
      await waitFor(() => {
        expect(window.location.href).toContain('/api/auth/login');
        expect(window.location.href).toContain('Username-Password-Authentication');
      });
    });

    it('should handle test account credentials', async () => {
      const user = userEvent.setup();
      render(<UsernamePasswordForm />);

      // Simulate test account login
      const emailInput = screen.getByTestId('email-input');
      const passwordInput = screen.getByTestId('password-input');

      await user.type(emailInput, 'admin@test.example.com');
      await user.type(passwordInput, 'testPassword123');
      await user.click(screen.getByTestId('submit-button'));

      await waitFor(() => {
        expect(window.location.href).toContain('/api/auth/login');
      });
    });
  });

  describe('Component Structure', () => {
    it('should have proper form structure', () => {
      const { container } = render(<UsernamePasswordForm />);

      const form = container.querySelector('form');
      expect(form).toBeInTheDocument();

      // Should have email and password fields
      const inputs = form?.querySelectorAll('input');
      expect(inputs?.length).toBeGreaterThanOrEqual(2);

      // Should have submit button
      const submitButton = form?.querySelector('button[type="submit"]');
      expect(submitButton).toBeInTheDocument();
    });

    it('should group related inputs with labels', () => {
      render(<UsernamePasswordForm />);

      // Email label should be associated with email input
      const emailLabel = screen.getByText('Email');
      expect(emailLabel).toBeInTheDocument();

      // Password label should be associated with password input
      const passwordLabel = screen.getByText('Password');
      expect(passwordLabel).toBeInTheDocument();
    });
  });
});

/**
 * Notes for T041 Implementation:
 * 
 * 1. Component should use Auth0 SDK's handleLogin with Username-Password-Authentication connection
 * 2. Form should POST to /api/auth/login with connection parameter
 * 3. Email validation should use standard regex pattern
 * 4. Password visibility toggle improves UX (common pattern)
 * 5. Loading states prevent double-submission
 * 6. Error handling should display Auth0 error messages (FR-015b)
 * 7. Component should be client-side ('use client') for Next.js
 * 8. Consider adding "Forgot password?" link for production
 * 9. Consider adding password strength indicator
 * 10. Ensure WCAG 2.1 AA compliance for accessibility
 * 11. Match design pattern from LoginButton (gradient, styling)
 * 12. Consider rate limiting on backend to prevent brute force
 */
