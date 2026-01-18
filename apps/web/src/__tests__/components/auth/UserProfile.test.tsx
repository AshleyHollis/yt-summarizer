/**
 * Unit tests for UserProfile component
 *
 * @module UserProfile.test
 */

import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { AuthProvider } from '@/contexts/AuthContext';
import type { User } from '@/contexts/AuthContext';

// Mock the UserProfile component since we're writing tests before implementation
// This will be replaced with the actual component in T020
const MockUserProfile = ({ user }: { user: User | null }) => {
  if (!user) {
    return <div data-testid="not-authenticated">Please log in</div>;
  }

  return (
    <div data-testid="user-profile">
      <img src={user.picture} alt={`${user.name}'s profile`} data-testid="profile-picture" />
      <div data-testid="user-name">{user.name || user.email}</div>
      <div data-testid="user-email">{user.email}</div>
      <div data-testid="user-role">{user['https://yt-summarizer.com/role']}</div>
    </div>
  );
};

// Temporarily use mock for testing
const UserProfile = MockUserProfile;

// Test fixtures
const mockAdminUser: User = {
  sub: 'google-oauth2|123456789',
  email: 'admin@example.com',
  email_verified: true,
  name: 'Admin User',
  picture: 'https://example.com/admin-avatar.jpg',
  'https://yt-summarizer.com/role': 'admin',
  updated_at: '2026-01-19T00:00:00.000Z',
};

const mockNormalUser: User = {
  sub: 'github|987654321',
  email: 'user@example.com',
  email_verified: true,
  name: 'Normal User',
  picture: 'https://example.com/user-avatar.jpg',
  'https://yt-summarizer.com/role': 'normal',
  updated_at: '2026-01-19T00:00:00.000Z',
};

const mockUserWithoutName: User = {
  sub: 'auth0|abc123',
  email: 'nopic@example.com',
  email_verified: false,
  'https://yt-summarizer.com/role': 'normal',
  updated_at: '2026-01-19T00:00:00.000Z',
};

describe('UserProfile Component', () => {
  describe('Authenticated User Display', () => {
    it('should display user name when available', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-name')).toHaveTextContent('Admin User');
    });

    it('should display user email', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-email')).toHaveTextContent('admin@example.com');
    });

    it('should display user role', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-role')).toHaveTextContent('admin');
    });

    it('should display profile picture when available', () => {
      render(<UserProfile user={mockAdminUser} />);

      const profilePicture = screen.getByTestId('profile-picture') as HTMLImageElement;
      expect(profilePicture).toBeInTheDocument();
      expect(profilePicture.src).toContain('admin-avatar.jpg');
    });

    it('should fallback to email when name is not available', () => {
      render(<UserProfile user={mockUserWithoutName} />);

      expect(screen.getByTestId('user-name')).toHaveTextContent('nopic@example.com');
    });
  });

  describe('Unauthenticated State', () => {
    it('should show login prompt when user is null', () => {
      render(<UserProfile user={null} />);

      expect(screen.getByTestId('not-authenticated')).toHaveTextContent('Please log in');
    });

    it('should not display profile info when user is null', () => {
      render(<UserProfile user={null} />);

      expect(screen.queryByTestId('user-profile')).not.toBeInTheDocument();
      expect(screen.queryByTestId('user-name')).not.toBeInTheDocument();
      expect(screen.queryByTestId('user-email')).not.toBeInTheDocument();
    });
  });

  describe('Role-Based Display', () => {
    it('should display admin role for admin users', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-role')).toHaveTextContent('admin');
    });

    it('should display normal role for normal users', () => {
      render(<UserProfile user={mockNormalUser} />);

      expect(screen.getByTestId('user-role')).toHaveTextContent('normal');
    });
  });

  describe('Different User Types', () => {
    it('should display Google OAuth user correctly', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
      expect(screen.getByTestId('user-name')).toHaveTextContent('Admin User');
      expect(screen.getByTestId('profile-picture')).toBeInTheDocument();
    });

    it('should display GitHub OAuth user correctly', () => {
      render(<UserProfile user={mockNormalUser} />);

      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
      expect(screen.getByTestId('user-name')).toHaveTextContent('Normal User');
    });

    it('should display database user correctly (without picture)', () => {
      render(<UserProfile user={mockUserWithoutName} />);

      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
      expect(screen.getByTestId('user-email')).toHaveTextContent('nopic@example.com');
    });
  });

  describe('Accessibility', () => {
    it('should have accessible alt text for profile picture', () => {
      render(<UserProfile user={mockAdminUser} />);

      const profilePicture = screen.getByTestId('profile-picture');
      expect(profilePicture).toHaveAttribute('alt', "Admin User's profile");
    });

    it('should display text content for screen readers', () => {
      render(<UserProfile user={mockAdminUser} />);

      // All text content should be in the document for screen readers
      expect(screen.getByText('Admin User')).toBeInTheDocument();
      expect(screen.getByText('admin@example.com')).toBeInTheDocument();
      expect(screen.getByText('admin')).toBeInTheDocument();
    });
  });

  describe('User Story 1 - Social Login Display', () => {
    it('should display authenticated user info after Google OAuth (US1 Scenario 2)', () => {
      render(<UserProfile user={mockAdminUser} />);

      // After OAuth completion, user profile should be displayed
      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
      expect(screen.getByTestId('user-name')).toHaveTextContent('Admin User');
      expect(screen.getByTestId('user-email')).toHaveTextContent('admin@example.com');
    });

    it('should display authenticated user info after GitHub OAuth', () => {
      render(<UserProfile user={mockNormalUser} />);

      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
      expect(screen.getByTestId('user-name')).toHaveTextContent('Normal User');
    });
  });

  describe('User Story 2 - RBAC Display', () => {
    it('should indicate admin status (US2 Scenario 3)', () => {
      render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-role')).toHaveTextContent('admin');
    });

    it('should indicate normal user status (US2 Scenario 4)', () => {
      render(<UserProfile user={mockNormalUser} />);

      expect(screen.getByTestId('user-role')).toHaveTextContent('normal');
    });
  });

  describe('Error Handling', () => {
    it('should handle missing picture gracefully', () => {
      const userWithoutPicture: User = {
        ...mockAdminUser,
        picture: undefined,
      };

      expect(() => render(<UserProfile user={userWithoutPicture} />)).not.toThrow();
    });

    it('should handle missing name gracefully', () => {
      expect(() => render(<UserProfile user={mockUserWithoutName} />)).not.toThrow();
    });

    it('should not throw when user is null', () => {
      expect(() => render(<UserProfile user={null} />)).not.toThrow();
    });
  });

  describe('Component Structure', () => {
    it('should have semantic HTML structure', () => {
      const { container } = render(<UserProfile user={mockAdminUser} />);

      // Should contain user profile container
      expect(screen.getByTestId('user-profile')).toBeInTheDocument();
    });

    it('should organize user information logically', () => {
      render(<UserProfile user={mockAdminUser} />);

      const profile = screen.getByTestId('user-profile');
      const name = screen.getByTestId('user-name');
      const email = screen.getByTestId('user-email');
      const role = screen.getByTestId('user-role');

      // All elements should be within the profile container
      expect(profile).toContainElement(name);
      expect(profile).toContainElement(email);
      expect(profile).toContainElement(role);
    });
  });

  describe('Re-rendering Behavior', () => {
    it('should update when user changes', () => {
      const { rerender } = render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-name')).toHaveTextContent('Admin User');

      rerender(<UserProfile user={mockNormalUser} />);

      expect(screen.getByTestId('user-name')).toHaveTextContent('Normal User');
    });

    it('should update when user logs out', () => {
      const { rerender } = render(<UserProfile user={mockAdminUser} />);

      expect(screen.getByTestId('user-profile')).toBeInTheDocument();

      rerender(<UserProfile user={null} />);

      expect(screen.queryByTestId('user-profile')).not.toBeInTheDocument();
      expect(screen.getByTestId('not-authenticated')).toBeInTheDocument();
    });
  });
});

/**
 * Notes for T020 Implementation:
 *
 * 1. Component should receive user from useAuth() hook, not as a prop
 * 2. Consider adding a loading skeleton while user data is loading
 * 3. Consider using getUserDisplayName() utility from auth-utils.ts
 * 4. Consider adding fallback avatar when picture is not available
 * 5. Consider making role display more user-friendly ("Admin" vs "admin")
 * 6. Should be client-side component ('use client') for Next.js
 * 7. Consider adding link to logout or account settings
 * 8. Ensure WCAG 2.1 AA compliance for color contrast and text sizing
 */
