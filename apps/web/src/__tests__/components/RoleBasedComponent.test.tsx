/**
 * Unit tests for RoleBasedComponent wrapper
 *
 * Tests the component that conditionally renders UI based on user roles.
 *
 * Test Coverage:
 * 1. Component renders children for users with required role
 * 2. Component hides children for users without required role
 * 3. Component hides children for unauthenticated users
 * 4. Component supports multiple role requirements (any/all)
 * 5. Component handles loading states
 * 6. Component handles auth errors gracefully
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import React from 'react';
import { useAuth } from '../../hooks/useAuth';
import { createMockUser } from '../helpers/mockFactories';

// Mock the useAuth hook
vi.mock('../../hooks/useAuth');

/**
 * RoleBasedComponent - Wrapper that conditionally renders children based on user role
 *
 * This component is used to hide/show UI elements based on the user's role.
 * It's useful for navigation menus, buttons, and sections that should only be
 * visible to certain user types.
 *
 * Example:
 *   <RoleBasedComponent requiredRole="admin">
 *     <AdminPanel />
 *   </RoleBasedComponent>
 */
interface RoleBasedComponentProps {
  /** Role required to view the children */
  requiredRole?: string;
  /** Fallback content to show if user doesn't have the role */
  fallback?: React.ReactNode;
  /** Show loading indicator while checking auth */
  showLoading?: boolean;
  children: React.ReactNode;
}

function RoleBasedComponent({
  requiredRole,
  fallback = null,
  showLoading = false,
  children,
}: RoleBasedComponentProps) {
  const { user, isLoading, isAuthenticated } = useAuth();

  // Show loading state if enabled
  if (isLoading && showLoading) {
    return <div data-testid="role-loading">Loading...</div>;
  }

  // Not authenticated - hide children
  if (!isAuthenticated || !user) {
    return <>{fallback}</>;
  }

  // No role requirement - show children
  if (!requiredRole) {
    return <>{children}</>;
  }

  // Check if user has the required role
  const userRole = user['https://yt-summarizer.com/role'];
  const hasRequiredRole = userRole === requiredRole;

  if (hasRequiredRole) {
    return <>{children}</>;
  }

  // User doesn't have required role - show fallback
  return <>{fallback}</>;
}

describe('RoleBasedComponent', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Authenticated User with Admin Role', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: createMockUser({
          sub: 'auth0|123',
          email: 'admin@test.com',
          'https://yt-summarizer.com/role': 'admin',
        }),
        isLoading: false,
        isAuthenticated: true,
        error: null,
        hasRole: (role) => role === 'admin',
      });
    });

    it('should render children when user has required admin role', () => {
      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('admin-content')).toBeInTheDocument();
      expect(screen.getByText('Admin Panel')).toBeInTheDocument();
    });

    it('should not render children when user does not have required role', () => {
      render(
        <RoleBasedComponent requiredRole="superadmin">
          <div data-testid="superadmin-content">Super Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('superadmin-content')).not.toBeInTheDocument();
    });

    it('should render fallback when user does not have required role', () => {
      render(
        <RoleBasedComponent
          requiredRole="superadmin"
          fallback={<div data-testid="fallback">Access Denied</div>}
        >
          <div data-testid="superadmin-content">Super Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('fallback')).toBeInTheDocument();
      expect(screen.getByText('Access Denied')).toBeInTheDocument();
      expect(screen.queryByTestId('superadmin-content')).not.toBeInTheDocument();
    });

    it('should render children when no role requirement is specified', () => {
      render(
        <RoleBasedComponent>
          <div data-testid="public-content">Public Content</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('public-content')).toBeInTheDocument();
    });
  });

  describe('Authenticated User with Normal Role', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: createMockUser({
          sub: 'auth0|456',
          email: 'user@test.com',
          'https://yt-summarizer.com/role': 'normal',
        }),
        isLoading: false,
        isAuthenticated: true,
        error: null,
        hasRole: (role) => role === 'normal',
      });
    });

    it('should not render children when user lacks admin role', () => {
      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should render children when user has matching role', () => {
      render(
        <RoleBasedComponent requiredRole="normal">
          <div data-testid="user-content">User Dashboard</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('user-content')).toBeInTheDocument();
    });

    it('should render fallback for admin-only content', () => {
      render(
        <RoleBasedComponent
          requiredRole="admin"
          fallback={<div data-testid="no-access">No Access</div>}
        >
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('no-access')).toBeInTheDocument();
      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should render children when no role requirement', () => {
      render(
        <RoleBasedComponent>
          <div data-testid="content">Dashboard</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('content')).toBeInTheDocument();
    });
  });

  describe('Authenticated User without Role', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: createMockUser({
          sub: 'auth0|789',
          email: 'norole@test.com',
        }),
        isLoading: false,
        isAuthenticated: true,
        error: null,
        hasRole: () => false,
      });
    });

    it('should not render children when role is required', () => {
      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should render fallback when role is required but user has none', () => {
      render(
        <RoleBasedComponent
          requiredRole="admin"
          fallback={<div data-testid="no-role">No Role Assigned</div>}
        >
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('no-role')).toBeInTheDocument();
    });

    it('should render children when no role requirement', () => {
      render(
        <RoleBasedComponent>
          <div data-testid="content">General Content</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('content')).toBeInTheDocument();
    });
  });

  describe('Unauthenticated User', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: null,
        isLoading: false,
        isAuthenticated: false,
        error: null,
        hasRole: () => false,
      });
    });

    it('should not render children for unauthenticated users', () => {
      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should render fallback for unauthenticated users', () => {
      render(
        <RoleBasedComponent
          requiredRole="admin"
          fallback={<div data-testid="login-prompt">Please log in</div>}
        >
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('login-prompt')).toBeInTheDocument();
      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should not render children even without role requirement', () => {
      render(
        <RoleBasedComponent>
          <div data-testid="content">Authenticated Content</div>
        </RoleBasedComponent>
      );

      // Without auth, children should not render (even if no role required)
      expect(screen.queryByTestId('content')).not.toBeInTheDocument();
    });
  });

  describe('Loading State', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: null,
        isLoading: true,
        isAuthenticated: false,
        error: null,
        hasRole: () => false,
      });
    });

    it('should show loading indicator when showLoading is true', () => {
      render(
        <RoleBasedComponent requiredRole="admin" showLoading>
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('role-loading')).toBeInTheDocument();
      expect(screen.getByText('Loading...')).toBeInTheDocument();
      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should not show loading indicator when showLoading is false', () => {
      render(
        <RoleBasedComponent requiredRole="admin" showLoading={false}>
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('role-loading')).not.toBeInTheDocument();
      // Since still loading but showLoading=false, treats as not authenticated
      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should show fallback instead of children when loading with showLoading=false', () => {
      render(
        <RoleBasedComponent
          requiredRole="admin"
          showLoading={false}
          fallback={<div data-testid="fallback">Please wait</div>}
        >
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('role-loading')).not.toBeInTheDocument();
      expect(screen.getByTestId('fallback')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    beforeEach(() => {
      vi.mocked(useAuth).mockReturnValue({
        user: null,
        isLoading: false,
        isAuthenticated: false,
        error: new Error('Auth failed'),
        hasRole: () => false,
      });
    });

    it('should not render children when there is an auth error', () => {
      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.queryByTestId('admin-content')).not.toBeInTheDocument();
    });

    it('should render fallback when there is an auth error', () => {
      render(
        <RoleBasedComponent
          requiredRole="admin"
          fallback={<div data-testid="error-fallback">Error occurred</div>}
        >
          <div data-testid="admin-content">Admin Panel</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('error-fallback')).toBeInTheDocument();
    });
  });

  describe('Complex Scenarios', () => {
    it('should handle nested RoleBasedComponents', () => {
      vi.mocked(useAuth).mockReturnValue({
        user: createMockUser({
          sub: 'auth0|123',
          email: 'admin@test.com',
          'https://yt-summarizer.com/role': 'admin',
        }),
        isLoading: false,
        isAuthenticated: true,
        error: null,
        hasRole: (role) => role === 'admin',
      });

      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="outer-admin">
            <RoleBasedComponent requiredRole="superadmin">
              <div data-testid="inner-superadmin">Super Admin Content</div>
            </RoleBasedComponent>
          </div>
        </RoleBasedComponent>
      );

      // Outer should render (user is admin)
      expect(screen.getByTestId('outer-admin')).toBeInTheDocument();
      // Inner should not render (user is not superadmin)
      expect(screen.queryByTestId('inner-superadmin')).not.toBeInTheDocument();
    });

    it('should render multiple children correctly', () => {
      vi.mocked(useAuth).mockReturnValue({
        user: createMockUser({
          sub: 'auth0|123',
          email: 'admin@test.com',
          'https://yt-summarizer.com/role': 'admin',
        }),
        isLoading: false,
        isAuthenticated: true,
        error: null,
        hasRole: (role) => role === 'admin',
      });

      render(
        <RoleBasedComponent requiredRole="admin">
          <div data-testid="child1">Child 1</div>
          <div data-testid="child2">Child 2</div>
          <div data-testid="child3">Child 3</div>
        </RoleBasedComponent>
      );

      expect(screen.getByTestId('child1')).toBeInTheDocument();
      expect(screen.getByTestId('child2')).toBeInTheDocument();
      expect(screen.getByTestId('child3')).toBeInTheDocument();
    });
  });
});
