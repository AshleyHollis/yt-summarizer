/**
 * Unit tests for useAuth hook
 *
 * @module useAuth.test
 */

import { describe, it, expect } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useAuth } from '@/hooks/useAuth';
import { AuthProvider } from '@/contexts/AuthContext';
import type { User } from '@/contexts/AuthContext';

describe('useAuth', () => {
  describe('Provider Integration', () => {
    it('should throw error when used outside AuthProvider', () => {
      // Suppress console.error for this test to avoid noise
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      expect(() => {
        renderHook(() => useAuth());
      }).toThrow('useAuthContext must be used within an AuthProvider');

      consoleSpy.mockRestore();
    });

    it('should return auth context when used inside AuthProvider', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      expect(result.current).toHaveProperty('user');
      expect(result.current).toHaveProperty('isLoading');
      expect(result.current).toHaveProperty('error');
      expect(result.current).toHaveProperty('isAuthenticated');
      expect(result.current).toHaveProperty('hasRole');
    });
  });

  describe('Authentication State', () => {
    it('should return isAuthenticated=false when user is null', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBeNull();
    });

    it('should return correct initial loading state', async () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      // Initial loading state should be true
      expect(result.current.isLoading).toBe(true);

      // Wait for loading to complete
      await waitFor(() => {
        expect(result.current.isLoading).toBe(false);
      });
    });

    it('should return null error by default', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      expect(result.current.error).toBeNull();
    });
  });

  describe('Role Checking', () => {
    it('should return false when checking role without authenticated user', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      expect(result.current.hasRole('admin')).toBe(false);
      expect(result.current.hasRole('normal')).toBe(false);
    });

    // Note: Testing with authenticated user will be possible after T017 (AuthProvider implementation)
    // For now, we verify the method exists and behaves correctly for unauthenticated state
  });

  describe('Type Safety', () => {
    it('should have correct TypeScript types for user property', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      // TypeScript compile-time check: user should be User | null
      const user: User | null = result.current.user;
      expect(user).toBeNull();
    });

    it('should have correct TypeScript types for boolean properties', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      const isAuthenticated: boolean = result.current.isAuthenticated;
      const isLoading: boolean = result.current.isLoading;

      expect(typeof isAuthenticated).toBe('boolean');
      expect(typeof isLoading).toBe('boolean');
    });

    it('should have correct TypeScript types for hasRole function', () => {
      const { result } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      const hasRole: (role: 'admin' | 'normal') => boolean = result.current.hasRole;

      expect(typeof hasRole).toBe('function');
      expect(hasRole('admin')).toBe(false);
    });
  });

  describe('Context Value Stability', () => {
    it('should provide stable context value structure', () => {
      const { result, rerender } = renderHook(() => useAuth(), {
        wrapper: AuthProvider,
      });

      const firstRender = result.current;
      rerender();
      const secondRender = result.current;

      // Context structure should remain consistent
      expect(Object.keys(firstRender).sort()).toEqual(Object.keys(secondRender).sort());
      expect(Object.keys(firstRender).sort()).toEqual([
        'error',
        'hasRole',
        'isAuthenticated',
        'isLoading',
        'user',
      ]);
    });
  });
});
