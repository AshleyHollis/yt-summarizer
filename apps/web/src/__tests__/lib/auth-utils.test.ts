/**
 * Unit tests for auth utility functions
 *
 * @module auth-utils.test
 */

import { describe, it, expect } from 'vitest';
import {
  hasRole,
  getAuthMethod,
  getProvider,
  getUserDisplayName,
  isAuthenticated,
  getUserRole,
} from '@/lib/auth-utils';
import type { User } from '@/contexts/AuthContext';

// Test fixture: admin user with Google OAuth
const mockAdminUser: User = {
  sub: 'google-oauth2|123456789',
  email: 'admin@example.com',
  email_verified: true,
  name: 'Admin User',
  picture: 'https://example.com/avatar.jpg',
  'https://yt-summarizer.com/role': 'admin',
  updated_at: '2026-01-19T00:00:00.000Z',
};

// Test fixture: normal user with GitHub OAuth
const mockNormalUser: User = {
  sub: 'github|987654321',
  email: 'user@example.com',
  email_verified: true,
  name: 'Normal User',
  'https://yt-summarizer.com/role': 'normal',
  updated_at: '2026-01-19T00:00:00.000Z',
};

// Test fixture: database user (username/password)
const mockDatabaseUser: User = {
  sub: 'auth0|abc123def456',
  email: 'dbuser@example.com',
  email_verified: true,
  username: 'dbuser',
  'https://yt-summarizer.com/role': 'normal',
  updated_at: '2026-01-19T00:00:00.000Z',
};

// Test fixture: user with email only (no name/username)
const mockEmailOnlyUser: User = {
  sub: 'google-oauth2|emailonly',
  email: 'emailonly@example.com',
  email_verified: false,
  'https://yt-summarizer.com/role': 'normal',
  updated_at: '2026-01-19T00:00:00.000Z',
};

describe('hasRole', () => {
  describe('Admin Role Checks', () => {
    it('should return true when user has admin role', () => {
      expect(hasRole(mockAdminUser, 'admin')).toBe(true);
    });

    it('should return false when user has normal role but checking for admin', () => {
      expect(hasRole(mockNormalUser, 'admin')).toBe(false);
    });
  });

  describe('Normal Role Checks', () => {
    it('should return true when user has normal role', () => {
      expect(hasRole(mockNormalUser, 'normal')).toBe(true);
    });

    it('should return false when user has admin role but checking for normal', () => {
      expect(hasRole(mockAdminUser, 'normal')).toBe(false);
    });
  });

  describe('Null User Handling', () => {
    it('should return false when user is null', () => {
      expect(hasRole(null, 'admin')).toBe(false);
      expect(hasRole(null, 'normal')).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should work correctly for database users', () => {
      expect(hasRole(mockDatabaseUser, 'normal')).toBe(true);
      expect(hasRole(mockDatabaseUser, 'admin')).toBe(false);
    });
  });
});

describe('getAuthMethod', () => {
  describe('Social Providers', () => {
    it('should return "social" for Google OAuth', () => {
      expect(getAuthMethod('google-oauth2|123')).toBe('social');
    });

    it('should return "social" for GitHub OAuth', () => {
      expect(getAuthMethod('github|456')).toBe('social');
    });

    it('should return "social" for any non-auth0 provider', () => {
      expect(getAuthMethod('twitter|789')).toBe('social');
      expect(getAuthMethod('facebook|abc')).toBe('social');
      expect(getAuthMethod('microsoft|def')).toBe('social');
    });
  });

  describe('Database Connection', () => {
    it('should return "database" for auth0 provider', () => {
      expect(getAuthMethod('auth0|abc123')).toBe('database');
    });

    it('should return "database" for auth0 provider with complex ID', () => {
      expect(getAuthMethod('auth0|507f1f77bcf86cd799439011')).toBe('database');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string after pipe', () => {
      expect(getAuthMethod('auth0|')).toBe('database');
      expect(getAuthMethod('google-oauth2|')).toBe('social');
    });

    it('should handle sub without pipe', () => {
      // This shouldn't happen in practice, but test the behavior
      expect(getAuthMethod('invalidformat')).toBe('social');
    });
  });
});

describe('getProvider', () => {
  describe('Provider Extraction', () => {
    it('should extract Google OAuth provider', () => {
      expect(getProvider('google-oauth2|123456')).toBe('google-oauth2');
    });

    it('should extract GitHub provider', () => {
      expect(getProvider('github|789012')).toBe('github');
    });

    it('should extract auth0 provider', () => {
      expect(getProvider('auth0|abc123')).toBe('auth0');
    });

    it('should extract other providers', () => {
      expect(getProvider('twitter|xyz')).toBe('twitter');
      expect(getProvider('facebook|123')).toBe('facebook');
      expect(getProvider('microsoft|456')).toBe('microsoft');
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string after pipe', () => {
      expect(getProvider('google-oauth2|')).toBe('google-oauth2');
    });

    it('should handle sub without pipe', () => {
      expect(getProvider('invalidformat')).toBe('invalidformat');
    });

    it('should handle multiple pipes (take first segment)', () => {
      expect(getProvider('auth0|123|extra')).toBe('auth0');
    });
  });
});

describe('getUserDisplayName', () => {
  describe('Name Priority', () => {
    it('should return name when available', () => {
      expect(getUserDisplayName(mockAdminUser)).toBe('Admin User');
      expect(getUserDisplayName(mockNormalUser)).toBe('Normal User');
    });

    it('should return username when name is not available', () => {
      expect(getUserDisplayName(mockDatabaseUser)).toBe('dbuser');
    });

    it('should return email when neither name nor username is available', () => {
      expect(getUserDisplayName(mockEmailOnlyUser)).toBe('emailonly@example.com');
    });
  });

  describe('Null User Handling', () => {
    it('should return "User" when user is null', () => {
      expect(getUserDisplayName(null)).toBe('User');
    });
  });

  describe('Edge Cases', () => {
    it('should prefer name over username', () => {
      const userWithBoth: User = {
        ...mockDatabaseUser,
        name: 'Display Name',
        username: 'username',
      };
      expect(getUserDisplayName(userWithBoth)).toBe('Display Name');
    });

    it('should prefer username over email', () => {
      const userWithUsernameAndEmail: User = {
        ...mockEmailOnlyUser,
        username: 'testuser',
      };
      expect(getUserDisplayName(userWithUsernameAndEmail)).toBe('testuser');
    });
  });
});

describe('isAuthenticated', () => {
  describe('Type Guard Functionality', () => {
    it('should return true for non-null user', () => {
      expect(isAuthenticated(mockAdminUser)).toBe(true);
      expect(isAuthenticated(mockNormalUser)).toBe(true);
      expect(isAuthenticated(mockDatabaseUser)).toBe(true);
    });

    it('should return false for null user', () => {
      expect(isAuthenticated(null)).toBe(false);
    });
  });

  describe('TypeScript Type Guard', () => {
    it('should narrow user type when true', () => {
      const user: User | null = mockAdminUser;

      if (isAuthenticated(user)) {
        // TypeScript should know user is User here
        expect(user.email).toBe('admin@example.com');
      }
    });
  });
});

describe('getUserRole', () => {
  describe('Role Extraction', () => {
    it('should return admin role for admin user', () => {
      expect(getUserRole(mockAdminUser)).toBe('admin');
    });

    it('should return normal role for normal user', () => {
      expect(getUserRole(mockNormalUser)).toBe('normal');
      expect(getUserRole(mockDatabaseUser)).toBe('normal');
    });
  });

  describe('Null User Handling', () => {
    it('should return null when user is null', () => {
      expect(getUserRole(null)).toBeNull();
    });
  });

  describe('Integration with Other Functions', () => {
    it('should be consistent with hasRole', () => {
      const adminRole = getUserRole(mockAdminUser);
      const normalRole = getUserRole(mockNormalUser);

      expect(hasRole(mockAdminUser, adminRole!)).toBe(true);
      expect(hasRole(mockNormalUser, normalRole!)).toBe(true);
    });
  });
});

describe('Utility Functions Integration', () => {
  it('should work together for comprehensive user info', () => {
    const user = mockAdminUser;

    // All functions should work together
    expect(isAuthenticated(user)).toBe(true);
    expect(getUserRole(user)).toBe('admin');
    expect(hasRole(user, 'admin')).toBe(true);
    expect(getAuthMethod(user.sub)).toBe('social');
    expect(getProvider(user.sub)).toBe('google-oauth2');
    expect(getUserDisplayName(user)).toBe('Admin User');
  });

  it('should handle unauthenticated state consistently', () => {
    const user = null;

    expect(isAuthenticated(user)).toBe(false);
    expect(getUserRole(user)).toBeNull();
    expect(hasRole(user, 'admin')).toBe(false);
    expect(hasRole(user, 'normal')).toBe(false);
    expect(getUserDisplayName(user)).toBe('User');
  });

  it('should handle database user comprehensively', () => {
    const user = mockDatabaseUser;

    expect(isAuthenticated(user)).toBe(true);
    expect(getUserRole(user)).toBe('normal');
    expect(hasRole(user, 'normal')).toBe(true);
    expect(getAuthMethod(user.sub)).toBe('database');
    expect(getProvider(user.sub)).toBe('auth0');
    expect(getUserDisplayName(user)).toBe('dbuser');
  });
});
