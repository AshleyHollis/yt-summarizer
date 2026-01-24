/**
 * useAuth Hook
 *
 * Provides authentication state and user information from the backend session.
 * This hook fetches the current user session from the API and manages loading state.
 */

'use client';

import { useState, useEffect } from 'react';
import { getSession, type User } from '../services/auth';

interface UseAuthResult {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  refetch: () => Promise<void>;
}

export function useAuth(): UseAuthResult {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const fetchSession = async () => {
    setIsLoading(true);
    try {
      const session = await getSession();
      setUser(session.user);
    } catch (error) {
      console.error('Failed to fetch auth session:', error);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSession();
  }, []);

  return {
    user,
    isLoading,
    isAuthenticated: user !== null,
    refetch: fetchSession,
  };
}
