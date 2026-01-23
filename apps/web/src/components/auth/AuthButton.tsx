'use client';

import { useState, useEffect } from 'react';
import { getSession, login, logout, type Session } from '@/services/auth';

export function AuthButton() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadSession() {
      try {
        const sessionData = await getSession();
        setSession(sessionData);
      } catch (error) {
        console.error('Failed to load session:', error);
      } finally {
        setLoading(false);
      }
    }

    loadSession();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
        <div className="h-4 w-4 animate-spin rounded-full border-2 border-gray-300 border-t-blue-600" />
        Loading...
      </div>
    );
  }

  if (session?.isAuthenticated && session.user) {
    return (
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          {session.user.picture && (
            <img
              src={session.user.picture}
              alt={session.user.name}
              className="h-8 w-8 rounded-full"
            />
          )}
          <div className="hidden md:block">
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {session.user.name}
            </p>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {session.user.email}
            </p>
          </div>
        </div>
        <button
          onClick={() => logout()}
          className="rounded-md bg-gray-100 px-4 py-2 text-sm font-medium text-gray-700 transition-colors hover:bg-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:hover:bg-gray-600"
        >
          Logout
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => login(window.location.pathname)}
      className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-blue-700"
    >
      Login
    </button>
  );
}
