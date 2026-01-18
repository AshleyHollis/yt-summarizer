/**
 * UserProfile Component
 *
 * Displays authenticated user information including avatar, name, email, and role.
 *
 * @module UserProfile
 *
 * Implementation: T020
 */

'use client';

import React from 'react';
import { useAuth } from '@/hooks/useAuth';
import { getUserDisplayName } from '@/lib/auth-utils';

/**
 * UserProfile Component
 *
 * Displays user profile information when authenticated.
 * Shows a login prompt when not authenticated.
 *
 * @example
 * ```tsx
 * import { UserProfile } from '@/components/auth/UserProfile';
 *
 * export default function Header() {
 *   return (
 *     <div className="flex items-center gap-4">
 *       <UserProfile />
 *     </div>
 *   );
 * }
 * ```
 */
export function UserProfile() {
  const { user, isLoading, isAuthenticated } = useAuth();

  // Loading state
  if (isLoading) {
    return (
      <div className="animate-pulse flex items-center gap-3">
        <div className="w-10 h-10 bg-gray-200 rounded-full"></div>
        <div className="space-y-2">
          <div className="h-4 bg-gray-200 rounded w-24"></div>
          <div className="h-3 bg-gray-200 rounded w-32"></div>
        </div>
      </div>
    );
  }

  // Not authenticated
  if (!isAuthenticated || !user) {
    return (
      <div data-testid="not-authenticated" className="text-gray-600">
        Please log in
      </div>
    );
  }

  // Authenticated user
  const displayName = getUserDisplayName(user);
  const role = user['https://yt-summarizer.com/role'];
  const roleDisplay = role === 'admin' ? 'Admin' : 'User';

  return (
    <div data-testid="user-profile" className="flex items-center gap-3">
      {/* Profile Picture */}
      {user.picture ? (
        <img
          src={user.picture}
          alt={`${displayName}'s profile`}
          data-testid="profile-picture"
          className="w-10 h-10 rounded-full border-2 border-gray-200"
        />
      ) : (
        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-semibold">
          {displayName.charAt(0).toUpperCase()}
        </div>
      )}

      {/* User Info */}
      <div className="flex flex-col">
        <span data-testid="user-name" className="text-sm font-semibold text-gray-900">
          {displayName}
        </span>
        <div className="flex items-center gap-2">
          <span data-testid="user-email" className="text-xs text-gray-600">
            {user.email}
          </span>
          <span
            data-testid="user-role"
            className={`text-xs px-2 py-0.5 rounded-full font-medium ${
              role === 'admin'
                ? 'bg-purple-100 text-purple-700'
                : 'bg-blue-100 text-blue-700'
            }`}
          >
            {roleDisplay}
          </span>
        </div>
      </div>
    </div>
  );
}
