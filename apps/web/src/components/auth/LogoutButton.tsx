/**
 * LogoutButton Component
 *
 * Provides a button to log out the current user.
 *
 * @module LogoutButton
 *
 * Implementation: T021
 */

'use client';

import React from 'react';

/**
 * LogoutButton Props
 */
interface LogoutButtonProps {
  /** Optional className for styling */
  className?: string;
  /** Optional variant style */
  variant?: 'primary' | 'secondary' | 'text';
}

/**
 * LogoutButton Component
 *
 * Displays a logout button that clears the user session.
 * Redirects to the Auth0 logout endpoint which clears the session and redirects home.
 *
 * @param props - Component props
 *
 * @example
 * ```tsx
 * import { LogoutButton } from '@/components/auth/LogoutButton';
 *
 * export default function Header() {
 *   return (
 *     <div>
 *       <LogoutButton />
 *     </div>
 *   );
 * }
 * ```
 *
 * @example
 * ```tsx
 * // With custom styling
 * <LogoutButton variant="secondary" className="ml-4" />
 * ```
 */
export function LogoutButton({ className = '', variant = 'primary' }: LogoutButtonProps) {
  const handleLogout = () => {
    // Redirect to Auth0 logout endpoint
    window.location.href = '/api/auth/logout';
  };

  // Variant styles
  const variantStyles = {
    primary:
      'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
    secondary:
      'bg-gray-200 text-gray-700 hover:bg-gray-300 focus:ring-gray-500',
    text:
      'bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-500',
  };

  return (
    <button
      onClick={handleLogout}
      data-testid="logout-button"
      className={`
        px-4 py-2 rounded-lg font-medium transition-colors
        focus:outline-none focus:ring-2 focus:ring-offset-2
        ${variantStyles[variant]}
        ${className}
      `}
      aria-label="Sign out"
    >
      Sign Out
    </button>
  );
}
