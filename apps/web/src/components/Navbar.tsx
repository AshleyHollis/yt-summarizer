'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ThemeToggle } from '@/components/common';
import { AuthButton } from '@/components/auth/AuthButton';
import { useAuth } from '@/hooks/useAuth';

/**
 * Main navigation bar component
 */
export function Navbar() {
  const pathname = usePathname();
  const { user } = useAuth();

  const isActive = (path: string) => pathname === path || pathname.startsWith(path + '/');

  // Check if user has admin role (Auth0 custom claim)
  const isAdmin =
    user &&
    'https://yt-summarizer.com/role' in user &&
    (user as Record<string, unknown>)['https://yt-summarizer.com/role'] === 'admin';

  return (
    <nav className="sticky top-0 z-50 w-full border-b border-gray-200 bg-white/90 backdrop-blur-sm dark:border-gray-700 dark:bg-gray-900/90">
      <div className="mx-auto max-w-7xl">
        <div className="flex h-16 items-center justify-between px-4">
          {/* Logo */}
          <Link href="/" className="flex items-center space-x-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-purple-600">
              <svg
                className="h-5 w-5 text-white"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"
                />
              </svg>
            </div>
            <span className="text-xl font-bold text-gray-900 dark:text-white">YT Summarizer</span>
          </Link>

          {/* Desktop Navigation Links */}
          <div className="hidden md:flex md:items-center md:space-x-4">
            <div className="flex space-x-1">
              <Link
                href="/add"
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive('/add')
                    ? 'bg-blue-500 text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-blue-500/10 hover:text-blue-500 dark:hover:text-blue-400'
                }`}
              >
                Add
              </Link>
              <Link
                href="/library"
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive('/library')
                    ? 'bg-green-500 text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-green-500/10 hover:text-green-500 dark:hover:text-green-400'
                }`}
              >
                Library
              </Link>
              <Link
                href="/batches"
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive('/batches')
                    ? 'bg-red-500 text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-red-500/10 hover:text-red-500 dark:hover:text-red-400'
                }`}
              >
                Jobs
              </Link>
              {isAdmin && (
                <Link
                  href="/admin"
                  className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                    isActive('/admin')
                      ? 'bg-purple-600 text-white'
                      : 'text-gray-600 dark:text-gray-400 hover:bg-purple-600/10 hover:text-purple-600 dark:hover:text-purple-400'
                  }`}
                >
                  Admin
                </Link>
              )}
            </div>
          </div>

          {/* Right Side: Auth Button & Theme Toggle */}
          <div className="flex items-center space-x-3">
            <ThemeToggle />
            <AuthButton />
          </div>
        </div>
      </div>
    </nav>
  );
}
