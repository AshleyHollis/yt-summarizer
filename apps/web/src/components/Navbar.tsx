'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ThemeToggle } from '@/components/common';

/**
 * Main navigation bar component
 */
export function Navbar() {
  const pathname = usePathname();

  const isActive = (path: string) => pathname === path || pathname.startsWith(path + '/');

  return (
    <nav className="sticky top-0 z-40 border-b border-gray-200/80 dark:border-gray-800/80 bg-white/95 dark:bg-[#1a1a1a]/95 backdrop-blur-md">
      <div className="px-4 sm:px-6">
        <div className="flex h-12 items-center justify-between">
          {/* Left section: Logo and nav links */}
          <div className="flex items-center">
            <Link href="/" className="flex shrink-0 items-center gap-2">
              <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-red-500 to-rose-600 flex items-center justify-center shadow-sm shadow-red-500/20">
                <svg className="w-4 h-4 text-white" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.816v-8l8 3.993-8 4.007z"/>
                </svg>
              </div>
              <span className="text-lg font-bold bg-gradient-to-r from-red-500 to-rose-500 bg-clip-text text-transparent">
                YT Summarizer
              </span>
            </Link>
            <div className="ml-8 flex items-center space-x-1">
              <Link
                href="/add"
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive('/add') || isActive('/submit') || isActive('/ingest')
                    ? 'bg-red-500 text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-red-500/10 hover:text-red-500 dark:hover:text-red-400'
                }`}
              >
                Add
              </Link>
              <Link
                href="/library"
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
                  isActive('/library')
                    ? 'bg-red-500 text-white'
                    : 'text-gray-600 dark:text-gray-400 hover:bg-red-500/10 hover:text-red-500 dark:hover:text-red-400'
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
            </div>
          </div>

          {/* Right Side: Theme Toggle */}
          <div className="flex items-center space-x-3">
            <ThemeToggle />
          </div>
        </div>
      </div>
    </nav>
  );
}
