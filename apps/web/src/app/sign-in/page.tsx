/**
 * Login Page
 *
 * Public login page that displays social login options and username/password authentication.
 *
 * @module login-page
 *
 * Implementation: T022 (social login), T042 (username/password)
 */

import { LoginCard } from '@/components/auth/LoginCard';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Sign In | YT Summarizer',
  description: 'Sign in to access your YouTube video summaries',
};

/**
 * Login Page Component
 *
 * Displays the login page with social authentication options and username/password form.
 * Accessible to unauthenticated users.
 *
 * @example
 * Navigate to /sign-in to access this page
 */
export default function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-purple-50 dark:from-gray-900 dark:to-gray-800 px-4">
      <div className="max-w-md w-full">
        {/* Branding */}
        <div className="text-center mb-8">
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-2">YT Summarizer</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Get instant AI-powered summaries of YouTube videos
          </p>
        </div>

        <LoginCard />

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-gray-600 dark:text-gray-400">
          <p>
            Having trouble signing in?{' '}
            <a href="/help" className="text-blue-600 dark:text-blue-400 hover:underline">
              Get help
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
