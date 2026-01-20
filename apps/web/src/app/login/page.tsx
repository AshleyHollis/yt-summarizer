/**
 * Login Page
 *
 * Public login page that displays social login options and username/password authentication.
 *
 * @module login-page
 *
 * Implementation: T022 (social login), T042 (username/password)
 */

import { LoginButton } from '@/components/auth/LoginButton';
import { UsernamePasswordForm } from '@/components/auth/UsernamePasswordForm';
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
 * Navigate to /login to access this page
 */
export default function LoginPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-purple-50 px-4">
      <div className="max-w-md w-full">
        {/* Login Card */}
        <div className="bg-white rounded-2xl shadow-xl p-8">
          {/* Logo/Branding */}
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-900 mb-2">YT Summarizer</h1>
            <p className="text-gray-600">Get instant AI-powered summaries of YouTube videos</p>
          </div>

          {/* Login Form */}
          <LoginButton />

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-300"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-white text-gray-500">Or continue with email</span>
            </div>
          </div>

          {/* Username/Password Form */}
          <UsernamePasswordForm />

          {/* Additional Info */}
          <div className="mt-8 pt-6 border-t border-gray-200">
            <p className="text-sm text-gray-600 text-center">
              New to YT Summarizer?{' '}
              <span className="text-blue-600 font-medium">Create an account by signing in</span>
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-gray-600">
          <p>
            Having trouble signing in?{' '}
            <a href="/help" className="text-blue-600 hover:underline">
              Get help
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}
