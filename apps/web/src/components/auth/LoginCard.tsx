'use client';

import { LoginButton } from './LoginButton';
import { UsernamePasswordForm } from './UsernamePasswordForm';

interface LoginCardProps {
  className?: string;
}

export function LoginCard({ className }: LoginCardProps) {
  return (
    <div
      className={`bg-white dark:bg-gray-800 rounded-2xl shadow-xl dark:shadow-2xl dark:shadow-black/20 p-8${className ? ` ${className}` : ''}`}
    >
      <LoginButton />

      {/* Divider */}
      <div className="relative my-6">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-300 dark:border-gray-600"></div>
        </div>
        <div className="relative flex justify-center text-sm">
          <span className="px-4 bg-white dark:bg-gray-800 text-gray-500 dark:text-gray-400">
            Or continue with email
          </span>
        </div>
      </div>

      <UsernamePasswordForm />

      <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700">
        <p className="text-sm text-gray-600 dark:text-gray-400 text-center">
          New to YT Summarizer?{' '}
          <span className="text-blue-600 dark:text-blue-400 font-medium">
            Create an account by signing in
          </span>
        </p>
      </div>
    </div>
  );
}
