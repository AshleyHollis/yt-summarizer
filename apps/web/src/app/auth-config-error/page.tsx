/**
 * Auth Configuration Error Page
 *
 * Displayed when Auth0 is not properly configured.
 * This is a graceful degradation page that informs users/admins
 * that authentication is currently unavailable.
 */

import { Suspense } from 'react';
import Link from 'next/link';

function ErrorContent({ searchParams }: { searchParams: { error?: string } }) {
  const error = searchParams.error || 'Auth0 configuration is missing or invalid';

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          {/* Warning Icon */}
          <svg
            className="mx-auto h-16 w-16 text-yellow-500"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>

          <h2 className="mt-6 text-3xl font-extrabold text-gray-900 dark:text-white">
            Authentication Configuration Error
          </h2>

          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            The authentication system is currently not configured.
          </p>
        </div>

        <div className="mt-8 bg-white dark:bg-gray-800 shadow overflow-hidden sm:rounded-lg">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-gray-900 dark:text-white">
              What happened?
            </h3>
            <div className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              <p>
                This deployment is missing required Auth0 environment variables. The application can
                still start, but authentication features are disabled.
              </p>
            </div>

            <div className="mt-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                    <path
                      fillRule="evenodd"
                      d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                      clipRule="evenodd"
                    />
                  </svg>
                </div>
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
                    Technical Details
                  </h3>
                  <div className="mt-2 text-sm text-yellow-700 dark:text-yellow-300">
                    <p className="font-mono text-xs break-all">{error}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-5">
              <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                For Administrators:
              </h4>
              <ul className="list-disc list-inside text-sm text-gray-600 dark:text-gray-400 space-y-1">
                <li>Check that AUTH0_SECRET is set</li>
                <li>Check that AUTH0_ISSUER_BASE_URL is set</li>
                <li>Check that AUTH0_CLIENT_ID is set</li>
                <li>Check that AUTH0_CLIENT_SECRET is set</li>
                <li>Verify environment variables are configured in Azure SWA settings</li>
                <li>Check deployment logs for initialization errors</li>
              </ul>
            </div>
          </div>
        </div>

        <div className="flex justify-center space-x-4">
          <Link
            href="/"
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Return to Home
          </Link>

          <button
            onClick={() => window.location.reload()}
            className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            Reload Page
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AuthConfigErrorPage({
  searchParams,
}: {
  searchParams: { error?: string };
}) {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-gray-500">Loading...</div>
        </div>
      }
    >
      <ErrorContent searchParams={searchParams} />
    </Suspense>
  );
}
