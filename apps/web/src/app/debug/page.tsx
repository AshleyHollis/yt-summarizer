"use client";

/**
 * Debug page to show build-time environment variables
 * This helps diagnose issues with environment variable injection in deployments
 */

import Link from 'next/link';

export default function DebugPage() {
  // These are evaluated at BUILD time and baked into the bundle
  const buildTimeEnv = {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL,
    NEXT_PUBLIC_ENVIRONMENT: process.env.NEXT_PUBLIC_ENVIRONMENT,
    NODE_ENV: process.env.NODE_ENV,
  };
  const runtimeConfig = typeof window !== 'undefined' ? window.__RUNTIME_CONFIG__ : undefined;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-8">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold mb-8 text-gray-900 dark:text-white">
          🐛 Debug Information
        </h1>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
            Build-Time Environment Variables
          </h2>
          <div className="space-y-2 font-mono text-sm">
            {Object.entries(buildTimeEnv).map(([key, value]) => (
              <div key={key} className="flex gap-4">
                <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                  {key}:
                </span>
                <span className="text-gray-800 dark:text-gray-200">
                  {value || '<empty string>'}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
            Runtime Information
          </h2>
          <div className="space-y-2 font-mono text-sm">
            <div className="flex gap-4">
              <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                window.location.href:
              </span>
              <span className="text-gray-800 dark:text-gray-200 break-all">
                {typeof window !== 'undefined' ? window.location.href : 'N/A (SSR)'}
              </span>
            </div>
            <div className="flex gap-4">
              <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                window.location.origin:
              </span>
              <span className="text-gray-800 dark:text-gray-200">
                {typeof window !== 'undefined' ? window.location.origin : 'N/A (SSR)'}
              </span>
            </div>
            <div className="flex gap-4">
              <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                window.__RUNTIME_CONFIG__.apiUrl:
              </span>
              <span className="text-gray-800 dark:text-gray-200 break-all">
                {runtimeConfig?.apiUrl || '<empty string>'}
              </span>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-900 dark:text-white">
            API Client Configuration
          </h2>
          <div className="space-y-2 font-mono text-sm">
            <div className="flex gap-4">
              <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                Expected API Base URL (client):
              </span>
              <span className="text-gray-800 dark:text-gray-200 break-all">
                {runtimeConfig?.apiUrl || process.env.NEXT_PUBLIC_API_URL || '<empty string>'}
              </span>
            </div>
            <div className="flex gap-4">
              <span className="font-bold text-blue-600 dark:text-blue-400 min-w-[300px]">
                Expected CopilotKit URL:
              </span>
              <span className="text-gray-800 dark:text-gray-200 break-all">
                {`${runtimeConfig?.apiUrl || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/copilotkit`}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-6 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
          <h3 className="font-semibold text-yellow-800 dark:text-yellow-200 mb-2">
            ⚠️ Important Notes
          </h3>
          <ul className="text-sm text-yellow-700 dark:text-yellow-300 space-y-1 list-disc list-inside">
            <li>NEXT_PUBLIC_ variables are baked into the build at build time</li>
            <li>runtime-config.js is applied at deploy time to set the API URL per environment</li>
            <li>Check the build logs to see what values were set during npm run build</li>
            <li>If runtime-config is empty, the app falls back to NEXT_PUBLIC_API_URL</li>
          </ul>
        </div>

        <div className="mt-6 text-center">
          <Link
            href="/"
            className="inline-block bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded-lg transition-colors"
          >
            ← Back to Home
          </Link>
        </div>
      </div>
    </div>
  );
}
