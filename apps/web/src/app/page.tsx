/**
 * Landing Page
 *
 * Public landing page introducing the app. Auth-aware CTAs:
 * - Unauthenticated: "Browse Library" (primary) + "Add Content" (secondary, hits AuthGate)
 * - Authenticated: "Add Content" (primary) + "Browse Library" (secondary)
 *
 * Library is public — let users see value before requiring sign-in.
 */

'use client';

import Link from 'next/link';
import { useAuth } from '@/hooks/useAuth';

export default function Home() {
  const { isAuthenticated } = useAuth();

  return (
    <main className="min-h-[calc(100vh-4rem)] bg-gray-100 dark:bg-[#0f0f0f]">
      {/* Hero */}
      <section className="max-w-4xl mx-auto px-4 pt-20 pb-16 text-center">
        <h1 className="text-5xl font-extrabold tracking-tight text-gray-900 dark:text-white mb-4">
          YT Summarizer
        </h1>
        <p className="text-xl text-gray-600 dark:text-gray-400 max-w-2xl mx-auto mb-8">
          Get instant AI-powered summaries, transcripts, and key insights from any YouTube video or
          channel.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <Link
            href="/add"
            className={`inline-flex items-center gap-2 px-8 py-3 text-lg font-semibold rounded-lg transition-colors ${
              isAuthenticated
                ? 'order-1 bg-red-600 text-white hover:bg-red-700'
                : 'order-2 border-2 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            Add Content{isAuthenticated ? ' →' : ''}
          </Link>
          <Link
            href="/library"
            className={`inline-flex items-center gap-2 px-8 py-3 text-lg font-semibold rounded-lg transition-colors ${
              isAuthenticated
                ? 'order-2 border-2 border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800'
                : 'order-1 bg-red-600 text-white hover:bg-red-700'
            }`}
          >
            Browse Library{isAuthenticated ? '' : ' →'}
          </Link>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-4xl mx-auto px-4 pb-20">
        <div className="grid md:grid-cols-3 gap-6">
          <FeatureCard
            icon="🎥"
            title="Video Summaries"
            description="Paste any YouTube video URL to get an AI-generated summary with key takeaways."
          />
          <FeatureCard
            icon="📺"
            title="Channel Import"
            description="Browse a channel's entire catalog and batch-process the videos you choose."
          />
          <FeatureCard
            icon="📚"
            title="Video Library"
            description="Access transcripts, summaries, and insights for all your processed videos."
          />
        </div>
      </section>
    </main>
  );
}

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <div className="bg-white dark:bg-gray-800/50 rounded-xl border border-gray-200 dark:border-gray-700/50 p-6 text-center">
      <span className="text-4xl mb-4 block">{icon}</span>
      <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2">{title}</h3>
      <p className="text-sm text-gray-600 dark:text-gray-400">{description}</p>
    </div>
  );
}
