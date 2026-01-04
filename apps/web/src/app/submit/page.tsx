import { Metadata } from 'next';
import Link from 'next/link';
import SubmitVideoForm from '@/components/SubmitVideoForm';

export const metadata: Metadata = {
  title: 'Submit Video | YouTube Summarizer',
  description: 'Submit a YouTube video to extract transcripts and generate AI-powered summaries.',
};

/**
 * Submit Video Page
 *
 * Allows users to paste a YouTube URL and submit it for processing.
 */
export default function SubmitPage() {
  return (
    <main className="min-h-[calc(100vh-4rem)] bg-gray-100 dark:bg-[#0f0f0f]">
      {/* Main Content */}
      <div className="max-w-4xl mx-auto px-4 py-6">
        {/* Hero Section - Compact */}
        <section className="text-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
            Get AI-Powered Video Summaries
          </h1>
          <p className="text-gray-700 dark:text-gray-300 max-w-xl mx-auto">
            Paste a YouTube URL to extract transcripts and generate summaries
          </p>
        </section>

        {/* Submit Form */}
        <section className="bg-white dark:bg-gray-800/50 rounded-xl shadow-md border border-gray-300 dark:border-gray-700/50 p-5 md:p-6">
          <SubmitVideoForm />
        </section>

        {/* Channel Ingestion CTA */}
        <section className="mt-5 text-center">
          <Link
            href="/ingest"
            className="inline-flex items-center gap-2 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:text-red-600 dark:hover:text-red-400 transition-colors"
          >
            <ChannelIcon />
            Want to ingest multiple videos from a channel?
          </Link>
        </section>

        {/* Features Section - Compact */}
        <section className="mt-8 grid md:grid-cols-3 gap-6">
          <FeatureCard
            icon={<TranscriptIcon />}
            title="Transcript Extraction"
            description="Automatically extract captions from any YouTube video."
          />
          <FeatureCard
            icon={<SummaryIcon />}
            title="AI Summaries"
            description="Generate summaries with key points and takeaways."
          />
          <FeatureCard
            icon={<RelatedIcon />}
            title="Related Videos"
            description="Discover related content via embeddings."
          />
        </section>
      </div>

      {/* Footer - Minimal */}
      <footer className="border-t border-gray-200 dark:border-gray-800 mt-auto">
        <div className="max-w-4xl mx-auto px-4 py-4 text-center text-xs text-gray-500 dark:text-gray-400">
          Built with Next.js, FastAPI, and OpenAI
        </div>
      </footer>
    </main>
  );
}

/**
 * Feature card component
 */
interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
}

function FeatureCard({ icon, title, description }: FeatureCardProps) {
  return (
    <div className="text-center p-4 rounded-lg bg-white dark:bg-gray-800/30 border border-gray-300 dark:border-gray-700/30 shadow-sm">
      <div className="inline-flex items-center justify-center w-10 h-10 rounded-lg bg-red-50 dark:bg-red-900/30 text-red-500 dark:text-red-400 mb-3">
        {icon}
      </div>
      <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
        {title}
      </h3>
      <p className="text-xs text-gray-600 dark:text-gray-300">{description}</p>
    </div>
  );
}

/**
 * Feature icons
 */
function TranscriptIcon() {
  return (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
      />
    </svg>
  );
}

function SummaryIcon() {
  return (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M13 10V3L4 14h7v7l9-11h-7z"
      />
    </svg>
  );
}

function RelatedIcon() {
  return (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"
      />
    </svg>
  );
}

function ChannelIcon() {
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth={2}
        d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"
      />
    </svg>
  );
}
