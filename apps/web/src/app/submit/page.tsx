import { Metadata } from 'next';
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
    <main className="min-h-screen bg-gray-50 dark:bg-gray-900">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="max-w-4xl mx-auto px-4 py-6">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            YouTube Summarizer
          </h1>
          <p className="mt-1 text-gray-600 dark:text-gray-400">
            Transform YouTube videos into actionable summaries
          </p>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-4xl mx-auto px-4 py-12">
        {/* Hero Section */}
        <section className="text-center mb-12">
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white mb-4">
            Get AI-Powered Video Summaries
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            Paste a YouTube URL below and we&apos;ll extract the transcript,
            generate a comprehensive summary, and find related content.
          </p>
        </section>

        {/* Submit Form */}
        <section className="bg-white dark:bg-gray-800 rounded-xl shadow-lg p-6 md:p-8">
          <SubmitVideoForm />
        </section>

        {/* Features Section */}
        <section className="mt-16 grid md:grid-cols-3 gap-8">
          <FeatureCard
            icon={<TranscriptIcon />}
            title="Transcript Extraction"
            description="Automatically extract captions and subtitles from any YouTube video."
          />
          <FeatureCard
            icon={<SummaryIcon />}
            title="AI Summaries"
            description="Generate comprehensive summaries with key points and takeaways."
          />
          <FeatureCard
            icon={<RelatedIcon />}
            title="Related Videos"
            description="Discover semantically related content based on video embeddings."
          />
        </section>
      </div>

      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 border-t border-gray-200 dark:border-gray-700 mt-auto">
        <div className="max-w-4xl mx-auto px-4 py-6 text-center text-sm text-gray-500 dark:text-gray-400">
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
    <div className="text-center">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-lg bg-blue-100 dark:bg-blue-900 text-blue-600 dark:text-blue-400 mb-4">
        {icon}
      </div>
      <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
        {title}
      </h3>
      <p className="text-gray-600 dark:text-gray-400">{description}</p>
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
