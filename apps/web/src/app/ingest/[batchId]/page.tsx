'use client';

import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { use, useState } from 'react';
import { BatchProgress } from '@/components/BatchProgress';
import { BatchDetailResponse } from '@/services/api';

interface BatchPageProps {
  params: Promise<{
    batchId: string;
  }>;
}

/**
 * Batch progress page - shows real-time progress of batch ingestion
 */
export default function BatchPage({ params }: BatchPageProps) {
  const { batchId } = use(params);
  const router = useRouter();
  const [isComplete, setIsComplete] = useState(false);
  const [completedBatch, setCompletedBatch] = useState<BatchDetailResponse | null>(null);

  /**
   * Handle batch completion
   */
  const handleComplete = (batch: BatchDetailResponse) => {
    console.log('Batch completed:', batch);
    setIsComplete(true);
    setCompletedBatch(batch);
  };

  return (
    <main className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-4 mb-4">
            <Link
              href="/ingest"
              className="text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
            >
              ← Back to Ingest
            </Link>
          </div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Batch Progress</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Track the progress of your batch video ingestion.
          </p>
        </div>

        {/* Progress component */}
        <div className="bg-white dark:bg-gray-900 rounded-xl shadow-lg p-6">
          <BatchProgress batchId={batchId} pollInterval={5000} onComplete={handleComplete} />
        </div>

        {/* Navigation buttons */}
        <div className="mt-8 flex flex-wrap gap-4">
          <Link
            href="/ingest"
            className="px-6 py-3 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
          >
            Ingest More Videos
          </Link>
          {isComplete && completedBatch && completedBatch.succeeded_count > 0 && (
            <Link
              href="/library?status=completed"
              className="px-6 py-3 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              View {completedBatch.succeeded_count} Ready Video
              {completedBatch.succeeded_count !== 1 ? 's' : ''} →
            </Link>
          )}
          <Link
            href="/library"
            className="px-6 py-3 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700"
          >
            View Library
          </Link>
        </div>
      </div>
    </main>
  );
}
