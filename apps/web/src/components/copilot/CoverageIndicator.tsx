'use client';

import { useState, useEffect } from 'react';
import { useCoverage } from '@/hooks/useCopilotActions';

interface CoverageData {
  videoCount: number;
  segmentCount: number;
  channelCount: number;
}

export function CoverageIndicator() {
  const [coverage, setCoverage] = useState<CoverageData | null>(null);
  const [loading, setLoading] = useState(true);
  const { fetchCoverage } = useCoverage();

  useEffect(() => {
    const loadCoverage = async () => {
      try {
        setLoading(true);
        const data = await fetchCoverage();
        setCoverage({
          videoCount: data.videoCount,
          segmentCount: data.segmentCount,
          channelCount: data.channelCount,
        });
      } catch (error) {
        console.error('Failed to load coverage:', error);
        setCoverage(null);
      } finally {
        setLoading(false);
      }
    };

    loadCoverage();
  }, [fetchCoverage]);

  if (loading) {
    return (
      <div className="flex items-center gap-1 text-xs text-gray-400">
        <span className="animate-pulse">Loading...</span>
      </div>
    );
  }

  if (!coverage) {
    return null;
  }

  return (
    <div className="flex items-center gap-2 text-xs text-gray-500">
      <span title="Indexed videos">📹 {coverage.videoCount}</span>
      <span title="Indexed segments">📄 {coverage.segmentCount}</span>
    </div>
  );
}
