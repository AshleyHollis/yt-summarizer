'use client';

import { useState, useEffect } from "react";
import { useScope } from "@/app/providers";
import { getClientApiUrl } from "@/services/runtimeConfig";

interface TopicCount {
  facetId: string;
  name: string;
  type: string;
  videoCount: number;
  segmentCount: number;
}

interface TopicsPanelProps {
  onTopicClick?: (facetId: string) => void;
}

export function TopicsPanel({ onTopicClick }: TopicsPanelProps) {
  const [topics, setTopics] = useState<TopicCount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { scope, addFacet } = useScope();

  useEffect(() => {
    const fetchTopics = async () => {
      const API_URL = getClientApiUrl();
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(`${API_URL}/api/v1/copilot/topics`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scope }),
        });

        if (!response.ok) {
          throw new Error('Failed to fetch topics');
        }

        const data = await response.json();
        setTopics(data.topics || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load topics');
      } finally {
        setLoading(false);
      }
    };

    fetchTopics();
  }, [scope]);

  const handleTopicClick = (facetId: string) => {
    addFacet(facetId);
    onTopicClick?.(facetId);
  };

  if (loading) {
    return (
      <div className="p-4">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Topics in Scope</h3>
        <div className="animate-pulse space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-6 bg-gray-100 rounded" />
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Topics in Scope</h3>
        <p className="text-sm text-red-500">{error}</p>
      </div>
    );
  }

  if (topics.length === 0) {
    return (
      <div className="p-4">
        <h3 className="text-sm font-medium text-gray-900 mb-3">Topics in Scope</h3>
        <p className="text-sm text-gray-500">No topics found in the current scope.</p>
      </div>
    );
  }

  return (
    <div className="p-4">
      <h3 className="text-sm font-medium text-gray-900 mb-3">Topics in Scope</h3>
      <div className="flex flex-wrap gap-2">
        {topics.slice(0, 15).map((topic) => (
          <TopicChip
            key={topic.facetId}
            topic={topic}
            onClick={() => handleTopicClick(topic.facetId)}
          />
        ))}
      </div>
      {topics.length > 15 && (
        <p className="mt-2 text-xs text-gray-500">+{topics.length - 15} more topics</p>
      )}
    </div>
  );
}

interface TopicChipProps {
  topic: TopicCount;
  onClick: () => void;
}

function TopicChip({ topic, onClick }: TopicChipProps) {
  const getTypeColor = (type: string): string => {
    switch (type.toLowerCase()) {
      case 'topic':
        return 'bg-blue-50 text-blue-700 hover:bg-blue-100';
      case 'format':
        return 'bg-green-50 text-green-700 hover:bg-green-100';
      case 'level':
        return 'bg-purple-50 text-purple-700 hover:bg-purple-100';
      default:
        return 'bg-gray-50 text-gray-700 hover:bg-gray-100';
    }
  };

  return (
    <button
      onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium transition-colors ${getTypeColor(topic.type)}`}
    >
      <span>{topic.name}</span>
      <span className="text-gray-400">({topic.videoCount})</span>
    </button>
  );
}
