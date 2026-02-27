'use client';

import { useEffect, useState } from 'react';
import type { ChannelCard } from '@/services/api';
import { libraryApi } from '@/services/api';

interface ChannelFilterProps {
  selectedChannelId: string | null;
  onChannelChange: (channelId: string | null) => void;
}

/**
 * Channel filter dropdown for filtering videos by channel
 */
export function ChannelFilter({ selectedChannelId, onChannelChange }: ChannelFilterProps) {
  const [channels, setChannels] = useState<ChannelCard[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadChannels() {
      try {
        setLoading(true);
        const response = await libraryApi.listChannels(1, 50); // Load up to 50 channels (API max)
        setChannels(response.channels);
        setError(null);
      } catch (err) {
        setError('Failed to load channels');
        console.error('Failed to load channels:', err);
      } finally {
        setLoading(false);
      }
    }

    loadChannels();
  }, []);

  if (loading) {
    return (
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
          Channel
        </label>
        <div className="h-10 animate-pulse rounded-md bg-gray-200 dark:bg-gray-700" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="mb-4">
        <label className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300">
          Channel
        </label>
        <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="mb-4">
      <label
        htmlFor="channel-filter"
        className="mb-2 block text-sm font-medium text-gray-700 dark:text-gray-300"
      >
        Channel
      </label>
      <select
        id="channel-filter"
        value={selectedChannelId || ''}
        onChange={(e) => onChannelChange(e.target.value || null)}
        className="block w-full rounded-xl border border-gray-200 dark:border-gray-700 bg-gray-50/50 dark:bg-gray-800/50 px-3 py-2.5 text-sm text-gray-900 dark:text-gray-100 shadow-sm transition-all hover:border-red-400 focus:border-red-400 focus:bg-white dark:focus:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-red-100 dark:focus:ring-red-900/30 appearance-none cursor-pointer"
      >
        <option value="">All Channels</option>
        {channels.map((channel) => (
          <option key={channel.channel_id} value={channel.channel_id}>
            {channel.name} ({channel.video_count})
          </option>
        ))}
      </select>
    </div>
  );
}

export default ChannelFilter;
