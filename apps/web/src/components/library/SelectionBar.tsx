'use client';

import Image from 'next/image';
import { useRouter, useSearchParams } from 'next/navigation';
import { useVideoSelection } from '@/contexts/VideoSelectionContext';
import { useScope } from '@/app/providers';
import { XMarkIcon, ChatBubbleLeftRightIcon, XCircleIcon } from '@heroicons/react/20/solid';

/**
 * Floating selection bar that appears when videos are selected
 * Shows thumbnails of selected videos and provides actions
 */
export function SelectionBar() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { selectedVideos, removeFromSelection, clearSelection, exitSelectionMode } =
    useVideoSelection();
  const { setScope } = useScope();

  if (selectedVideos.length === 0) {
    return null;
  }

  const handleChatWithSelected = () => {
    // Set the scope to include only selected video IDs
    setScope({ videoIds: selectedVideos.map((v) => v.video_id) });

    // Navigate to library with chat open
    const params = new URLSearchParams(searchParams.toString());
    params.set('chat', 'open');
    router.push(`/library?${params.toString()}`);

    // Exit selection mode but keep the scope
    exitSelectionMode();
  };

  const handleClear = () => {
    clearSelection();
  };

  // Show max 5 thumbnails, then "+X more"
  const displayedVideos = selectedVideos.slice(0, 5);
  const remainingCount = selectedVideos.length - 5;

  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50 animate-in slide-in-from-bottom-4 duration-300">
      <div className="flex items-center gap-3 px-4 py-3 bg-gray-900/95 dark:bg-gray-800/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-black/30 border border-gray-700/50">
        {/* Selected count */}
        <div className="flex items-center gap-2 pr-3 border-r border-gray-600">
          <div className="w-8 h-8 rounded-lg bg-red-500 flex items-center justify-center">
            <span className="text-sm font-bold text-white">{selectedVideos.length}</span>
          </div>
          <span className="text-sm font-medium text-gray-300">
            video{selectedVideos.length !== 1 ? 's' : ''} selected
          </span>
        </div>

        {/* Thumbnail strip */}
        <div className="flex items-center gap-1">
          {displayedVideos.map((video) => {
            const thumbnailUrl =
              video.thumbnail_url ||
              `https://img.youtube.com/vi/${video.youtube_video_id}/mqdefault.jpg`;

            return (
              <div key={video.video_id} className="relative group/thumb">
                <div className="w-12 h-8 rounded-md overflow-hidden ring-2 ring-gray-600 hover:ring-red-500 transition-all">
                  <Image
                    src={thumbnailUrl}
                    alt={video.title}
                    width={48}
                    height={32}
                    className="object-cover w-full h-full"
                  />
                </div>
                {/* Remove button on hover */}
                <button
                  onClick={() => removeFromSelection(video.video_id)}
                  className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white opacity-0 group-hover/thumb:opacity-100 transition-opacity flex items-center justify-center"
                  title={`Remove ${video.title}`}
                >
                  <XMarkIcon className="w-3 h-3" />
                </button>
                {/* Tooltip */}
                <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded opacity-0 group-hover/thumb:opacity-100 transition-opacity whitespace-nowrap pointer-events-none">
                  {video.title.length > 30 ? video.title.substring(0, 30) + '...' : video.title}
                </div>
              </div>
            );
          })}
          {remainingCount > 0 && (
            <div className="w-12 h-8 rounded-md bg-gray-700 flex items-center justify-center text-xs font-medium text-gray-300">
              +{remainingCount}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 pl-3 border-l border-gray-600">
          <button
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-700 rounded-lg transition-colors"
          >
            <XCircleIcon className="w-4 h-4" />
            Clear
          </button>
          <button
            onClick={handleChatWithSelected}
            className="flex items-center gap-1.5 px-4 py-1.5 text-sm font-semibold text-white bg-red-600 hover:bg-red-700 rounded-lg transition-colors shadow-lg shadow-red-600/25"
          >
            <ChatBubbleLeftRightIcon className="w-4 h-4" />
            Chat with selected
          </button>
        </div>
      </div>
    </div>
  );
}
