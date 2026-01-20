'use client';

import { MessageSquare, Trash2 } from 'lucide-react';
import styles from './ThreadedCopilotSidebar.module.css';
import { formatRelativeDate } from '@/utils/formatDate';

// ============================================================================
// Types
// ============================================================================

export interface Thread {
  id: string;
  title: string;
  updatedAt: number;
  messageCount: number;
}

interface ThreadListProps {
  threads: Thread[];
  activeThreadId: string | null;
  onSelectThread: (threadId: string) => void;
  onDeleteThread: (threadId: string) => void;
  onClose: () => void;
}

// ============================================================================
// Component
// ============================================================================

/**
 * ThreadList - Dropdown list of chat threads
 *
 * Extracted from ThreadedCopilotSidebar for better maintainability.
 */
export function ThreadList({
  threads,
  activeThreadId,
  onSelectThread,
  onDeleteThread,
  onClose,
}: ThreadListProps) {
  const sortedThreads = threads.slice().sort((a, b) => b.updatedAt - a.updatedAt);

  return (
    <div className={styles.threadDropdown}>
      {sortedThreads.map((thread) => {
        const isActive = thread.id === activeThreadId;

        return (
          <div
            key={thread.id}
            onClick={() => {
              onSelectThread(thread.id);
              onClose();
            }}
            className={`${styles.threadItem} ${isActive ? styles.active : ''}`}
          >
            <MessageSquare className={styles.threadIcon} />

            <div className={styles.threadInfo}>
              <div className={styles.threadTitle}>{thread.title}</div>
              <div className={styles.threadMeta}>
                {formatRelativeDate(thread.updatedAt)}
                {thread.messageCount > 0 && ` • ${thread.messageCount}`}
              </div>
            </div>

            {threads.length > 1 && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDeleteThread(thread.id);
                }}
                className={styles.threadDeleteBtn}
                title="Delete thread"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
          </div>
        );
      })}
    </div>
  );
}
