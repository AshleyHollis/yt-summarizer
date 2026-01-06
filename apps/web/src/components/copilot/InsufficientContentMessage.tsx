"use client";

import { AlertCircle, Lightbulb, Plus } from "lucide-react";
import { copilotBoxStyles, copilotTextSizes, copilotColors } from "./copilotStyles";

interface InsufficientContentMessageProps {
  message: string;
  synthesisType: "learning_path" | "watch_list";
  query?: string;
  onIngestMore?: () => void;
  onBroaderScope?: () => void;
}

/**
 * InsufficientContentMessage - Displays when synthesis can't find enough content
 * 
 * Provides helpful messaging and actionable suggestions for the user
 * to either:
 * 1. Broaden their scope/query
 * 2. Ingest more videos on the topic
 */
export function InsufficientContentMessage({
  message,
  synthesisType,
  query,
  onIngestMore,
  onBroaderScope,
}: InsufficientContentMessageProps) {
  const typeLabel = synthesisType === "learning_path" ? "learning path" : "watch list";

  return (
    <div className={`${copilotBoxStyles.static} space-y-4`}>
      {/* Header with icon */}
      <div className="flex items-start gap-3">
        <div className="flex-shrink-0 w-10 h-10 rounded-full bg-yellow-100 dark:bg-yellow-900/30 flex items-center justify-center">
          <AlertCircle className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
        </div>
        <div>
          <h3 className={`${copilotTextSizes.header} ${copilotColors.primary}`}>
            Not Enough Content
          </h3>
          <p className={`${copilotTextSizes.body} ${copilotColors.muted} mt-1`}>
            {message}
          </p>
        </div>
      </div>

      {/* Suggestions */}
      <div className={`p-4 rounded-lg ${copilotColors.bg.primary} border ${copilotColors.border.default}`}>
        <h4 className={`flex items-center gap-2 ${copilotTextSizes.small} ${copilotColors.primary} font-medium mb-3`}>
          <Lightbulb className="w-4 h-4 text-yellow-500" />
          Suggestions to create a {typeLabel}:
        </h4>
        
        <ul className="space-y-3">
          <li className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
            <strong>Try a broader query:</strong> Use more general terms related to your topic.
            {query && (
              <span className={`block mt-1 ${copilotTextSizes.small} ${copilotColors.muted}`}>
                Current query: &quot;{query}&quot;
              </span>
            )}
          </li>
          
          <li className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
            <strong>Remove scope filters:</strong> Expand your search to include all channels and topics in your library.
          </li>
          
          <li className={`${copilotTextSizes.body} ${copilotColors.primary}`}>
            <strong>Add more videos:</strong> Ingest additional videos on this topic to build up your library.
          </li>
        </ul>
      </div>

      {/* Action buttons */}
      <div className="flex flex-wrap gap-3">
        {onBroaderScope && (
          <button
            onClick={onBroaderScope}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg border ${copilotColors.border.default} ${copilotTextSizes.small} ${copilotColors.primary} font-medium hover:border-[var(--copilot-kit-primary-color)] transition-colors`}
          >
            Clear Filters
          </button>
        )}
        
        {onIngestMore && (
          <button
            onClick={onIngestMore}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--copilot-kit-primary-color)] text-white ${copilotTextSizes.small} font-medium hover:opacity-90 transition-opacity`}
          >
            <Plus className="w-4 h-4" />
            Ingest Videos
          </button>
        )}
      </div>
    </div>
  );
}

export default InsufficientContentMessage;
