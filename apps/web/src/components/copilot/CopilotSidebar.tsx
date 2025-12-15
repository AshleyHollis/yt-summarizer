"use client";

import { CopilotSidebar as CKSidebar } from "@copilotkit/react-ui";
import { useCopilotActions } from "@/hooks/useCopilotActions";
import { ScopeChips } from "./ScopeChips";
import { CoverageIndicator } from "./CoverageIndicator";

interface CopilotSidebarProps {
  defaultOpen?: boolean;
}

export function CopilotSidebar({ defaultOpen = false }: CopilotSidebarProps) {
  // Register copilot actions
  useCopilotActions();

  return (
    <CKSidebar
      defaultOpen={defaultOpen}
      labels={{
        title: "Ask about your videos",
        initial:
          "Hi! I can help you find information across your video library. Ask me anything about the videos you've ingested.",
      }}
      Header={() => (
        <div className="flex flex-col gap-2 border-b border-gray-200 p-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900">Copilot</h2>
            <CoverageIndicator />
          </div>
          <ScopeChips />
        </div>
      )}
    />
  );
}
