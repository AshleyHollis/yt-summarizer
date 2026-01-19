'use client';

import { Suspense } from 'react';
// Using CopilotKit Custom Sub-Components pattern
// for proper header customization without CSS conflicts
import { ThreadedCopilotSidebar } from './ThreadedCopilotSidebar';

// Wrap ThreadedCopilotSidebar in Suspense since it uses useSearchParams
interface CopilotSidebarProps {
  defaultOpen?: boolean;
}

export function CopilotSidebar(props: CopilotSidebarProps) {
  return (
    <Suspense fallback={null}>
      <ThreadedCopilotSidebar {...props} />
    </Suspense>
  );
}
