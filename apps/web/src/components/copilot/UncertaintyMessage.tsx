"use client";

import { ExclamationTriangleIcon } from "@heroicons/react/20/solid";

interface UncertaintyMessageProps {
  message: string;
}

export function UncertaintyMessage({ message }: UncertaintyMessageProps) {
  return (
    <div className="rounded-lg bg-amber-50 border border-amber-200 p-3">
      <div className="flex items-start gap-2">
        <ExclamationTriangleIcon className="h-5 w-5 text-amber-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <p className="text-sm font-medium text-amber-800">
            Limited Information
          </p>
          <p className="mt-1 text-sm text-amber-700">{message}</p>
        </div>
      </div>
    </div>
  );
}
