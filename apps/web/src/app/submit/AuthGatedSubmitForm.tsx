'use client';

import { AuthGate } from '@/components/auth/AuthGate';
import { QuotaStatusPanel } from '@/components/QuotaStatusPanel';
import SubmitVideoForm from '@/components/SubmitVideoForm';

export function AuthGatedSubmitForm() {
  return (
    <AuthGate action="submit videos for processing">
      <QuotaStatusPanel />
      <div className="mt-4">
        <SubmitVideoForm />
      </div>
    </AuthGate>
  );
}
