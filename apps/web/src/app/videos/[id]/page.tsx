import { redirect } from 'next/navigation';

/**
 * Video Detail Page - Redirect to Library
 *
 * This page now redirects to /library/[videoId] for consolidated video viewing.
 * Kept for backwards compatibility with existing links.
 */
export default async function VideoDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  redirect(`/library/${id}`);
}
