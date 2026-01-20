import { redirect } from 'next/navigation';

/**
 * Root page - redirects to add content page
 * Test deployment with full preview workflow - Auth0 integration test
 */
export default function Home() {
  redirect('/add');
}
