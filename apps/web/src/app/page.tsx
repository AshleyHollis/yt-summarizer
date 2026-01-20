import { redirect } from 'next/navigation';

/**
 * Root page - redirects to add content page
 * Updated to trigger CI/CD pipeline validation
 * BASELINE TEST: Force deployment to test SWA warmup (no Auth0 code)
 */
export default function Home() {
  redirect('/add');
}
