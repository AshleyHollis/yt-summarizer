import { redirect } from 'next/navigation';

/**
 * Root page - redirects to add content page
 * Updated to trigger CI/CD pipeline validation
 */
export default function Home() {
  redirect('/add');
}
