import { redirect } from 'next/navigation';

/**
 * Root page - redirects to add content page
 */
export default function Home() {
  redirect('/add');
}

