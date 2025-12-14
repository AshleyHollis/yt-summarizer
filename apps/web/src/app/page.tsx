import { redirect } from 'next/navigation';

/**
 * Root page - redirects to submit page
 */
export default function Home() {
  redirect('/submit');
}

