import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';
import { Navbar } from '@/components/Navbar';
import { CopilotSidebar } from '@/components/copilot';

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
});

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
});

export const metadata: Metadata = {
  title: 'YouTube Summarizer',
  description: 'Transform YouTube videos into actionable AI-powered summaries',
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-[#fafafa] dark:bg-[#0f0f0f] text-gray-900 dark:text-gray-100`}
      >
        <Providers>
          <Navbar />
          {children}
          <CopilotSidebar />
        </Providers>
      </body>
    </html>
  );
}
