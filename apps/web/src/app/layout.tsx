import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "YouTube Summarizer",
  description: "Transform YouTube videos into actionable AI-powered summaries",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <nav className="border-b border-gray-200 bg-white">
          <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
            <div className="flex h-16 justify-between">
              <div className="flex">
                <Link href="/" className="flex shrink-0 items-center">
                  <span className="text-xl font-bold text-indigo-600">
                    YT Summarizer
                  </span>
                </Link>
                <div className="ml-10 flex items-center space-x-4">
                  <Link
                    href="/submit"
                    className="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                  >
                    Submit
                  </Link>
                  <Link
                    href="/library"
                    className="rounded-md px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 hover:text-gray-900"
                  >
                    Library
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
