import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  // Enable React Compiler (React 19)
  reactCompiler: true,

  // Environment variables that are exposed to the browser
  // NEXT_PUBLIC_* variables are automatically exposed
  env: {
    // Internal API URL (for server-side requests)
    API_URL: process.env.API_URL || 'http://localhost:8000',
  },

  // Image optimization configuration for YouTube thumbnails
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'i.ytimg.com',
        pathname: '/vi/**',
      },
      {
        protocol: 'https',
        hostname: 'yt3.ggpht.com',
        pathname: '/**',
      },
      {
        protocol: 'https',
        hostname: 'img.youtube.com',
        pathname: '/vi/**',
      },
    ],
  },

  // Redirect API requests to the backend during development
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.API_URL || 'http://localhost:8000'}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;

