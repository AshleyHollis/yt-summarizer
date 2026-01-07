import type { NextConfig } from 'next';
import bundleAnalyzer from '@next/bundle-analyzer';

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
});

// Disable React Compiler in dev to reduce memory overhead
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig: NextConfig = {
  // Enable React Compiler only in production (reduces dev memory ~15-20%)
  reactCompiler: !isDev,

  // Memory optimizations for dev server (see: https://github.com/vercel/next.js/issues/54708)
  experimental: {
    webpackMemoryOptimizations: true,
    preloadEntriesOnStart: false,
    // Optimize barrel imports for heavy libraries (reduces module resolution significantly)
    // CopilotKit and icon libraries have many exports
    optimizePackageImports: [
      '@copilotkit/react-core',
      '@copilotkit/react-ui',
      '@copilotkit/runtime',
      'react-markdown',
    ],
  },

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
        hostname: 'i.ytimg.com',
        pathname: '/vi_webp/**',
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
      // Proxy health check endpoints to the backend API
      {
        source: '/health/:path*',
        destination: `${process.env.API_URL || 'http://localhost:8000'}/health/:path*`,
      },
      {
        source: '/health',
        destination: `${process.env.API_URL || 'http://localhost:8000'}/health`,
      },
    ];
  },
};

export default withBundleAnalyzer(nextConfig);

