import type { NextConfig } from 'next';
import bundleAnalyzer from '@next/bundle-analyzer';

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
});

// Disable React Compiler in dev to reduce memory overhead
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig: NextConfig = {
  // Enable standalone output for Azure SWA deployment
  // This reduces app size and is required for hybrid rendering on SWA
  output: 'standalone',

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
  // Note: Exclude .swa paths for Azure Static Web Apps health checks
  async rewrites() {
    return {
      beforeFiles: [
        // Exclude .swa paths from rewrites (required for SWA deployment validation)
        // SWA uses /.swa/health.html to verify deployment
      ],
      afterFiles: [
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
      ],
      fallback: [],
    };
  },
};

export default withBundleAnalyzer(nextConfig);

