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
    // Note: These packages must be listed in dependencies even if not directly imported,
    // as Next.js needs them for the optimizePackageImports feature
    optimizePackageImports: [
      '@copilotkit/react-core',
      '@copilotkit/react-ui',
      '@copilotkit/runtime', // Required here even though not directly imported
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

  // Redirect API requests to the backend during development AND preview
  // Note: Exclude .swa paths for Azure Static Web Apps health checks
  async rewrites() {
    let backendUrl = process.env.API_URL || 'http://localhost:8000';
    
    // Attempt to load dynamically injected backend URL (for CI/CD previews)
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const fs = require('fs');
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const path = require('path');
      const configPath = path.join(__dirname, 'backend-config.json');
      if (fs.existsSync(configPath)) {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config.url) {
            backendUrl = config.url;
            // Inject into env for server-side API calls (consumed by api.ts)
            process.env.API_URL = backendUrl;
            console.log(`[Next.js] Loaded backend URL from ${configPath}: ${backendUrl}`);
        }
      }
    } catch (e) {
      // Ignore errors in dev environment
    }

    return {
      beforeFiles: [
        // Exclude .swa paths from rewrites (required for SWA deployment validation)
        // SWA uses /.swa/health.html to verify deployment
      ],
      afterFiles: [
        // Generic proxy for absolute URL handling (mixed content fix)
        // Matches /api/proxy/v1/... -> http://backend/v1/...
        {
          source: '/api/proxy/:path*',
          destination: `${backendUrl}/:path*`,
        },
        {
          source: '/api/:path*',
          destination: `${backendUrl}/api/:path*`,
        },
        // Proxy health check endpoints to the backend API
        {
          source: '/health/:path*',
          destination: `${backendUrl}/health/:path*`,
        },
        {
          source: '/health',
          destination: `${backendUrl}/health`,
        },
      ],
      fallback: [],
    };
  },
};

export default withBundleAnalyzer(nextConfig);

