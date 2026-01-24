import type { NextConfig } from 'next';
import bundleAnalyzer from '@next/bundle-analyzer';

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
});

// Disable React Compiler in dev to reduce memory overhead
const isDev = process.env.NODE_ENV !== 'production';

const nextConfig: NextConfig = {
  env: {
    API_URL: process.env.API_URL,
  },
  async rewrites() {
    try {
      const configPath = path.join(process.cwd(), 'backend-config.json');
      const configContent = fs.readFileSync(configPath, 'utf8');
      const config = JSON.parse(configContent);

      return [
        {
          source: '/api/:path*',
          destination: `${config.apiBaseUrl}/api/:path*`,
        },
      ];
    } catch (error) {
      console.warn('backend-config.json not found, skipping API rewrites');
      return [];
    }
  },
  // Removed output: 'standalone' to fix Azure SWA deployment timeout
  // Azure SWA has limited support for Next.js standalone mode
};
  },
};

export default withBundleAnalyzer(nextConfig);
