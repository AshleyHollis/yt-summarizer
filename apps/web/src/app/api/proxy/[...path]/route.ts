import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs'; // Required for fetch with duplex option if needed, though Next.js 13+ handles web standard fetch

async function handler(req: NextRequest, props: { params: Promise<{ path: string[] }> }) {
  // Await params for Next.js 15 compatibility
  const params = await props.params;
  const path = params.path.join('/');
  const query = req.nextUrl.search;
  
  // URL priority:
  // 1. Env var API_BASE_URL (Runtime env from SWA/Container)
  // 2. Env var REAL_BACKEND_URL (Legacy support)
  // 3. backend-config.json (File injected at build time)
  let baseUrl = process.env.API_BASE_URL || process.env.REAL_BACKEND_URL;
  
  if (!baseUrl) {
    try {
      // Fallback: Try reading config file if env vars missing
      // Note: In SWA/Serverless environment, file system access might be restricted or file missing
      const fs = await import('fs');
      const configFile = process.cwd() + '/backend-config.json';
      if (fs.existsSync(configFile)) {
        const config = JSON.parse(fs.readFileSync(configFile, 'utf8'));
        baseUrl = config.url;
      }
    } catch (e) {
      // Ignore file error
      console.warn('Failed to read backend-config.json:', e);
    }
  }

  if (!baseUrl) {
    console.error('API Proxy: No backend URL configured');
    return NextResponse.json(
      { error: 'API Proxy configuration missing. Please check API_BASE_URL environment variable.' }, 
      { status: 500 }
    );
  }

  // Ensure trailing slash handling? No, path.join doesn't add it.
  // API requests usually start with /api in the path param if the route is /api/proxy/[...path]
  // BUT the preview patch routes /api to the backend.
  // If the request is /api/proxy/info -> path=['info'].
  // We want to forward to BASE_URL/info ?
  // If BASE_URL is `http://IP/api`, then `http://IP/api/info`.
  // If BASE_URL is `http://IP`, then `http://IP/api/info`.
  
  // The preview.yml sets URL to `.../api` (e.g. `https://INGRESS_IP/api`).
  // So we append the path. `.../api/info`. Correct.
  
  // Remove trailing slash from baseUrl if present
  baseUrl = baseUrl.replace(/\/$/, '');
  
  const targetUrl = `${baseUrl}/${path}${query}`;
  // console.log(`Proxying ${req.method} ${req.nextUrl.pathname} -> ${targetUrl}`);

  try {
    const headers = new Headers(req.headers);
    
    // Cleanup headers
    headers.delete('host');
    headers.delete('connection');
    headers.delete('content-length');
    
    // Add X-Forwarded headers
    headers.set('X-Forwarded-Host', req.headers.get('host') || '');
    headers.set('X-Forwarded-Proto', req.headers.get('x-forwarded-proto') || 'https');

    const fetchOptions: RequestInit = {
      method: req.method,
      headers: headers,
      cache: 'no-store',
    };

    if (req.method !== 'GET' && req.method !== 'HEAD') {
      try {
        const arrayBuffer = await req.arrayBuffer();
        if (arrayBuffer.byteLength > 0) {
          fetchOptions.body = Buffer.from(arrayBuffer);
        }
      } catch (e) {
        console.warn('Error reading request body:', e);
      }
    }

    const response = await fetch(targetUrl, fetchOptions);

    // Create response headers
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set('X-Debug-Target-Url', targetUrl);
    responseHeaders.set('X-Debug-Base-Url', baseUrl);
    
    // Fix CORS if needed (though proxy usually avoids it)
    // SWA might handle CORS on its own edge.
    
    return new NextResponse(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });

  } catch (error: any) {
    console.error('Proxy Request Failed:', error);
    return NextResponse.json(
      { error: 'Proxy Request Failed', details: error.message }, 
      { status: 502 }
    );
  }
}

export async function GET(req: NextRequest, props: any) {
  return handler(req, props);
}

export async function POST(req: NextRequest, props: any) {
  return handler(req, props);
}

export async function PUT(req: NextRequest, props: any) {
  return handler(req, props);
}

export async function DELETE(req: NextRequest, props: any) {
  return handler(req, props);
}

export async function PATCH(req: NextRequest, props: any) {
  return handler(req, props);
}

export async function HEAD(req: NextRequest, props: any) {
  return handler(req, props);
}
