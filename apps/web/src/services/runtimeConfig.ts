export type RuntimeConfig = {
  apiUrl?: string;
};

declare global {
  interface Window {
    __RUNTIME_CONFIG__?: RuntimeConfig;
  }
}

const DEFAULT_API_URL = 'http://localhost:8000';

export function getClientApiUrl(): string {
  const runtimeApiUrl = typeof window !== 'undefined' ? window.__RUNTIME_CONFIG__?.apiUrl : undefined;
  if (runtimeApiUrl) {
    return runtimeApiUrl;
  }

  return process.env.NEXT_PUBLIC_API_URL || DEFAULT_API_URL;
}

export function getServerApiUrl(): string {
  return (
    process.env.API_URL ||
    process.env.API_BASE_URL ||
    process.env.NEXT_PUBLIC_API_URL ||
    DEFAULT_API_URL
  );
}

export function getApiBaseUrl(): string {
  return typeof window === 'undefined' ? getServerApiUrl() : getClientApiUrl();
}
