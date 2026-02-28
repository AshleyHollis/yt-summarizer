#!/usr/bin/env node
/**
 * SWA-aware build script for Next.js monorepo.
 * When running in Azure SWA's Oryx build context (without skip_app_build),
 * detects pre-built .next output from CI and skips the expensive Next.js rebuild.
 * Falls back to full build if .next/BUILD_ID is not present.
 */
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function cpR(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src)) {
    const sp = path.join(src, entry);
    const dp = path.join(dest, entry);
    if (fs.statSync(sp).isDirectory()) cpR(sp, dp);
    else fs.copyFileSync(sp, dp);
  }
}

// Skip rebuild if CI pre-built the app (BUILD_ID present)
if (fs.existsSync('.next/BUILD_ID')) {
  console.log('[swa-build] Pre-built .next detected — skipping Next.js rebuild');
} else {
  console.log('[swa-build] No pre-built output — running Next.js build...');
  execSync('npx next build --webpack', { stdio: 'inherit' });
}

// Set up standalone output for SWA hybrid mode
const monoServer = '.next/standalone/apps/web/server.js';
if (fs.existsSync(monoServer)) {
  // Monorepo layout: copy static/public to nested path, create wrapper
  cpR('.next/static', '.next/standalone/apps/web/.next/static');
  cpR('public', '.next/standalone/apps/web/public');
  // Always write the wrapper (overwrite to ensure latest fix is applied).
  // Force HOSTNAME=0.0.0.0 so Next.js 15+ binds to all interfaces.
  // Azure sets HOSTNAME to the container hostname, causing the server to bind
  // to a specific container IP. Azure's health probe uses loopback (127.0.0.1)
  // and can't reach the server → 582s warm-up timeout.
  fs.writeFileSync(
    '.next/standalone/server.js',
    'process.env.HOSTNAME = \'0.0.0.0\';\nrequire("./apps/web/server.js");\n'
  );
} else {
  // Standard layout: copy static/public to flat path
  cpR('.next/static', '.next/standalone/.next/static');
  cpR('public', '.next/standalone/public');
}

// Copy SWA config files
if (fs.existsSync('staticwebapp.config.json')) {
  fs.copyFileSync('staticwebapp.config.json', '.next/standalone/staticwebapp.config.json');
}
if (fs.existsSync('backend-config.json')) {
  fs.copyFileSync('backend-config.json', '.next/standalone/backend-config.json');
}

// Replace the monorepo root package.json (copied by Next.js output tracing) with a clean
// minimal one. The original has "prepare": "husky" which causes Azure Functions to fail
// on warm-up because Azure runs "npm install" on the function package and the prepare
// hook tries to invoke husky (not present in the deployed package).
const cleanPkg = { name: 'yt-summarizer-web', version: '0.1.0', private: true, engines: { node: '>=20.0.0' } };
fs.writeFileSync('.next/standalone/package.json', JSON.stringify(cleanPkg, null, 2) + '\n');

console.log('[swa-build] Done');
