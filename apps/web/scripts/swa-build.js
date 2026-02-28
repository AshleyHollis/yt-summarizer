#!/usr/bin/env node
/**
 * SWA-aware build script for Next.js monorepo.
 * When running in Azure SWA's Oryx build context (without skip_app_build),
 * detects pre-built .next output from CI and skips the expensive Next.js rebuild.
 * Falls back to full build if .next/BUILD_ID is not present.
 *
 * next.config.ts sets outputFileTracingRoot: path.resolve(__dirname) which forces
 * a flat standalone structure (server.js, .next/, node_modules/ at root, no apps/web/ nesting).
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

// Copy static assets and public files into the standalone directory.
// With outputFileTracingRoot = __dirname (apps/web/), the standalone is FLAT:
//   standalone/server.js       ← actual Next.js server
//   standalone/.next/server/   ← server-side bundles (traced by Next.js)
//   standalone/node_modules/   ← traced runtime deps
// We only need to copy the client-side static assets and public files.
const monoServer = '.next/standalone/apps/web/server.js';
if (fs.existsSync(monoServer)) {
  // Legacy monorepo layout (outputFileTracingRoot not effective yet): copy to nested path
  cpR('.next/static', '.next/standalone/apps/web/.next/static');
  cpR('public', '.next/standalone/apps/web/public');
  // Write wrapper that forces binding to all interfaces
  fs.writeFileSync(
    '.next/standalone/server.js',
    'process.env.HOSTNAME = \'0.0.0.0\';\nrequire("./apps/web/server.js");\n'
  );
  // Replace monorepo root package.json (has "prepare": "husky") with a clean version
  const cleanPkg = { name: 'yt-summarizer-web', version: '0.1.0', private: true, engines: { node: '>=20.0.0' } };
  fs.writeFileSync('.next/standalone/package.json', JSON.stringify(cleanPkg, null, 2) + '\n');
} else {
  // Flat layout (outputFileTracingRoot = apps/web/): standard Next.js standalone structure
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

console.log('[swa-build] Done');
