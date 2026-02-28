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
  if (!fs.existsSync('.next/standalone/server.js')) {
    fs.writeFileSync('.next/standalone/server.js', 'require("./apps/web/server.js");\n');
  }
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

console.log('[swa-build] Done');
