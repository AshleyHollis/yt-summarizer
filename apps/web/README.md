This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Dependency Management

### Checking for unused dependencies

Run depcheck locally to scan for unused or missing dependencies:

```bash
npx depcheck
```

This uses the configuration in `.depcheckrc` and will match CI behavior. For details on why certain packages are ignored, see `.depcheckrc.md`.

### Packages that appear "unused" but are actually required

Some dependencies are used in configuration files or at build time, which static analysis can't detect. These are documented in `.depcheckrc` and include:

- **@copilotkit/runtime** - Referenced in `next.config.ts` for bundle optimization (`optimizePackageImports`)
- **@tailwindcss/postcss** - PostCSS plugin used in `postcss.config.mjs`
- **@tailwindcss/typography** - Provides `prose-*` utility classes used throughout the app
- **tailwindcss** - Core CSS framework loaded via `@import "tailwindcss"` in `src/app/globals.css`

See `.depcheckrc.md` for complete documentation.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
