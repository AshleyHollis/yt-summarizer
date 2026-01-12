/**
 * PostCSS configuration for Tailwind CSS v4
 * 
 * Note: @tailwindcss/postcss is required even though depcheck may flag it as unused.
 * It's consumed by the PostCSS build pipeline, not imported directly in JS/TS files.
 */
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
