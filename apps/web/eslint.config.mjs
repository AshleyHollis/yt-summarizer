import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Build artifacts
    "playwright-report/**",
    "test-results/**",
  ]),
  // Custom rule overrides for existing codebase patterns
  {
    rules: {
      // setMounted(true) in useEffect is a standard hydration pattern in Next.js
      "react-hooks/set-state-in-effect": "warn",
      // Allow unescaped entities in JSX (quotes, apostrophes)
      "react/no-unescaped-entities": "warn",
    },
  },
]);

export default eslintConfig;
