// SPDX-License-Identifier: MIT

import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Kept separate from vite.config.ts: that file configures the dev server and the
// embedded production build, neither of which the test run has any use for.
export default defineConfig({
  plugins: [react()],
  test: {
    // jsdom for all suites rather than per-file: the pure suites (ports, api,
    // primitives) do not care, and one environment keeps the config from drifting
    // out of step with which files happen to touch the DOM.
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    // Both are correctness settings, not conveniences: a spy on document.hidden or a
    // stubbed fetch that outlives its test silently changes what the next one is
    // actually asserting against.
    restoreMocks: true,
    unstubGlobals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'lcov'],
      // Only source ships in the bundle. Config, build output and the tests
      // themselves are not behavior a test could meaningfully execute, and counting
      // them turns the number into noise.
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.{ts,tsx}', 'src/test/**', 'src/main.tsx'],
    },
  },
})
