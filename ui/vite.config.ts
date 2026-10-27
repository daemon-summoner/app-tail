// SPDX-License-Identifier: MIT

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The agent serves this build from its embedded FS, so asset URLs must be relative.
// In dev, /api and /healthz proxy to a locally running agent (see run.sh).
const apiTarget = process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8377'

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: false },
      '/healthz': { target: apiTarget, changeOrigin: false },
    },
  },
})
