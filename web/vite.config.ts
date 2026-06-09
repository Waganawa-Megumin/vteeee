import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));

// Project pages serve under /<repo>/. Set VITE_BASE=/vteeee/ in the Pages build.
export default defineConfig({
  base: process.env.VITE_BASE ?? '/',
  plugins: [react()],
  resolve: {
    alias: {
      // Resolve the shared package to its TS source so Vite transpiles it.
      '@vteeee/shared': path.resolve(dir, '../shared/src/index.ts'),
    },
  },
});
