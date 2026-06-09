import { defineConfig } from 'vitest/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: { '@vteeee/shared': path.resolve(dir, '../shared/src/index.ts') },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
