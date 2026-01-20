import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    environment: 'jsdom',
    environmentOptions: {
      jsdom: {
        url: 'http://localhost:3000',
      },
    },
    globals: true,
    include: ['__tests__/**/*.test.ts'],
    setupFiles: ['__tests__/setup.ts'],
    // Allow unhandled rejections from fake timer tests that test promise rejections
    dangerouslyIgnoreUnhandledErrors: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts'],
    },
    alias: {
      '@authrim/core': path.resolve(__dirname, '__tests__/__mocks__/@authrim/core.ts'),
    },
  },
});
