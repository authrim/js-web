import { defineConfig } from 'tsup';

export default defineConfig([
  // ESM and CJS builds (external @authrim/core)
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    sourcemap: true,
    minify: false,
    target: 'es2022',
    external: ['@authrim/core'],
  },
  // IIFE/UMD build for CDN (bundles @authrim/core)
  {
    entry: { 'authrim-web.umd': 'src/index.ts' },
    format: ['iife'],
    globalName: 'AuthrimWeb',
    clean: false, // Don't clean on second build
    sourcemap: true,
    minify: true,
    target: 'es2020',
    // Bundle @authrim/core into the IIFE build
    noExternal: ['@authrim/core'],
    platform: 'browser',
    // Workaround: @authrim/core package.json exports index.mjs but actual file is index.js
    esbuildOptions(options) {
      options.alias = {
        '@authrim/core': './node_modules/@authrim/core/dist/index.js',
      };
    },
  },
]);
