import { defineConfig } from 'vite';
import { resolve } from 'node:path';

// Multi-page build: three entry HTML files share the same module graph so
// D3 / topojson / shared code land in common chunks.
export default defineConfig({
  root: __dirname,
  base: '/',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      input: {
        index: resolve(__dirname, 'index.html'),
        history: resolve(__dirname, 'history.html'),
        recent: resolve(__dirname, 'recent.html'),
      },
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/d3') || id.includes('node_modules/topojson')) return 'vendor-d3';
          return undefined;
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8999',
      '/ws': { target: 'ws://localhost:8999', ws: true },
    },
  },
});
