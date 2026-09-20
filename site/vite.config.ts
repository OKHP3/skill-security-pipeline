import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'node:path';

export default defineConfig({
  base: '/skillz-shield/',
  plugins: [react(), tailwindcss()],
  build: {
    sourcemap: false,
    target: 'es2022',
    rollupOptions: {
      input: {
        home: resolve(import.meta.dirname, 'index.html'),
        evidence: resolve(import.meta.dirname, 'evidence/index.html'),
        engines: resolve(import.meta.dirname, 'engines/index.html'),
        integrate: resolve(import.meta.dirname, 'integrate/index.html'),
        guidance: resolve(import.meta.dirname, 'guidance/index.html'),
      },
    },
  },
});
