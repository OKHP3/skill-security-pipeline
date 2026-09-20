import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  base: '/skillz-shield/',
  plugins: [react(), tailwindcss()],
  build: { sourcemap: false, target: 'es2022' },
});
