import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    manifest: true,
    outDir: '../static/vite',
    emptyOutDir: true,
    rollupOptions: {
      input: 'src/main.tsx'
    }
  },
  server: {
    host: true,
    port: 5173
  }
});
