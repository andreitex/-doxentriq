import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  plugins: [react(), {
    name: 'portal-asset-prefix',
    transformIndexHtml: {
      order: 'post',
      handler(html, context) {
        return context.path === '/portal.html' ? html.replace(/(["'])\/assets\//g, '$1/portal-assets/') : html;
      }
    }
  }],
  build: {
    outDir: 'dist', emptyOutDir: true, manifest: true,
    rolldownOptions: { input: { admin: fileURLToPath(new URL('index.html', import.meta.url)), portal: fileURLToPath(new URL('portal.html', import.meta.url)) } }
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': { target: process.env.AUTOSOFT_API_URL ?? 'http://127.0.0.1:3000', changeOrigin: false },
      '/auth': { target: process.env.AUTOSOFT_API_URL ?? 'http://127.0.0.1:3000', changeOrigin: false }
    }
  }
});
