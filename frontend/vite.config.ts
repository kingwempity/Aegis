import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    postcss: './postcss.config.js',
  },
  build: {
    reportCompressedSize: false,
    chunkSizeWarningLimit: 2000,
    target: 'esnext',
    minify: 'esbuild',
    sourcemap: false, // 禁用 sourcemap 以节省内存和磁盘空间
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('lucide-react')) return 'vendor-lucide';
            return 'vendor';
          }
        }
      }
    }
  },
  // 针对低配服务器的 worker 限制
  worker: {
    format: 'es',
    plugins: () => [react()]
  }
})
