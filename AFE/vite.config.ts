import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: process.env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },
  css: {
    postcss: './postcss.config.js',
  },
  build: {
    reportCompressedSize: false,
    chunkSizeWarningLimit: 2000,
    target: 'esnext',
    sourcemap: false,
    emptyOutDir: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            return 'vendor';
          }
        }
      }
    }
  }
})
