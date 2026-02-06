import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    // 显式启用 PostCSS 处理
    postcss: './postcss.config.js',
  },
  build: {
    // 移除 minify: 'esbuild'，让 Vite 7 自动使用内置的 Oxc 压缩器
    reportCompressedSize: false,
    chunkSizeWarningLimit: 2000,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('lucide')) return 'vendor-icons';
            return 'vendor';
          }
        }
      }
    }
  }
})
