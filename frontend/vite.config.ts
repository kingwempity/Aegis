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
    // 针对低配服务器优化构建性能
    target: 'esnext',
    minify: 'esbuild', // 强制使用 esbuild 压缩，速度最快
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            // 将 lucide-react 单独分包，避免主包过大
            if (id.includes('lucide-react')) return 'vendor-lucide';
            return 'vendor';
          }
        }
      }
    }
  },
  // 优化依赖预构建
  optimizeDeps: {
    include: ['lucide-react'],
  }
})
