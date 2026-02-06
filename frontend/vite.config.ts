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
    // 针对服务器环境优化构建性能
    minify: 'esbuild',
    reportCompressedSize: false, // 禁用压缩大小报告以节省计算资源
    chunkSizeWarningLimit: 2000, // 进一步提高分包警告阈值
    rollupOptions: {
      output: {
        // 使用函数形式的 manualChunks 以兼容 Vite 7 (Rolldown)
        manualChunks(id) {
          if (id.includes('node_modules')) {
            if (id.includes('react')) return 'vendor-react';
            if (id.includes('lucide')) return 'vendor-icons';
            return 'vendor'; // 其他第三方库
          }
        }
      }
    }
  }
})
