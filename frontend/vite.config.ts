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
    cssMinify: 'esbuild', // 如果 esbuild 不可用，Vite 会自动回退，但 esbuild 通常比 lightningcss 更快
    minify: 'esbuild',
    reportCompressedSize: false, // 禁用压缩大小报告以节省计算资源
    chunkSizeWarningLimit: 1000, // 提高分包警告阈值
    rollupOptions: {
      output: {
        // 分包策略：将第三方库打包到独立文件，减少单个文件的处理压力
        manualChunks: {
          'vendor': ['react', 'react-dom', 'lucide-react'],
        }
      }
    }
  }
})
