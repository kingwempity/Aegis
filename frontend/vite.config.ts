import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  // 移除 base: './' 以避免在某些服务器配置下路径解析错误
  // 如果是部署在根目录，默认的 '/' 是最稳妥的
  plugins: [react()],
  css: {
    // 显式启用 PostCSS 处理
    postcss: './postcss.config.js',
  },
  build: {
    cssMinify: true,
    reportCompressedSize: false,
  }
})
