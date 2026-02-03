import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [react()],
  css: {
    // 使用 postcss 处理 CSS，这是 Tailwind v4 的标准处理方式
    transformer: 'postcss',
  },
  build: {
    // 移除显式的 esbuild 配置，使用 Vite 7 默认的压缩器
    // 这样可以避免因缺少 esbuild 包导致的构建失败
    cssMinify: true,
    reportCompressedSize: false,
  }
})
