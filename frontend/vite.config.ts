import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  css: {
    // Tailwind CSS v4 推荐在遇到 LightningCSS 兼容性问题时显式配置
    transformer: 'postcss',
    minify: true,
  },
  build: {
    // 使用 esbuild 压缩 CSS 以避免 LightningCSS 对 Tailwind v4 语法的误报
    cssMinify: 'esbuild',
    reportCompressedSize: false,
  }
})
