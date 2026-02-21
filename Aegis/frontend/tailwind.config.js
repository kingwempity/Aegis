/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // AWVS 风格色彩系统
        'awvs': {
          // 漏洞严重等级
          'critical': '#ff4d4f',  // 高危 - 红色
          'high': '#ff7a45',      // 高危变体
          'medium': '#ffa940',    // 中危 - 橙色
          'low': '#1890ff',       // 低危 - 蓝色
          'info': '#52c41a',      // 信息 - 绿色
          
          // 背景和文本
          'bg-dark': '#1f1f1f',   // 深色背景
          'bg-light': '#f5f5f5',  // 浅色背景
          'sidebar': '#2d2d2d',   // 侧边栏
          'card': '#ffffff',      // 卡片
          'border': '#e8e8e8',    // 边框
          
          // 文本
          'text-primary': '#000000',
          'text-secondary': '#595959',
          'text-muted': '#8c8c8c',
          'text-light': '#ffffff',
        }
      },
      fontFamily: {
        'inter': ['Inter', 'sans-serif'],
      },
      spacing: {
        'sidebar': '240px',
        'header': '56px',
      },
      borderRadius: {
        'awvs': '8px',
      }
    },
  },
  plugins: [],
}
