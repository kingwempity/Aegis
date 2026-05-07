/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // AWVS 专业风格色彩系统
        'awvs': {
          // 漏洞严重等级
          'critical': '#dc2626',
          'high': '#ea580c',
          'medium': '#ca8a04',
          'low': '#2563eb',
          'info': '#52c41a',
          
          // 背景和文本
          'bg-dark': '#1e293b',
          'bg-light': '#f8fafc',
          'sidebar': '#1e293b',
          'card': '#ffffff',
          'border': '#e2e8f0',
          'header': '#ffffff',
          
          // 文本
          'text-primary': '#1e293b',
          'text-secondary': '#64748b',
          'text-muted': '#94a3b8',
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
