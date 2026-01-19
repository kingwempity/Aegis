# Aegis 前端开发任务清单

## 阶段 1: 环境初始化与脚手架 (Day 1-2)
- [ ] 使用 Vite 初始化 React + TypeScript 项目。
- [ ] 安装并配置 TailwindCSS。
- [ ] 引入 Ant Design 5.0，并配置全局主题（简洁白风格）。
- [ ] 搭建基础路由结构 (React Router)。

## 阶段 2: 通用组件开发 (Day 3-5)
- [ ] **Layout 组件**: 实现侧边导航栏 (Sidebar) 和顶部状态栏 (Header)。
- [ ] **SeverityBadge**: 根据漏洞等级显示不同颜色的标签。
- [ ] **TrafficViewer**: 基于 `react-syntax-highlighter` 实现 HTTP 报文查看器。
- [ ] **ScanProgressBar**: 实现带有阶段状态说明的进度条组件。

## 阶段 3: 页面 UI 实现 (Day 6-8)
- [ ] **Dashboard**: 实现统计卡片和漏洞分布饼图 (ECharts/Ant Design Charts)。
- [ ] **TaskList**: 实现任务管理表格，支持分页、过滤和操作按钮。
- [ ] **TaskDetail**: 实现任务详情页布局，包含实时日志控制台。
- [ ] **VulnAudit**: 实现漏洞审计详情页，展示证据链和修复建议。

## 阶段 4: 数据交互与状态管理 (Day 9-11)
- [ ] **API 对接**: 使用 Axios 封装任务创建、列表获取、漏洞详情等接口。
- [ ] **WebSocket 集成**: 编写 `useWebSocket` Hook，实现扫描进度的实时更新。
- [ ] **全局状态**: 使用 Zustand 管理活跃任务 ID 和全局通知。

## 阶段 5: 优化与联调 (Day 12-14)
- [ ] **交互优化**: 添加页面切换动画 (Framer Motion)。
- [ ] **响应式适配**: 确保在不同屏幕尺寸下的展示效果。
- [ ] **全流程联调**: 配合后端完成从"创建任务"到"查看报告"的完整链路测试。
- [ ] **性能调优**: 优化长列表渲染，防止海量日志导致的页面卡顿。

---
*文档版本：v1.0*
*作者：Aegis 架构组*