# Aegis 前端项目

## 项目简介

Aegis（宙斯盾）前端界面，采用 React 18 + TypeScript + Ant Design 5.0 构建，风格简约，类似 AWVS。

## 技术栈

- **框架**: React 18 (Hooks)
- **语言**: TypeScript
- **UI 库**: Ant Design 5.0
- **样式**: TailwindCSS（可选）+ Ant Design 主题
- **路由**: React Router v7
- **状态管理**: Zustand
- **HTTP 客户端**: Axios
- **代码高亮**: react-syntax-highlighter
- **Markdown 渲染**: react-markdown

## 项目结构

```
src/
├── components/          # 组件
│   ├── Layout/         # 布局组件
│   │   ├── Sidebar.tsx # 侧边栏
│   │   └── Header.tsx  # 顶部栏
│   ├── Task/           # 任务相关组件
│   │   └── ScanProgress.tsx
│   └── Vuln/           # 漏洞相关组件
│       ├── SeverityBadge.tsx
│       └── TrafficViewer.tsx
├── pages/              # 页面
│   ├── Dashboard.tsx  # 仪表盘
│   ├── TaskList.tsx   # 任务列表
│   ├── TaskDetail.tsx # 任务详情
│   └── VulnAudit.tsx  # 漏洞审计
├── hooks/              # 自定义 Hooks
│   └── useWebSocket.ts
├── store/              # 状态管理
│   └── scanStore.ts
├── App.tsx            # 主应用组件
└── main.tsx           # 入口文件
```

## 安装依赖

```bash
cd frontend
npm install
```

## 开发

```bash
npm run dev
```

访问 http://localhost:5173

## 构建

```bash
npm run build
```

## 设计规范

### 色彩方案

- **背景色**: `#f5f5f5` (页面), `#ffffff` (卡片)
- **主色调**: `#1677ff` (Ant Design Blue)
- **文字颜色**: `#262626` (标题), `#595959` (正文), `#8c8c8c` (辅助文字)
- **边框颜色**: `#d9d9d9`
- **阴影**: `0 2px 8px rgba(0, 0, 0, 0.06)`

### 状态颜色

- 成功: `#52c41a`
- 警告: `#faad14`
- 错误: `#ff4d4f`
- 信息: `#1677ff`

## 功能特性

### 已实现

- ✅ 整体布局（侧边栏 + 顶部栏）
- ✅ 仪表盘页面（统计卡片）
- ✅ 任务列表页面（表格、筛选、操作）
- ✅ 任务详情页面（实时日志、漏洞列表）
- ✅ 漏洞审计页面（漏洞列表、详情、HTTP 报文查看器）
- ✅ WebSocket 实时通信支持
- ✅ 路由配置
- ✅ 状态管理（Zustand）

### 待实现

- ⏳ 图表组件（ECharts 或 Ant Design Charts）
- ⏳ 报告中心页面
- ⏳ 设置页面
- ⏳ 完整的 API 对接
- ⏳ WebSocket 后端实现

## API 接口

默认 API 基础路径: `/api/v1`

### 任务相关

- `GET /api/v1/tasks` - 获取任务列表
- `GET /api/v1/tasks/:id` - 获取任务详情
- `POST /api/v1/tasks` - 创建任务
- `DELETE /api/v1/tasks/:id` - 删除任务

### 漏洞相关

- `GET /api/v1/vulnerabilities` - 获取漏洞列表
- `GET /api/v1/vulnerabilities/:id` - 获取漏洞详情

### WebSocket

- `ws://host/ws/tasks/:id` - 任务实时更新

## 注意事项

1. 部分功能使用模拟数据，需要对接真实 API
2. WebSocket 功能需要后端支持
3. 图表组件需要安装 ECharts 或 Ant Design Charts
4. 确保后端 API 已启动并配置 CORS

## 开发规范

- 使用 TypeScript 严格模式
- 遵循 React Hooks 最佳实践
- 组件使用函数式组件
- 样式使用 Ant Design 主题配置
- 保持代码简洁，避免过度抽象
