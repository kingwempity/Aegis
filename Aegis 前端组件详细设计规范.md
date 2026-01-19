# Aegis 前端组件详细设计规范

## 1. 技术栈选型
- **框架**: React 18 (Hooks)
- **样式**: TailwindCSS + Ant Design 5.0
- **状态管理**: Zustand (轻量级)
- **图标**: Ant Design Icons / Lucide React
- **代码高亮**: react-syntax-highlighter

## 2. UI 风格指南 (简洁白)
- **背景**: `#f5f5f5` (页面), `#ffffff` (卡片)
- **主色**: `#1677ff` (Ant Blue)
- **文字**: `#262626` (标题), `#595959` (正文)
- **边框**: `#d9d9d9`
- **阴影**: `0 2px 8px rgba(0, 0, 0, 0.06)`

## 3. 核心组件树结构
```text
src/
├── components/
│   ├── Layout/
│   │   ├── Sidebar.tsx      # 侧边导航
│   │   └── Header.tsx       # 顶栏 (用户信息、全局搜索)
│   ├── Task/
│   │   ├── ScanProgress.tsx # 动态进度条
│   │   └── TaskTable.tsx    # 任务列表表格
│   └── Vuln/
│       ├── TrafficViewer.tsx # HTTP 报文查看器 (左右分栏)
│       └── SeverityBadge.tsx # 漏洞等级标签
├── pages/
│   ├── Dashboard.tsx        # 统计概览
│   ├── TaskDetail.tsx       # 任务详情与实时日志
│   └── VulnAudit.tsx        # 漏洞审计与修复建议
└── hooks/
    └── useWebSocket.ts      # 实时状态同步 Hook
```

## 4. 关键页面交互逻辑

### 4.1 任务详情页 (TaskDetail)
- **实时性**: 进入页面后自动建立 WebSocket 连接，监听 `PROGRESS` 和 `VULN_FOUND` 消息。
- **日志流**: 采用自动滚动到底部的日志控制台，展示当前扫描的 URL。

### 4.2 漏洞审计页 (VulnAudit)
- **对比视图**: 左侧展示原始 Request，右侧展示 Response，高亮显示 Payload 触发位置。
- **修复建议**: 采用 Markdown 渲染展示内置的修复方案。

## 5. 状态管理 (Zustand)
```typescript
interface ScanStore {
  activeTasks: string[];
  addTaskId: (id: string) => void;
  removeTaskId: (id: string) => void;
}
```

---
*文档版本：v1.0*
*作者：Aegis 架构组*