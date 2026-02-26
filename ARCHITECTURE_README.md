# Aegis 系统架构图说明

## 概述

本项目使用 LikeC4 建模工具绘制了 Aegis Web 应用程序漏洞检测系统的完整架构图。架构图文件为 `architecture.c4`，包含了系统的各个层次、组件及其相互关系。

## LikeC4 简介

LikeC4 是一个现代化的架构建模工具，它允许通过代码定义系统架构，并实时生成可视化图表。它受到 C4 模型和 Structurizr DSL 的启发，提供了更大的灵活性。

## 如何查看架构图

### 方法一：使用 LikeC4 在线 Playground

1. 访问 [LikeC4 Playground](https://likec4.dev/playground)
2. 将 `architecture.c4` 文件的内容复制粘贴到编辑器中
3. 系统会自动渲染架构图，你可以：
   - 查看不同的视图（系统整体架构、前端架构、后端架构、扫描引擎架构、数据流架构、部署架构）
   - 交互式浏览组件关系
   - 导出为 PNG 或 SVG 格式

### 方法二：安装 VS Code 扩展

1. 在 VS Code 中安装 LikeC4 扩展
2. 打开 `architecture.c4` 文件
3. 扩展会自动预览架构图
4. 可以在编辑器中实时修改并查看效果

### 方法三：安装 LikeC4 CLI

```bash
# 使用 npm 全局安装
npm install -g likec4

# 或使用 pnpm
pnpm add -g likec4

# 查看版本
likec4 --version

# 生成静态网站
likec4 build

# 启动本地预览服务器
likec4 serve
```

## 架构图视图说明

### 1. 系统整体架构 (index)
展示 Aegis 系统的整体架构和各组件之间的关系，包括：
- 用户
- 前端应用 (AFE)
- 后端 API 服务 (Aegis)
- 扫描引擎 (Scanner)
- 异步任务处理器 (Celery Worker)
- 数据库 (MySQL)
- 消息队列 (Redis)
- 目标系统
- 网络扫描工具 (Nmap)

### 2. 前端架构 (frontend_view)
展示前端应用的组件结构和页面组织，包括：
- Dashboard 页面
- Tasks 页面
- Reports 页面
- Statistics 页面
- AdminPanel 页面
- AttackEngine 页面
- API 服务层
- 认证上下文
- 主题上下文

### 3. 后端架构 (backend_view)
展示后端 API 服务的模块组织和路由结构，包括：
- API 路由层（任务管理、报告管理、统计、漏洞管理、发现、用户管理）
- 业务逻辑层（网络扫描服务、报告生成服务）
- 数据访问层（数据库模型、数据库会话）
- WebSocket 服务

### 4. 扫描引擎架构 (scanner_view)
展示核心扫描引擎的组件和工作流程，包括：
- 扫描引擎核心
- 攻击脚本生成器
- 路径探索器
- 上下文感知引擎
- 模板解析器
- 漏洞匹配器
- Payload 变体生成器

### 5. 数据流架构 (data_flow)
展示系统中的主要数据流向，从用户访问到扫描完成的完整流程。

### 6. 部署架构 (deployment)
展示系统的部署架构和容器化方案，包括：
- 前端容器 (Nginx)
- 后端容器 (Uvicorn)
- Worker 容器 (Celery)
- 数据库容器 (MySQL)
- Redis 容器 (Redis)

## 技术栈

### 前端
- React 18
- TypeScript
- Ant Design
- TailwindCSS
- Axios
- React Router

### 后端
- FastAPI
- Python 3.10+
- SQLAlchemy ORM
- Celery
- Redis
- MySQL 8.0

### 扫描引擎
- Python asyncio
- httpx
- Nmap
- YAML 插件系统

### 部署
- Docker
- Docker Compose
- Nginx

## 系统特性

1. **YAML 插件驱动**：使用声明式 YAML 定义检测请求与匹配器
2. **混合爬虫能力**：支持静态链接提取与基于浏览器渲染的动态爬取
3. **自动登录支持**：通过注入 Cookie 或凭据模拟登录
4. **可视化前端**：展示任务、进度、统计与报告
5. **报告生成**：HTML 报告（可导出/下载）
6. **非破坏性设计**：仅验证漏洞存在，不执行破坏性操作
7. **实时进度推送**：通过 WebSocket 实时推送扫描进度
8. **异步任务处理**：使用 Celery 处理后台扫描任务

## 数据流说明

1. 用户通过前端界面创建扫描任务
2. 前端调用后端 API 提交任务
3. 后端将任务保存到 MySQL 数据库
4. 后端将任务发送到 Redis 消息队列
5. Celery Worker 从队列接收任务
6. Worker 调用扫描引擎执行扫描
7. 扫描引擎向目标系统发送攻击请求
8. 扫描引擎将发现的漏洞返回给 Worker
9. Worker 将漏洞结果保存到数据库
10. Worker 更新任务状态到 Redis
11. 后端通过 WebSocket 向前端推送进度
12. 用户可以查看扫描报告

## 架构图使用建议

1. **系统设计**：在开发新功能前，参考架构图了解系统结构
2. **代码审查**：使用架构图验证代码是否符合设计规范
3. **团队协作**：使用架构图作为团队沟通的工具
4. **文档维护**：随着系统演进，及时更新架构图
5. **新人培训**：使用架构图帮助新成员快速了解系统

## 扩展和修改

如需修改架构图，请遵循以下步骤：

1. 编辑 `architecture.c4` 文件
2. 遵循 LikeC4 语法规范
3. 保持架构图与实际代码同步
4. 在修改后重新生成可视化图表

## 参考资料

- [LikeC4 官方文档](https://likec4.dev/docs)
- [LikeC4 Playground](https://likec4.dev/playground)
- [C4 模型](https://c4model.com/)
- [Aegis 系统功能规格说明书](./Aegis 系统功能规格说明书.md)
- [Aegis 系统架构设计说明书](./Aegis 系统架构设计说明书.md)

## 许可证

本架构图遵循项目的整体许可证。