# Aegis — 基于模拟攻击的 Web 漏洞扫描系统

Aegis（宙斯盾）是一款面向小型团队与个人的轻量级 DAST（动态应用安全测试）平台。通过模拟 HTTP/浏览器攻击流量（支持 Playwright 的动态渲染场景），并使用 YAML 驱动的插件规则库来发现 Web 应用中的常见漏洞（例如：XSS、SQL 注入、配置泄露等），在保证非破坏性的前提下自动化生成可读报告。

---

## 关键特性

- YAML 插件驱动：用声明式 YAML 定义检测请求与匹配器，方便扩展与维护检测规则。
- 混合爬虫能力：支持静态链接提取与基于浏览器（Playwright）渲染的动态爬取。
- 自动登录支持：通过注入 Cookie 或凭据模拟登录，提高对授权区域的覆盖率。
- 可视化前端：基于前端应用与后端 API 交互，展示任务、进度、统计与报告。
- 报告生成：HTML 报告（可导出/下载），每个漏洞包含证据片段（HTTP 应答摘要等）。
- 非破坏性设计：仅验证漏洞存在，不执行破坏性后果性的操作（默认策略）。

---

## 架构设计

项目使用 LikeC4 进行架构图建模，源文件位于 [`likec4-src/architecture.c4`](likec4-src/architecture.c4)。

系统采用**前后端分离 + 微服务**架构，主要组件包括：

- **用户**：系统使用者（安全工程师、开发人员、管理员）
- **前端应用 (AFE)**：React + TypeScript + Ant Design 构建的 Web 界面
- **后端 API 服务**：FastAPI 构建的 RESTful API 与 WebSocket 服务
- **扫描引擎 (Scanner)**：核心漏洞扫描引擎，执行模拟攻击检测
- **异步任务处理器 (Celery Worker)**：处理后台扫描任务
- **数据库 (MySQL)**：存储扫描任务、漏洞结果和系统配置
- **消息队列 (Redis)**：Celery 消息代理和缓存
- **目标系统**：被扫描的 Web 应用程序
- **网络扫描工具 (Nmap)**：用于网络设备发现和端口扫描

---

## 目录与组件概览

项目采用**前后端分离**架构：

```
Aegis/
├── AFE/                  # 前端 (Frontend) — React + TypeScript + Vite
│   ├── src/              # 前端源码
│   ├── package.json       # 前端依赖
│   └── ...
├── BE/                   # 后端 (Backend) — FastAPI + 扫描引擎 + Worker
│   ├── app/              # FastAPI 后端应用（API endpoints、服务、报告）
│   │   ├── main.py        # 应用入口
│   │   ├── api/v1/endpoints/  # REST API 路由
│   │   ├── services/      # 业务逻辑层
│   │   └── templates/     # 报告模板
│   ├── scanner/          # 扫描引擎核心
│   │   ├── engine/        # 引擎模块（simulator/recon/attack 等）
│   │   └── plugins/       # YAML 漏洞检测插件
│   └── worker/           # Celery 异步任务处理
├── data/                 # 运行时数据区（MySQL 数据、报告等）
├── TEST/                 # 测试靶场
├── docs/                 # 项目文档
├── likec4-src/                   # LikeC4 架构图源文件
├── Dockerfile            # 容器化构建
└── docker-compose.yml    # 一键编排部署
```

核心模块：
- `BE/scanner/engine/simulator.py` — LLM 驱动的模拟攻击引擎主流程
- `BE/scanner/engine/core.py` — 传统扫描引擎（插件加载、请求发送、匹配判定）
- `BE/app/services/report.py` — 报告生成（Jinja2 模板渲染 HTML）
- `AFE/src/api.ts` — 前端 API 客户端，默认地址 `http://localhost:8000/api/v1`

---

## 快速开始

> 服务器部署可参考：`docs/DEPLOYMENT.md`（含 Docker Compose 一键部署、运维与升级步骤）。


先决条件
- Python 3.10+（或适配的 3.x 版本）
- Node.js + npm/pnpm（仅在本地开发前端时需要）
- 可选：Docker & Docker Compose（推荐用于快速部署）
- 可选：Playwright（若要启用浏览器渲染爬取）

1) 使用 Docker Compose（推荐 — 一键运行）
- 在仓库根目录下：
  docker-compose up -d --build
- 默认服务会在容器内部启动后端 API、Worker 与静态文件托管。

2) 本地开发模式
- 后端：
  ```bash
  cd BE
  pip install -r ../requirements.txt
  set PYTHONPATH=.
  uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
  ```
- 前端：
  ```bash
  cd AFE
  pnpm install
  pnpm run dev
  ```

3) 运行一次简单扫描（示例）
- 通过 UI 创建一个扫描任务或调用 API 创建任务（参考 API 节）
- 查看扫描进度与生成报告（HTML）

---

## 插件（YAML）格式与示例

Aegis 采用声明式 YAML 插件来描述单个检测用例。每个插件包含 meta 信息与一组 request + matchers。

示例插件（示意）：
```yaml
id: example-vuln
info:
  name: Example Vulnerability
  severity: high
  description: "示例：通过响应中包含特定字符串判断漏洞存在"
requests:
  - method: GET
    path:
      - "{{BaseURL}}/test"
    headers:
      User-Agent: "AegisScanner/1.0"
    matchers:
      - type: word
        words:
          - "vulnerable-string"
```

插件要点
- 支持多个 requests（同一检测逻辑可尝试多条路径或多种方法）
- matchers 支持多种类型（关键词/正则/状态码/响应头存在等）
- 请求中的 `{{BaseURL}}` 将由扫描器运行时替换为目标地址


新增（模拟攻击引擎增强）字段：
- `preconditions`：请求前置条件（如允许方法）。
- `payload_sets`：按扫描策略（default/full/fast）定义 payload 组。
- `{{payload}}`：在 path 模板中插入运行时 payload。
- `matchers.type=status|regex`：支持状态码和正则匹配。


---

## 常用 API（示例）

后端提供 REST 风格 API（以 `/api/v1` 为基准路径）用于任务管理、状态、报告与漏洞数据导出。常见接口包括：
- GET /api/v1/dashboard — 仪表盘统计
- POST /api/v1/tasks — 创建扫描任务
- GET /api/v1/tasks — 列出扫描任务
- POST /api/v1/tasks/{id}/stop — 停止任务
- GET /api/v1/vulnerabilities — 获取漏洞列表（支持按 severity 筛选）
- GET /api/v1/reports — 列出/下载报告

（实际路由请参照 BE/app/api/ 目录下的 endpoints 实现）

---

## 开发与调试提示

- 扫描器核心：`BE/scanner/engine/simulator.py` 和 `BE/scanner/engine/core.py`。要增加/修改检测逻辑或匹配器，请从这里入手。
- 插件测试：本地调试单个插件可以写一个小脚本，使用 ScannerEngine 加载单个 YAML 并对测试目标运行。
- 报告模板：`BE/app/templates/report.html` 使用 Jinja2 渲染，调整样式或输出格式可以修改该模板。
- 异步任务：若启用 Celery/worker，请确保 broker（如 Redis）配置正确，并按需启动 worker。
- Playwright：如果启用浏览器爬取，安装 Playwright 并下载浏览器二进制：
  pip install playwright
  playwright install

---

## 部署建议

- 生产部署请使用容器化方案（Docker Compose / Kubernetes），并将数据目录（例如 data/）挂载为持久卷。
- 在生产中应启用 HTTPS、反向代理（如 Nginx），并对外暴露的接口进行鉴权与访问控制（默认项目仅作演示，务必补充认证/授权）。
- 控制扫描速率（QPS）与并发深度，避免对目标造成服务中断；确认在扫描器中提供频率控制配置。

---

## 法律与安全注意事项

- 确保你对目标拥有授权后再进行扫描与测试。未经授权的扫描可能触犯法律或导致服务中断。
- Aegis 的设计目标是"非破坏性验证"，但实际检测逻辑可能在极端情况下对目标造成影响，请在测试前评估风险并在隔离环境中先行验证。
- 请不要在生产关键系统上直接运行未经审计的自定义插件。

---

## 贡献与扩展

欢迎贡献插件、改进检测逻辑与增强前端展示：
- 提交插件示例与文档（YAML 格式）
- 改进匹配器（支持更复杂的语义/上下文判断）
- 增加扫描策略（快速/全面/自定义）与更细粒度的速率控制
- 添加认证机制与用户管理

建议工作流：
- Fork 仓库 → 新建分支 → 提交 PR（附相关测试与说明）

---

## 常见问题（FAQ）

Q: 如何增加新的检测规则？
A: 新增 YAML 插件文件并放入插件目录（`BE/scanner/plugins/vulnerabilities/`），然后重新加载/重启扫描器或在运行时支持热加载。

Q: 如何调低扫描速度防止压垮目标？
A: 在扫描配置中调整 QPS、并发数或对单目标的重试策略。

Q: 报告是否支持导出为 PDF？
A: 当前模板以 HTML 输出为主；若需要 PDF，可在部署环境中添加 wkhtmltopdf 或 headless 浏览器将 HTML 转为 PDF。

---

## 致谢与许可

Aegis 编写自愿以学习/小型团队使用为目标；如果你要在生产环境中使用，请务必进行安全审计与合规评估。
