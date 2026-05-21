# Aegis — 基于模拟攻击的 Web 漏洞扫描系统

Aegis（宙斯盾）是一款面向小型团队与个人的轻量级 DAST（动态应用安全测试）平台。通过模拟 HTTP/浏览器攻击流量（支持 Playwright 的动态渲染场景），并使用 YAML 驱动的插件规则库来发现 Web 应用中的常见漏洞（例如：XSS、SQL 注入、命令注入、路径遍历、SSRF 等），在保证非破坏性的前提下自动化生成可读报告。

---

## 关键特性

- **YAML 插件驱动**：用声明式 YAML 定义检测请求与匹配器，方便扩展与维护检测规则。
- **混合爬虫能力**：支持静态链接提取与基于浏览器（Playwright）渲染的动态爬取。
- **LLM 驱动模拟攻击引擎**：集成大语言模型智能分析漏洞上下文，生成精准的模拟攻击载荷。
- **多用户与权限管理**：支持用户注册/登录、JWT 认证、角色权限控制。
- **可视化前端**：基于 React + Ant Design + Tailwind CSS 构建，提供任务管理、实时进度、漏洞列表与报告展示。
- **实时 WebSocket 通信**：扫描进度、漏洞发现、通知事件通过 WebSocket 实时推送至前端。
- **漏洞实验室**：内置可交互的漏洞实验环境，支持 XSS、SQL 注入等场景的复现与学习。
- **报告生成**：HTML 报告（支持导出），每个漏洞包含证据片段（HTTP 请求/响应摘要等）。
- **网络资产发现**：集成 nmap 进行局域网资产探测与服务识别。
- **审计日志**：所有关键操作自动记录审计日志，支持追溯与合规。
- **非破坏性设计**：仅验证漏洞存在，不执行破坏性后果的操作（默认策略）。

---

## 技术栈

### 前端（AFE/）
| 技术 | 版本 |
|------|------|
| React | 19.x |
| TypeScript | 5.9.x |
| Vite | 5.4.x |
| Ant Design | 6.x |
| Tailwind CSS | 4.x |
| Zustand | 5.x |
| React Router | 7.x |

### 后端（BE/）
| 技术 | 版本 |
|------|------|
| FastAPI | 0.109.0 |
| SQLAlchemy | 2.0.x |
| MySQL | 8.0 |
| Redis | 7.2.x |
| Celery | 5.3.6 |
| Playwright | 1.40.0 |
| PyJWT | 2.8.0 |
| Jinja2 | 3.1.3 |

### 基础设施
- **Docker & Docker Compose**：容器化部署，含 MySQL、Redis、API、Worker 四服务编排
- **Nginx**：生产环境反向代理，支持 HTTPS、WebSocket 升级、静态资源缓存
- **Gunicorn + Uvicorn Worker**：生产级 ASGI 服务器

---

## 目录结构

```
Aegis/
├── AFE/                          # 前端应用 — React + TypeScript + Vite
│   ├── src/
│   │   ├── components/           # React 组件（仪表盘、任务列表、漏洞列表等）
│   │   │   ├── LabHome/          # 漏洞实验室组件（实验模式、响应模拟器）
│   │   │   ├── Task/             # 扫描进度组件
│   │   │   └── ...
│   │   ├── contexts/             # React Context（认证上下文）
│   │   ├── api.ts                # API 客户端（Axios）
│   │   └── utils/                # 工具函数
│   └── package.json
├── BE/                           # 后端服务 — FastAPI + 扫描引擎 + Worker
│   ├── app/
│   │   ├── main.py               # 应用入口（路由注册、数据库迁移、中间件）
│   │   ├── api/v1/endpoints/     # REST API 路由
│   │   │   ├── auth.py           # 认证接口（登录、注册、密码修改）
│   │   │   ├── tasks.py          # 扫描任务管理
│   │   │   ├── vulnerabilities.py# 漏洞数据接口
│   │   │   ├── reports.py        # 报告管理
│   │   │   ├── stats.py          # 仪表盘统计
│   │   │   ├── discovery.py      # 网络资产发现
│   │   │   ├── lab.py            # 漏洞实验室
│   │   │   ├── users.py          # 用户管理
│   │   │   ├── profiles.py       # 扫描策略配置
│   │   │   ├── ws.py             # WebSocket 实时通信
│   │   │   └── ...
│   │   ├── models/               # SQLAlchemy 数据模型
│   │   ├── schemas/              # Pydantic 数据校验
│   │   ├── services/             # 业务逻辑层
│   │   │   ├── report.py         # 报告生成（Jinja2 渲染）
│   │   │   ├── notification_service.py  # 通知服务
│   │   │   ├── audit_log.py      # 审计日志
│   │   │   ├── network_scanner.py# 网络扫描（nmap）
│   │   │   └── ...
│   │   ├── middleware/           # 审计中间件
│   │   └── templates/            # 报告 HTML 模板
│   ├── scanner/
│   │   ├── engine/               # 扫描引擎核心
│   │   │   ├── core.py           # 传统扫描引擎（插件加载、请求发送、匹配判定）
│   │   │   ├── simulator.py      # LLM 驱动的模拟攻击引擎
│   │   │   ├── hybrid_engine.py  # 混合爬取引擎
│   │   │   ├── attack.py         # 攻击链执行
│   │   │   ├── exploitation.py   # 漏洞利用模块
│   │   │   ├── recon.py          # 信息收集
│   │   │   ├── intelligence.py   # 情报分析
│   │   │   ├── learning.py       # 自学习模块
│   │   │   ├── weaponizer.py     # 武器化模块
│   │   │   └── ...
│   │   └── plugins/vulnerabilities/  # YAML 漏洞检测插件
│   │       ├── xss-reflected.yaml
│   │       ├── sqli-probe.yaml
│   │       ├── command-injection.yaml
│   │       ├── path-traversal.yaml
│   │       ├── ssrf-probe.yaml
│   │       └── ...
│   └── worker/
│       └── celery_app.py         # Celery 异步任务处理
├── TEST/                         # 测试靶场（含登录、注入等场景）
├── docs/                         # 项目文档
├── likec4-src/                   # LikeC4 架构图源文件
├── data/                         # 运行时数据区（MySQL 持久化卷）
├── Dockerfile                    # 容器化构建（多阶段：前端构建 + 后端运行）
├── docker-compose.yml            # 一键编排部署
└── nginx.conf                    # 生产环境 Nginx 配置
```

---

## 快速开始

> 服务器部署可参考：`docs/DEPLOYMENT.md`（含 Docker Compose 一键部署、运维与升级步骤）。

### 先决条件
- Python 3.10+
- Node.js + pnpm（仅本地开发前端时需要）
- Docker & Docker Compose（推荐用于快速部署）

### 1. Docker Compose 一键运行（推荐）

在仓库根目录下执行：

```bash
docker-compose up -d --build
```

服务默认配置：
- **后端 API**：`http://localhost:8000`
- **数据库**：MySQL 8.0（端口仅内部网络暴露）
- **缓存**：Redis 7.2（端口仅内部网络暴露）
- **Worker**：Celery 异步任务处理

环境变量（可通过 `.env` 文件配置）：
- `JWT_SECRET_KEY`：JWT 签名密钥
- `JWT_EXPIRE_HOURS`：Token 过期时间
- `LLM_API_KEY`：大语言模型 API 密钥
- `LLM_BASE_URL`：LLM 接口地址（默认 Silicon Flow）
- `LLM_MODEL`：使用的 LLM 模型

### 2. 本地开发模式

**后端：**
```bash
cd BE
pip install -r ../requirements.txt
set PYTHONPATH=.
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**前端：**
```bash
cd AFE
pnpm install
pnpm run dev
```

前端开发服务器默认连接 `http://localhost:8000/api/v1`。

### 3. 运行一次简单扫描

- 通过 Web UI 创建扫描任务，或调用 API 创建任务（参考 API 章节）
- 查看扫描进度与生成报告

---

## API 接口

后端提供 REST 风格 API（以 `/api/v1` 为基准路径）：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/v1/auth/` | POST | 认证（登录、注册、密码修改、验证码） |
| `/api/v1/tasks` | GET | 列出扫描任务 |
| `/api/v1/tasks` | POST | 创建扫描任务 |
| `/api/v1/tasks/{id}` | GET/DELETE | 获取/删除任务详情 |
| `/api/v1/tasks/{id}/execution-events` | GET | 获取执行事件流 |
| `/api/v1/vulnerabilities` | GET | 漏洞列表（支持筛选） |
| `/api/v1/reports` | GET | 报告管理 |
| `/api/v1/stats` | GET | 仪表盘统计 |
| `/api/v1/discovery` | POST | 网络资产发现 |
| `/api/v1/lab` | GET/POST | 漏洞实验室管理 |
| `/api/v1/users` | CRUD | 用户管理 |
| `/api/v1/profiles` | CRUD | 扫描策略配置 |
| `/api/v1/help` | CRUD | 帮助内容管理 |
| `/api/v1/notifications` | GET/WS | 通知事件 |
| `/ws/` | WS | WebSocket 实时通信 |
| `/health` | GET | 健康检查 |

---

## 插件（YAML）格式与示例

Aegis 采用声明式 YAML 插件来描述单个检测用例。每个插件包含 meta 信息与一组 request + matchers。

**示例插件：**
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

**插件要点：**
- 支持多个 requests（同一检测逻辑可尝试多条路径或多种方法）
- matchers 支持多种类型（关键词/正则/状态码/响应头存在等）
- 请求中的 `{{BaseURL}}` 将由扫描器运行时替换为目标地址

**模拟攻击引擎增强字段：**
- `preconditions`：请求前置条件（如允许方法）
- `payload_sets`：按扫描策略（default/full/fast）定义 payload 组
- `{{payload}}`：在 path 模板中插入运行时 payload
- `matchers.type=status|regex`：支持状态码和正则匹配

**内置漏洞插件：**
- XSS（反射型跨站脚本）
- SQL 注入（内联、ThinkPHP 等）
- 命令注入
- 路径遍历
- SSRF（服务器端请求伪造）
- 配置泄露（git-config 等）
- CVE 专项检测（Django CVE-2017-12794、Drupal CVE-2019-6341、Vite CVE-2025-32395）

---

## 架构设计

项目使用 LikeC4 进行架构图建模，源文件位于 `likec4-src/architecture.c4`。

系统采用**前后端分离 + 微服务**架构：
```
┌─────────────┐     ┌─────────────────────────────────────────┐
│   Nginx     │────▶│           Aegis API (FastAPI)           │
│  (反向代理)  │     │  ├─ REST API                           │
└─────────────┘     │  ├─ WebSocket 实时通信                  │
                    │  └─ 审计中间件                           │
                    └──────────────┬──────────────────────────┘
                                   │
                    ┌──────────────┼──────────────────────────┐
                    │              │                          │
              ┌─────▼─────┐  ┌────▼────┐  ┌────────────────▼─┐
              │  MySQL    │  │ Redis   │  │  Celery Worker   │
              │  8.0      │  │ (缓存)  │  │  ├─ 扫描任务执行  │
              │ (持久化)   │  │ (Broker)│  │  ├─ Celery 队列   │
              └───────────┘  └─────────┘  └──────────────────┘
                                                │
                                    ┌───────────▼────────────┐
                                    │    Scanner Engine      │
                                    │  ├─ 核心扫描引擎        │
                                    │  ├─ LLM 模拟攻击       │
                                    │  ├─ 混合爬虫           │
                                    │  └─ YAML 插件系统      │
                                    └────────────────────────┘
```

---

## 开发与调试提示

- **扫描器核心**：`BE/scanner/engine/simulator.py` 和 `BE/scanner/engine/core.py`。要增加/修改检测逻辑或匹配器，请从这里入手。
- **插件测试**：本地调试单个插件可以写一个小脚本，使用 ScannerEngine 加载单个 YAML 并对测试目标运行。
- **报告模板**：`BE/app/templates/report.html` 使用 Jinja2 渲染，调整样式或输出格式可以修改该模板。
- **异步任务**：Celery worker 依赖 Redis broker，按需启动 worker。
- **Playwright**：如果启用浏览器爬取，安装 Playwright 并下载浏览器二进制：
  ```bash
  pip install playwright
  playwright install
  ```
- **数据库迁移**：`BE/app/migrate_db.py` 提供增量迁移脚本，支持字段自动添加。
- **审计日志**：所有关键操作通过 `BE/app/middleware/audit_middleware.py` 自动记录。

---

## 部署建议

- **生产部署**：使用 Docker Compose 编排，数据目录（`data/`）挂载为持久卷。
- **反向代理**：使用 Nginx 配置 HTTPS 与 WebSocket 升级，参考 `nginx.conf`。
- **安全加固**：
  - 修改默认 JWT 密钥
  - 启用 HTTPS
  - 限制 CORS 来源
  - 配置合理的扫描速率（QPS）与并发深度
- **资源限制**：docker-compose.yml 中已为各服务配置了内存上限，可根据实际需求调整。

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
- 扩展漏洞实验室场景

建议工作流：
- Fork 仓库 → 新建分支 → 提交 PR（附相关测试与说明）

---

## 常见问题（FAQ）

**Q: 如何增加新的检测规则？**
A: 新增 YAML 插件文件并放入插件目录（`BE/scanner/plugins/vulnerabilities/`），然后重新加载/重启扫描器。

**Q: 如何调低扫描速度防止压垮目标？**
A: 在扫描配置中调整 QPS、并发数或对单目标的重试策略。

**Q: 报告是否支持导出为 PDF？**
A: 当前模板以 HTML 输出为主，支持导出 PDF、HTML、JSON 格式。

**Q: 如何使用 LLM 模拟攻击引擎？**
A: 配置环境变量 `LLM_API_KEY`、`LLM_BASE_URL`、`LLM_MODEL` 后，扫描器会自动调用 LLM 进行智能分析。

**Q: WebSocket 连接超时怎么办？**
A: Nginx 配置中已设置 24 小时超时，若仍有问题请检查网络中间件是否限制了长连接。

---

## 致谢

Aegis 编写自愿以学习/小型团队使用为目标；如果你要在生产环境中使用，请务必进行安全审计与合规评估。
