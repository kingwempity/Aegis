# Aegis 系统架构设计说明书

## 1. 技术架构概览
Aegis 采用主控-执行-数据三层解耦的分布式架构，优化了在小型环境下的运行效率。

### 1.1 技术栈选型
- **Web 框架**: FastAPI (Python)
- **任务队列**: Celery + Redis
- **数据库**: MySQL 8.0
- **爬虫引擎**: Playwright (Headless Chromium)
- **报告渲染**: Jinja2 + WeasyPrint

## 2. 核心模块划分

### 2.1 控制中心 (Control Center)
- **API Gateway**: 负责 RESTful 接口服务及用户鉴权。
- **Task Manager**: 管理扫描任务生命周期。
- **Report Service**: 异步处理报告生成请求。

### 2.2 扫描引擎 (Scanning Engine)
- **YAML Engine**: 兼容 Nuclei 风格的插件解析器，负责执行 `.yaml` 探测模板。
- **Crawler**: 负责目标发现，集成自动登录逻辑。
- **Requester**: 异步 HTTP 客户端，内置无害化频率控制。

### 2.3 异步任务流 (Async Workflow)
- **扫描任务**: 由 Web 端投递至 Celery，Worker 独立执行。
- **报告任务**: PDF 生成作为独立 Celery 任务执行，避免阻塞主进程。

## 3. 数据库设计
- **scan_tasks**: 存储任务元数据、状态及时间戳。
- **vulnerabilities**: 存储漏洞详情，其中 `evidence` 字段以 JSON 格式存储原始 HTTP 报文。
- **report_tasks**: 存储异步报告生成的进度与下载链接。

## 4. YAML 插件设计
插件采用声明式语法，定义请求路径、方法及匹配器（Matchers）。
```yaml
id: example-vuln
info:
  severity: high
requests:
  - method: GET
    path: ["{{BaseURL}}/test"]
    matchers:
      - type: word
        words: ["vulnerable-string"]
```

## 5. 部署方案
使用 Docker Compose 编排以下容器：
- `aegis-api`: FastAPI 服务
- `aegis-worker`: Celery 执行节点
- `aegis-db`: MySQL 数据库
- `aegis-redis`: 消息中间件

---
*文档版本：v1.0*
*作者：Aegis 架构组*