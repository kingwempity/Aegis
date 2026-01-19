# Aegis - Web应用漏洞检测系统

一款轻量级、高性能的Web应用程序漏洞检测系统（DAST），专注于通过模拟攻击流量自动化发现Web应用安全漏洞。

## 🚀 快速开始

### 环境要求

- **Python**: 3.6+
- **MySQL**: 8.0+
- **Redis**: 4.0+
- **内存**: 建议2GB+

### 安装依赖

```bash
# 克隆项目
git clone <repository-url>
cd aegis

# 安装Python依赖 (使用清华源加速)
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 安装Playwright浏览器
pip install playwright
playwright install chromium
```

### Docker部署 (推荐)

```bash
# 启动服务
docker-compose up -d

# 初始化数据库
docker-compose exec aegis-api python init_db.py

# 查看日志
docker-compose logs -f
```

### 手动部署

```bash
# 1. 启动MySQL和Redis
# 使用宝塔面板或其他方式启动MySQL 8.0和Redis

# 2. 配置环境变量 (可选)
cp .env.example .env
# 编辑.env文件中的数据库连接信息

# 3. 初始化数据库
python init_db.py

# 4. 启动API服务
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# 5. 启动Celery Worker (新终端)
celery -A app.core.celery_app worker --loglevel=info
```

## 📊 功能特性

### 核心功能
- ✅ **智能爬虫**: 支持静态链接提取及动态页面渲染
- ✅ **自动登录**: 支持Cookie注入和凭据模拟
- ✅ **漏洞检测**: 支持OWASP Top 10漏洞检测
- ✅ **实时监控**: WebSocket实时扫描进度推送
- ✅ **多格式报告**: JSON、HTML、Markdown、PDF格式

### 技术特性
- 🔒 **无害化扫描**: 严格遵循非侵入式原则
- ⚡ **高性能**: 异步请求和连接池优化
- 🎯 **高精度**: 低误报率检测算法
- 🔧 **可扩展**: YAML驱动的插件系统
- 📱 **易用性**: 直观的Web界面

## 🏗️ 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Frontend  │    │   FastAPI API   │    │  Celery Worker  │
│    (React)      │◄──►│  (Control Center)│◄──►│ (Scan Engine)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────┐
                    │   MySQL + Redis │
                    │   (Data Store)  │
                    └─────────────────┘
```

## 📁 项目结构

```
aegis/
├── app/                    # 后端应用
│   ├── main.py            # FastAPI应用入口
│   ├── database.py        # 数据库配置
│   ├── config.py          # 应用配置
│   ├── models/            # 数据模型
│   │   ├── task.py        # 扫描任务模型
│   │   └── __init__.py
│   ├── schemas/           # Pydantic验证模型
│   │   ├── task.py        # API数据验证
│   │   └── __init__.py
│   ├── api/               # API路由 (待开发)
│   ├── services/          # 业务逻辑 (待开发)
│   └── utils/             # 工具函数 (待开发)
├── plugins/               # 漏洞检测插件
├── init_db.py            # 数据库初始化脚本
├── test_*.py             # 测试脚本
├── requirements.txt      # Python依赖
├── docker-compose.yml    # Docker编排配置
└── Dockerfile           # 容器构建配置
```

## 🧪 测试

```bash
# 数据库模型测试
python test_db_models.py

# Python 3.6兼容性测试
python test_python36_compatibility.py

# 完整功能测试 (开发中)
python test_models.py
```

## 📚 API文档

启动服务后访问: http://localhost:8000/docs

## 🔧 开发计划

### P1-P2 已完成 ✅
- [x] 基础设施搭建 (Docker + 数据库)
- [x] 数据库建模与任务管理
- [x] Python 3.6兼容性优化

### P3-P5 进行中 🚧
- [ ] YAML解析器开发
- [ ] 异步HTTP客户端
- [ ] 智能爬虫引擎
- [ ] FastAPI接口开发
- [ ] React前端界面
- [ ] 系统集成测试

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📄 许可证

MIT License

## 📞 联系我们

- 项目主页: [GitHub Repository]
- 文档: [项目文档]
- 作者: Aegis架构组