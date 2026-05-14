import logging
import time
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text, inspect

# 导入审计中间件
from app.middleware.audit_middleware import add_audit_middleware

# 使用别名导入以避免命名冲突
from app.api.v1.endpoints import (
    tasks, reports, stats, vulnerabilities, ws, 
    discovery as discovery_router, 
    users, profiles, auth, help, notifications,
    lab
)
from app.db.database import engine, Base, SessionLocal
from app.models import discovery as discovery_model
from app.models.help import HelpContent
from app.models.task import ScanTask, Vulnerability
from app.services.lab_init import init_lab_scenarios

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

def migrate_vulnerabilities_table():
    """
    为 vulnerabilities 表添加新字段（如果不存在）。
    
    支持增量迁移，不会影响现有数据。
    """
    # 新字段定义：(列名, 列类型SQL)
    new_columns = [
        ("attack_path", "JSON"),
        ("vuln_type", "VARCHAR(50)"),
        ("parameter", "VARCHAR(100)"),
        ("method", "VARCHAR(10)"),
        ("description", "TEXT"),
        ("remediation", "TEXT"),
        ("cvss_score", "INT"),
        ("detected_at", "DATETIME"),
    ]
    
    try:
        inspector = inspect(engine)
        
        # 检查表是否存在
        if 'vulnerabilities' not in inspector.get_table_names():
            logger.info("vulnerabilities 表不存在，将由 create_all 创建")
            return
        
        # 获取现有列
        existing_columns = {col['name'] for col in inspector.get_columns('vulnerabilities')}
        
        # 添加缺失的列
        with engine.connect() as conn:
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    try:
                        # MySQL 语法
                        sql = f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"
                        conn.execute(text(sql))
                        conn.commit()
                        logger.info(f" 添加新列: {col_name}")
                    except Exception as e:
                        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                            logger.info(f" 列已存在: {col_name}")
                        else:
                            logger.warning(f" 添加列失败 {col_name}: {e}")
                else:
                    logger.debug(f" 列已存在: {col_name}")
        
        logger.info("数据库字段迁移完成")
        
    except Exception as e:
        logger.warning(f"数据库迁移检查失败: {e}")


def migrate_lab_scenarios_table():
    """
    为 lab_scenarios 表添加新字段（如果不存在）。
    """
    new_columns = [
        ("is_auto_generated", "BOOLEAN DEFAULT FALSE"),
        ("source_scan_task_id", "INT NULL"),
        ("tags", "JSON"),
    ]
    
    try:
        inspector = inspect(engine)
        
        if 'lab_scenarios' not in inspector.get_table_names():
            logger.info("lab_scenarios 表不存在，将由 create_all 创建")
            return
        
        existing_columns = {col['name'] for col in inspector.get_columns('lab_scenarios')}
        
        with engine.connect() as conn:
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    try:
                        sql = f"ALTER TABLE lab_scenarios ADD COLUMN {col_name} {col_type}"
                        conn.execute(text(sql))
                        conn.commit()
                        logger.info(f" 添加新列: lab_scenarios.{col_name}")
                    except Exception as e:
                        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                            logger.info(f" 列已存在: lab_scenarios.{col_name}")
                        else:
                            logger.warning(f" 添加列失败 lab_scenarios.{col_name}: {e}")
                else:
                    logger.debug(f" 列已存在: lab_scenarios.{col_name}")
        
    except Exception as e:
        logger.warning(f"lab_scenarios 迁移检查失败: {e}")


def migrate_scan_tasks_display_id():
    """
    为 scan_tasks 表添加 display_id 字段并回填连续展示编号。

    注意：仅维护 display_id 的连续性，不修改主键 id。
    """
    try:
        inspector = inspect(engine)

        if 'scan_tasks' not in inspector.get_table_names():
            logger.info("scan_tasks 表不存在，将由 create_all 创建")
            return

        existing_columns = {col['name'] for col in inspector.get_columns('scan_tasks')}
        with engine.connect() as conn:
            if 'display_id' not in existing_columns:
                if engine.dialect.name == "sqlite":
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN display_id INTEGER"))
                else:
                    conn.execute(text("ALTER TABLE scan_tasks ADD COLUMN display_id INT NULL"))
                conn.commit()
                logger.info(" 已添加字段: scan_tasks.display_id")

            # 按创建顺序重建连续 display_id（1..N）
            task_ids = conn.execute(
                text("SELECT id FROM scan_tasks ORDER BY created_at ASC, id ASC")
            ).fetchall()
            for index, row in enumerate(task_ids, start=1):
                conn.execute(
                    text("UPDATE scan_tasks SET display_id = :display_id WHERE id = :task_id"),
                    {"display_id": index, "task_id": row[0]}
                )
            conn.commit()
            logger.info(f" 已回填 display_id，共处理 {len(task_ids)} 条任务记录")

            # 创建唯一索引（如果不存在）
            index_names = {idx["name"] for idx in inspector.get_indexes("scan_tasks")}
            unique_index_name = "idx_scan_tasks_display_id_unique"
            if unique_index_name not in index_names:
                conn.execute(
                    text(f"CREATE UNIQUE INDEX {unique_index_name} ON scan_tasks(display_id)")
                )
                conn.commit()
                logger.info(" 已创建唯一索引: scan_tasks.display_id")

    except Exception as e:
        logger.warning(f"display_id 迁移检查失败: {e}")


# 创建数据库表 (带重试逻辑)
max_retries = 5
retry_interval = 5

for i in range(max_retries):
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        logger.info("Database tables verified/created successfully.")
        
        # 执行增量迁移
        migrate_vulnerabilities_table()
        migrate_lab_scenarios_table()
        migrate_scan_tasks_display_id()
        
        break
    except Exception as e:
        if "already exists" in str(e):
            logger.info("Tables already exist, skipping creation.")
            # 即使表已存在，也尝试迁移
            try:
                migrate_vulnerabilities_table()
                migrate_scan_tasks_display_id()
            except Exception as migrate_err:
                logger.warning(f"Migration failed: {migrate_err}")
            break
        
        if i < max_retries - 1:
            logger.warning(f"Database connection failed (attempt {i+1}/{max_retries}). Retrying in {retry_interval}s... Error: {e}")
            time.sleep(retry_interval)
        else:
            logger.error(f"Could not connect to database after {max_retries} attempts.")

app = FastAPI(
    title="Aegis API",
    version="1.0.0"
)

# 处理 HTTPS 转发头 (解决 Mixed Content)
class HTTPSRedirectMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # 如果 X-Forwarded-Proto 是 https，则强制 request.url 也是 https
        if request.headers.get("x-forwarded-proto") == "https":
            request.scope["scheme"] = "https"
        return await call_next(request)

app.add_middleware(HTTPSRedirectMiddleware)

# 强化 CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 允许所有来源
    allow_credentials=True,
    allow_methods=["*"], # 允许所有方法 (GET, POST, etc.)
    allow_headers=["*"], # 允许所有头
    expose_headers=["*"]
)

# 全局异常处理，确保即使报错也返回 CORS 头
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global error caught: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error", "message": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*"
        }
    )

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*"
        }
    )

# 注册路由
app.include_router(tasks.router, prefix="/api/v1/tasks", tags=["Tasks"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["Stats"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(discovery_router.router, prefix="/api/v1/discovery", tags=["Discovery"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(profiles.router, prefix="/api/v1/profiles", tags=["Profiles"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(help.router, prefix="/api/v1/help", tags=["Help"])
app.include_router(notifications.router, prefix="/api/v1/notifications", tags=["Notifications"])
app.include_router(lab.router, prefix="/api/v1/lab", tags=["Vulnerability Lab"])
app.include_router(ws.router, tags=["WebSocket"])


# ==================== 初始化默认帮助内容 ====================
def init_default_help_contents():
    """
    初始化默认帮助内容。
    当数据库中没有帮助内容时，创建默认的四项内容。
    """
    db: Session = SessionLocal()
    try:
        # 检查是否已有内容
        existing_count = db.query(HelpContent).count()
        if existing_count > 0:
            logger.info(f"Help contents already exist ({existing_count} items), skipping initialization.")
            return
        
        # 默认帮助内容
        default_contents = [
            {
                "key": "quick_start",
                "title": "快速入门",
                "description": "了解如何创建第一个扫描任务，配置扫描目标。",
                "content": """## 快速入门指南

欢迎使用 Aegis 漏洞扫描系统！本指南将帮助您快速上手。

### 1. 添加扫描目标
- 进入「目标管理」页面
- 点击「添加目标」按钮
- 输入目标 URL 或 IP 地址

### 2. 创建扫描任务
- 点击右上角「新扫描」按钮
- 选择扫描目标和扫描策略
- 确认后开始扫描

### 3. 查看扫描结果
- 在「扫描任务」页面查看进度
- 扫描完成后查看漏洞详情
- 导出扫描报告

### 需要帮助？
如有疑问，请联系系统管理员。""",
                "icon": "BookOpen",
                "icon_color": "#ff6b00",
                "link": None,
                "order": 1,
                "is_active": True
            },
            {
                "key": "scan_guide",
                "title": "扫描指南",
                "description": "学习不同扫描类型的配置方法和最佳实践。",
                "content": """## 扫描指南

### 扫描类型说明

#### 1. 快速扫描
- 适用于初步安全评估
- 扫描时间：5-10分钟
- 检测常见漏洞

#### 2. 标准扫描
- 全面安全检测
- 扫描时间：30-60分钟
- 检测中高危漏洞

#### 3. 深度扫描
- 最全面的安全检测
- 扫描时间：1-3小时
- 检测所有类型漏洞

### 最佳实践

1. **选择合适的扫描时间**：避开业务高峰期
2. **设置合理的并发数**：避免对目标造成过大压力
3. **定期扫描**：建议每周至少一次安全扫描
4. **及时修复**：发现高危漏洞应立即处理""",
                "icon": "Shield",
                "icon_color": "#3b82f6",
                "link": None,
                "order": 2,
                "is_active": True
            },
            {
                "key": "report_guide",
                "title": "报告解读",
                "description": "理解漏洞扫描报告，分析安全风险等级。",
                "content": """## 报告解读指南

### 风险等级说明

| 等级 | 说明 | 建议处理时间 |
|------|------|-------------|
| 严重 | 可直接导致系统被入侵 | 立即处理 |
| 高危 | 存在被利用的风险 | 24小时内 |
| 中危 | 需要关注的安全问题 | 7天内 |
| 低危 | 建议优化的问题 | 30天内 |
| 信息 | 仅供参考的信息 | 可选处理 |

### 报告内容说明

#### 漏洞详情
- 漏洞名称和类型
- 受影响的 URL
- 漏洞证明（请求/响应）

#### 修复建议
- 漏洞成因分析
- 具体修复方案
- 相关安全参考

### 导出报告
支持导出 PDF、HTML、JSON 格式的报告。""",
                "icon": "FileText",
                "icon_color": "#22c55e",
                "link": None,
                "order": 3,
                "is_active": True
            },
            {
                "key": "contact_support",
                "title": "联系支持",
                "description": "遇到问题？联系技术支持获取帮助。",
                "content": """## 联系技术支持

### 支持渠道

#### 在线支持
- 工作时间：周一至周五 9:00-18:00
- 响应时间：2小时内

#### 邮件支持
- 邮箱：support@aegis.local
- 响应时间：24小时内

### 常见问题

**Q: 扫描任务卡在「运行中」状态？**
A: 请检查网络连接，或联系管理员重启扫描服务。

**Q: 无法添加扫描目标？**
A: 请确认目标格式正确（URL 需包含协议头，如 https://）。

**Q: 如何获取更高权限？**
A: 请联系系统管理员申请相应权限。

### 问题反馈
如发现系统问题或有功能建议，欢迎反馈！""",
                "icon": "MessageCircle",
                "icon_color": "#a855f7",
                "link": None,
                "order": 4,
                "is_active": True
            }
        ]
        
        # 批量插入
        for content_data in default_contents:
            content = HelpContent(**content_data)
            db.add(content)
        
        db.commit()
        logger.info(f"Successfully initialized {len(default_contents)} default help contents.")
    except Exception as e:
        logger.error(f"Failed to initialize default help contents: {e}")
        db.rollback()
    finally:
        db.close()


# 添加审计中间件
add_audit_middleware(app)

# 应用启动时初始化默认帮助内容
@app.on_event("startup")
async def startup_event():
    """应用启动时执行初始化操作。"""
    init_default_help_contents()
    
    # 初始化漏洞实验室场景
    try:
        db: Session = SessionLocal()
        count = init_lab_scenarios(db)
        if count > 0:
            logger.info(f"Successfully initialized {count} lab scenarios.")
        db.close()
    except Exception as e:
        logger.error(f"Failed to initialize lab scenarios: {e}")

# 静态文件服务
static_path = "/app/static"
if os.path.exists(static_path):
    app.mount("/assets", StaticFiles(directory=f"{static_path}/assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend(full_path: str = ""):
        # 如果请求的是 API，则不拦截（虽然路由已经注册，但为了保险）
        if full_path.startswith("api/"):
            raise StarletteHTTPException(status_code=404)
        
        # 检查文件是否存在
        file_path = os.path.join(static_path, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        
        # SPA 路由：所有非文件请求返回 index.html
        return FileResponse(os.path.join(static_path, "index.html"))
else:
    @app.get("/")
    async def root():
        return {"status": "online", "message": "Static files not found, API only mode."}
