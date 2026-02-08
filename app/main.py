import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.endpoints import tasks, reports, stats, vulnerabilities, ws, discovery, users, profiles
from app.db.database import engine, Base
from app.models import discovery # 导入模型以确保其被 SQLAlchemy 识别

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

# 创建数据库表
try:
    # 使用 checkfirst=True 是 SQLAlchemy 的标准做法，它会先检查表是否存在
    Base.metadata.create_all(bind=engine, checkfirst=True)
    logger.info("Database tables verified/created successfully.")
except Exception as e:
    logger.error(f"Database initialization error: {e}")
    # 在某些情况下，如果表已存在但 create_all 仍报错，我们可以选择忽略它
    if "already exists" in str(e):
        logger.info("Tables already exist, skipping creation.")
    else:
        # 如果是其他错误（如连接失败），则可能需要关注
        pass

app = FastAPI(
    title="Aegis API",
    version="1.0.0"
)

# 允许所有来源跨域 (生产环境应限制)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(tasks.router, prefix="/api/v1/tasks", tags=["Tasks"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["Stats"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(discovery.router, prefix="/api/v1/discovery", tags=["Discovery"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(profiles.router, prefix="/api/v1/profiles", tags=["Profiles"])
app.include_router(ws.router, tags=["WebSocket"])

@app.get("/")
async def root():
    return {"status": "online"}
