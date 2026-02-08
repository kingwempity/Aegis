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
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully.")
except Exception as e:
    logger.warning(f"Database tables creation skipped or failed: {e}")

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
