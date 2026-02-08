import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
# 使用别名导入以避免命名冲突
from app.api.v1.endpoints import (
    tasks, reports, stats, vulnerabilities, ws, 
    discovery as discovery_router, # 别名区分路由
    users, profiles
)
from app.db.database import engine, Base
from app.models import discovery as discovery_model # 别名区分模型

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

# 创建数据库表 (带重试逻辑，适配 Docker 启动顺序)
import time
max_retries = 5
retry_interval = 5

for i in range(max_retries):
    try:
        Base.metadata.create_all(bind=engine, checkfirst=True)
        logger.info("Database tables verified/created successfully.")
        break
    except Exception as e:
        if "already exists" in str(e):
            logger.info("Tables already exist, skipping creation.")
            break
        
        if i < max_retries - 1:
            logger.warning(f"Database connection failed (attempt {i+1}/{max_retries}). Retrying in {retry_interval}s... Error: {e}")
            time.sleep(retry_interval)
        else:
            logger.error(f"Could not connect to database after {max_retries} attempts. Proceeding without table creation.")

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

# 注册路由 - 使用别名后的 discovery_router
app.include_router(tasks.router, prefix="/api/v1/tasks", tags=["Tasks"])
app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(stats.router, prefix="/api/v1/stats", tags=["Stats"])
app.include_router(vulnerabilities.router, prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])
app.include_router(discovery_router.router, prefix="/api/v1/discovery", tags=["Discovery"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(profiles.router, prefix="/api/v1/profiles", tags=["Profiles"])
app.include_router(ws.router, tags=["WebSocket"])

@app.get("/")
async def root():
    return {"status": "online"}
