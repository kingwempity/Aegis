import logging
import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

# 使用别名导入以避免命名冲突
from app.api.v1.endpoints import (
    tasks, reports, stats, vulnerabilities, ws, 
    discovery as discovery_router, 
    users, profiles, auth
)
from app.db.database import engine, Base
from app.models import discovery as discovery_model
from app.models import user as user_model  # 导入用户模型以创建数据库表

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("uvicorn")

# 创建数据库表 (带重试逻辑)
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
            logger.error(f"Could not connect to database after {max_retries} attempts.")

app = FastAPI(
    title="Aegis API",
    version="1.0.0"
)

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
app.include_router(ws.router, tags=["WebSocket"])

@app.get("/")
async def root():
    return {"status": "online"}
