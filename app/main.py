"""
Aegis 主入口文件
----------------
负责初始化 FastAPI 应用、注册路由及全局配置。
"""
from fastapi import FastAPI

# 初始化 FastAPI 实例
app = FastAPI(
    title="Aegis API",
    description="基于模拟攻击的 Web 漏洞检测系统 API",
    version="1.0.0"
)

@app.get("/")
async def root():
    """健康检查接口"""
    return {
        "status": "online",
        "message": "Welcome to Aegis Security Platform",
        "docs": "/docs"
    }

# 后续在这里注册路由
# from app.api.v1 import tasks
# app.include_router(tasks.router, prefix="/api/v1")

