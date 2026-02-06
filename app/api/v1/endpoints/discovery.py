from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import asyncio

router = APIRouter()

class Asset(BaseModel):
    id: int
    ip: str
    hostname: str
    ports: List[int]
    services: List[str]
    last_seen: datetime

class TargetCreate(BaseModel):
    url: str
    description: Optional[str] = None

class Target(BaseModel):
    id: int
    url: str
    description: Optional[str]
    status: str
    created_at: datetime

# 模拟数据库存储
_mock_targets = [
    {"id": 1, "url": "192.168.10.156", "description": "内网测试服务器", "status": "active", "created_at": datetime.now()}
]

_mock_assets = [
    {"id": 1, "ip": "192.168.1.1", "hostname": "gateway", "ports": [80, 443], "services": ["http", "https"], "last_seen": datetime.now()},
    {"id": 2, "ip": "192.168.1.105", "hostname": "dev-server", "ports": [22, 8080], "services": ["ssh", "http-alt"], "last_seen": datetime.now()},
]

@router.get("/assets", response_model=List[Asset])
async def get_assets():
    return _mock_assets

@router.post("/scan")
async def start_network_scan():
    """
    触发网络资产发现扫描
    """
    # 模拟启动异步扫描任务
    # 在实际应用中，这里会调用 Celery 任务或启动一个子进程运行 nmap/zmap 等工具
    return {"status": "success", "message": "Network discovery scan started", "timestamp": datetime.now()}

@router.get("/targets", response_model=List[Target])
async def get_targets():
    return _mock_targets

@router.post("/targets", response_model=Target)
async def create_target(target_in: TargetCreate):
    new_target = {
        "id": len(_mock_targets) + 1,
        "url": target_in.url,
        "description": target_in.description,
        "status": "active",
        "created_at": datetime.now()
    }
    _mock_targets.append(new_target)
    return new_target
