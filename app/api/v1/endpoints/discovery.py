from fastapi import APIRouter
from typing import List
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class Asset(BaseModel):
    id: int
    ip: str
    hostname: str
    ports: List[int]
    services: List[str]
    last_seen: datetime

@router.get("/", response_model=List[Asset])
async def get_assets():
    # Mock 数据，实际应从数据库查询
    return [
        {"id": 1, "ip": "192.168.1.1", "hostname": "gateway", "ports": [80, 443], "services": ["http", "https"], "last_seen": datetime.now()},
        {"id": 2, "ip": "192.168.1.105", "hostname": "dev-server", "ports": [22, 8080], "services": ["ssh", "http-alt"], "last_seen": datetime.now()},
    ]
