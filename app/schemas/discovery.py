from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class DiscoveryCreate(BaseModel):
    """
    Pydantic 模型，用于创建新的 DiscoveryResult 记录。
    """
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    open_ports: Optional[List[int]] = []
    os_info: Optional[str] = None
    services: Optional[List[str]] = []
    network_range: str
    status: Optional[str] = "active"

class DiscoveryResponse(DiscoveryCreate):
    """
    Pydantic 模型，用于返回 DiscoveryResult 记录。
    继承自 DiscoveryCreate 并添加了 ID 和时间戳字段。
    """
    id: int
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
