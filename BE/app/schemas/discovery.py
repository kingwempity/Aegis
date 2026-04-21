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

class TargetCreate(BaseModel):
    url: str
    description: Optional[str] = None

class TargetResponse(BaseModel):
    """
    目标响应模型，包含漏洞统计信息。
    
    Attributes:
        id: 目标ID
        url: 目标URL
        description: 描述信息
        status: 目标状态
        created_at: 创建时间
        last_scanned: 最后扫描时间
        critical_vulns: 高危漏洞数量
        high_vulns: 中危漏洞数量
        low_vulns: 低危漏洞数量
    """
    id: int
    url: str
    description: Optional[str] = None
    status: str
    created_at: datetime
    last_scanned: Optional[datetime] = None
    critical_vulns: Optional[int] = 0
    high_vulns: Optional[int] = 0
    low_vulns: Optional[int] = 0

    class Config:
        from_attributes = True
