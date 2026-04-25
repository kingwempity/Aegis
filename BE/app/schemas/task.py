"""
aegis.app.schemas.task
----------------------
定义 API 请求和响应的 Pydantic 模型。
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from datetime import datetime

class TaskCreate(BaseModel):
    """创建任务时的请求参数"""
    target_url: HttpUrl = Field(..., description="目标网站 URL")
    scan_strategy: str = Field("default", description="扫描策略: default/full/fast")

class VulnerabilityOut(BaseModel):
    """响应中的漏洞信息"""
    id: int
    vuln_name: str
    severity: str
    url: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

class TaskOut(BaseModel):
    """响应中的任务信息"""
    id: int
    display_id: int
    target_url: str
    status: str
    scan_strategy: str
    created_at: datetime
    duration_seconds: Optional[float] = None
    # vulnerabilities: List[VulnerabilityOut] = [] 

    class Config:
        from_attributes = True
