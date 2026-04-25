"""
aegis.app.schemas.task
----------------------
定义 API 请求和响应的 Pydantic 模型。
"""
from pydantic import BaseModel, HttpUrl, Field
from typing import Optional, List
from datetime import datetime

class TaskCreate(BaseModel):
    target_url: HttpUrl = Field(..., description="目标网站 URL")
    scan_strategy: str = Field("attack_validation", description="扫描策略: attack_validation/full_audit/focused_probe")
    target_paths: Optional[List[str]] = Field(None, description="定向路径列表（仅 focused_probe 模式）")
    target_vuln_types: Optional[List[str]] = Field(None, description="定向漏洞类型列表（仅 focused_probe 模式）")
    target_parameters: Optional[List[str]] = Field(None, description="定向参数列表（仅 focused_probe 模式）")

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
