"""
扫描任务相关的数据验证模型
==========================
包含创建、更新、响应等各种场景的Pydantic模型。
兼容Python 3.6环境。
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, validator
from urllib.parse import urlparse


class ScanConfig(BaseModel):
    """扫描配置模型"""
    max_qps: int = Field(default=5, ge=1, le=50, description="最大QPS限制")
    timeout: int = Field(default=30, ge=5, le=300, description="请求超时时间(秒)")
    max_retries: int = Field(default=3, ge=0, le=10, description="最大重试次数")
    follow_redirects: bool = Field(default=True, description="是否跟随重定向")
    user_agent: str = Field(default="Aegis-Security-Scanner/1.0", description="User-Agent")
    headers: Optional[Dict[str, str]] = Field(default=None, description="自定义请求头")


class ScanTaskCreate(BaseModel):
    """创建扫描任务的请求模型"""
    name: str = Field(..., min_length=1, max_length=255, description="任务名称")
    target_url: str = Field(..., description="目标URL")
    scan_config: Optional[ScanConfig] = Field(default_factory=ScanConfig, description="扫描配置")
    cookies: Optional[str] = Field(default=None, description="登录Cookies")

    @validator('target_url')
    def validate_target_url(cls, v):
        """验证目标URL格式"""
        if not v.startswith(('http://', 'https://')):
            raise ValueError('目标URL必须以http://或https://开头')
        # 基本URL格式验证
        try:
            parsed = urlparse(v)
            if not parsed.netloc:
                raise ValueError('无效的URL格式')
        except Exception:
            raise ValueError('无效的URL格式')
        return v


class ScanTaskUpdate(BaseModel):
    """更新扫描任务的请求模型"""
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="任务名称")
    status: Optional[str] = Field(None, description="任务状态")
    scan_config: Optional[ScanConfig] = Field(None, description="扫描配置")
    cookies: Optional[str] = Field(None, description="登录Cookies")

    @validator('status')
    def validate_status(cls, v):
        """验证任务状态"""
        valid_statuses = ["pending", "running", "completed", "failed", "stopped", "paused"]
        if v and v not in valid_statuses:
            raise ValueError(f'状态必须是以下之一: {", ".join(valid_statuses)}')
        return v


class ScanTaskResponse(BaseModel):
    """扫描任务响应模型"""
    id: str = Field(..., description="任务ID")
    name: str = Field(..., description="任务名称")
    target_url: str = Field(..., description="目标URL")
    status: str = Field(..., description="任务状态")
    progress: float = Field(..., description="扫描进度")
    total_urls: int = Field(..., description="发现的总URL数")
    scanned_urls: int = Field(..., description="已扫描URL数")
    found_vulnerabilities: int = Field(..., description="发现漏洞数")
    severity_stats: Dict[str, int] = Field(..., description="严重程度统计")
    created_at: datetime = Field(..., description="创建时间")
    started_at: Optional[datetime] = Field(None, description="开始时间")
    completed_at: Optional[datetime] = Field(None, description="完成时间")
    duration: Optional[int] = Field(None, description="执行时长(秒)")
    error_message: Optional[str] = Field(None, description="错误信息")

    class Config:
        orm_mode = True  # pydantic v1.x uses orm_mode instead of from_attributes


class ScanTaskList(BaseModel):
    """扫描任务列表响应模型"""
    total: int
    items: List[ScanTaskResponse]
    page: int
    size: int


class VulnerabilityResponse(BaseModel):
    """漏洞响应模型"""
    id: str
    task_id: str
    vuln_type: str
    title: str
    severity: str
    severity_score: int
    cwe_id: Optional[str]
    cwe_name: Optional[str]
    url: str
    parameter: Optional[str]
    method: str
    payload: Optional[str]
    plugin_id: Optional[str]
    evidence: Optional[Dict[str, Any]]
    evidence_summary: Dict[str, Any]
    description: Optional[str]
    solution: Optional[str]
    references: Optional[List[str]]
    verified: bool
    false_positive: bool
    is_confirmed: bool
    created_at: datetime

    class Config:
        orm_mode = True


class VulnerabilityList(BaseModel):
    """漏洞列表响应模型"""
    total: int
    items: List[VulnerabilityResponse]
    page: int
    size: int


class ReportTaskCreate(BaseModel):
    """创建报告任务的请求模型"""
    report_type: str = Field(..., description="报告格式")
    report_title: Optional[str] = Field(None, description="报告标题")
    include_evidence: bool = Field(default=True, description="是否包含证据")
    include_logs: bool = Field(default=False, description="是否包含扫描日志")

    @validator('report_type')
    def validate_report_type(cls, v):
        """验证报告类型"""
        valid_types = ["json", "html", "markdown", "pdf"]
        if v not in valid_types:
            raise ValueError(f'报告类型必须是以下之一: {", ".join(valid_types)}')
        return v


class ReportTaskResponse(BaseModel):
    """报告任务响应模型"""
    id: str
    task_id: str
    report_type: str
    report_title: Optional[str]
    include_evidence: bool
    include_logs: bool
    status: str
    file_name: Optional[str]
    file_size: Optional[int]
    file_size_mb: float
    download_url: Optional[str]
    is_expired: bool
    expires_at: Optional[datetime]
    total_vulnerabilities: int
    generation_time: Optional[float]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]

    class Config:
        orm_mode = True


class ScanLogResponse(BaseModel):
    """扫描日志响应模型"""
    id: int
    task_id: str
    level: str
    level_priority: int
    message: str
    url: Optional[str]
    plugin_id: Optional[str]
    vuln_type: Optional[str]
    response_time: Optional[float]
    response_status: Optional[int]
    request_method: Optional[str]
    bytes_sent: Optional[int]
    bytes_received: Optional[int]
    created_at: datetime

    class Config:
        orm_mode = True


class ScanLogList(BaseModel):
    """扫描日志列表响应模型"""
    total: int
    items: List[ScanLogResponse]
    page: int
    size: int