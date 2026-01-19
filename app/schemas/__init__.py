"""
Aegis Pydantic Schemas
--------------------
API请求和响应的数据验证模型。
使用Pydantic进行数据序列化和验证。
"""

from .task import (
    ScanTaskCreate,
    ScanTaskUpdate,
    ScanTaskResponse,
    ScanTaskList,
    VulnerabilityResponse,
    VulnerabilityList,
    ReportTaskCreate,
    ReportTaskResponse,
    ScanLogResponse
)

__all__ = [
    "ScanTaskCreate",
    "ScanTaskUpdate",
    "ScanTaskResponse",
    "ScanTaskList",
    "VulnerabilityResponse",
    "VulnerabilityList",
    "ReportTaskCreate",
    "ReportTaskResponse",
    "ScanLogResponse"
]