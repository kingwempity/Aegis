"""
aegis.app.api.v1.endpoints.vulnerabilities
------------------------------------------
漏洞管理 API，从数据库查询漏洞数据。

性能优化版本：
- 支持分页查询，避免一次性加载大量数据
- 使用轻量查询，不加载大 JSON 字段
"""

from fastapi import APIRouter, Depends, Query
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.db.query_utils import fetch_vulnerability_list_rows
from app.models.task import Vulnerability

VULN_LIST_LIMIT = 500

router = APIRouter()


class VulnerabilityResponse(BaseModel):
    """漏洞响应数据模型"""
    id: int
    title: str
    severity: str
    target_url: str
    description: Optional[str] = None
    vuln_type: Optional[str] = None
    parameter: Optional[str] = None
    payload_present: bool
    attack_path_present: bool
    evidence_present: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class VulnerabilityListResponse(BaseModel):
    """漏洞列表响应（带分页信息）"""
    total: int
    items: List[VulnerabilityResponse]


@router.get("", response_model=VulnerabilityListResponse)
@router.get("/", response_model=VulnerabilityListResponse)
async def get_vulnerabilities(
    severity: Optional[str] = None,
    skip: int = Query(default=0, ge=0, description="跳过的记录数"),
    limit: int = Query(default=50, ge=1, le=500, description="返回的记录数"),
    db: Session = Depends(get_db)
):
    """
    获取漏洞列表（支持分页）。
    
    Args:
        severity: 可选的严重程度筛选（critical, high, medium, low）
        skip: 跳过的记录数（分页偏移）
        limit: 返回的记录数（每页大小）
        db: 数据库会话
        
    Returns:
        VulnerabilityListResponse: 包含总数和漏洞列表
    """
    severity_mapping = {
        "critical": ["Critical", "critical", "CRITICAL"],
        "high": ["High", "high", "HIGH"],
        "medium": ["Medium", "medium", "MEDIUM"],
        "low": ["Low", "low", "LOW", "Info", "info", "INFO"],
    }

    allowed_values = None
    if severity:
        allowed_values = severity_mapping.get(severity.lower())
        if allowed_values is None:
            return VulnerabilityListResponse(total=0, items=[])

    base_query = db.query(Vulnerability)
    if allowed_values:
        base_query = base_query.filter(Vulnerability.severity.in_(allowed_values))
    
    total = base_query.count()

    rows = fetch_vulnerability_list_rows(
        db, severity_values=allowed_values, limit=limit, offset=skip
    )

    items = [
        VulnerabilityResponse(
            id=row.id,
            title=row.vuln_name,
            severity=_normalize_severity(row.severity),
            target_url=row.url or "",
            description=_build_list_description(row),
            vuln_type=row.vuln_type,
            parameter=row.parameter,
            payload_present=bool(row.payload_present),
            attack_path_present=bool(row.attack_path_present),
            evidence_present=bool(row.evidence_present),
            created_at=row.created_at or datetime.now(),
        )
        for row in rows
    ]

    return VulnerabilityListResponse(total=total, items=items)


def _normalize_severity(severity: Optional[str]) -> str:
    if not severity:
        return "info"
    
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(severity.lower(), severity.lower())


def _build_list_description(row) -> Optional[str]:
    """列表页摘要，不解析 evidence JSON。"""
    parts = []
    if row.payload_present:
        parts.append("已命中攻击载荷")
    if row.attack_path_present:
        parts.append("已记录攻击路径")
    if row.evidence_present:
        parts.append("已保留证据链")
    return "，".join(parts) if parts else None
