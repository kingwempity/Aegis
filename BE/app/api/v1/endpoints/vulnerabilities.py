"""
aegis.app.api.v1.endpoints.vulnerabilities
------------------------------------------
漏洞管理 API，从数据库查询漏洞数据。
"""

from fastapi import APIRouter, Depends
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session

from app.database import get_db
from app.db.query_utils import fetch_vulnerability_list_rows

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


@router.get("", response_model=List[VulnerabilityResponse])
@router.get("/", response_model=List[VulnerabilityResponse])
async def get_vulnerabilities(
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    获取漏洞列表。
    
    Args:
        severity: 可选的严重程度筛选（critical, high, medium, low）
        db: 数据库会话
        
    Returns:
        漏洞列表
    """
    severity_mapping = {
        "critical": ["Critical", "critical", "CRITICAL"],
        "high": ["High", "high", "HIGH"],
        "medium": ["Medium", "medium", "MEDIUM"],
        "low": ["Low", "low", "LOW", "Info", "info", "INFO"],
    }

    allowed_values = None
    if severity and severity.lower() in severity_mapping:
        allowed_values = severity_mapping[severity.lower()]

    rows = fetch_vulnerability_list_rows(
        db, severity_values=allowed_values, limit=VULN_LIST_LIMIT
    )

    return [
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
