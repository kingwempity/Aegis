"""
aegis.app.api.v1.endpoints.vulnerabilities
------------------------------------------
漏洞管理 API，从数据库查询漏洞数据。

Author: Aegis Architect
Created: 2026-01-21
"""

from fastapi import APIRouter, Depends
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.task import Vulnerability as VulnerabilityModel

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
    # 构建基础查询
    query = db.query(VulnerabilityModel)
    
    # 严重程度映射（前端参数 -> 数据库值）
    severity_mapping = {
        "critical": ["Critical", "critical"],
        "high": ["High", "high"],
        "medium": ["Medium", "medium"],
        "low": ["Low", "low", "Info", "info"],
    }
    
    # 应用筛选条件
    if severity and severity.lower() in severity_mapping:
        allowed_values = severity_mapping[severity.lower()]
        query = query.filter(VulnerabilityModel.severity.in_(allowed_values))
    
    # 按创建时间倒序排列
    query = query.order_by(VulnerabilityModel.created_at.desc())
    
    # 查询结果
    vulns = query.all()
    
    # 转换为响应格式
    return [
        VulnerabilityResponse(
            id=v.id,
            title=v.vuln_name,
            severity=_normalize_severity(v.severity),
            target_url=v.url or "",
            description=_get_description(v),
            vuln_type=getattr(v, "vuln_type", None),
            parameter=getattr(v, "parameter", None),
            payload_present=bool(getattr(v, "payload", None)),
            attack_path_present=bool(getattr(v, "attack_path", None)),
            evidence_present=bool(getattr(v, "evidence", None)),
            created_at=v.created_at or datetime.now()
        )
        for v in vulns
    ]


def _normalize_severity(severity: Optional[str]) -> str:
    """
    标准化严重程度名称。
    
    Args:
        severity: 原始严重程度
        
    Returns:
        标准化后的严重程度（lowercase）
    """
    if not severity:
        return "info"
    
    mapping = {
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "info",
    }
    return mapping.get(severity, severity.lower())


def _get_description(vuln: VulnerabilityModel) -> Optional[str]:
    """
    从漏洞对象中提取轻量验证摘要。
    
    Args:
        vuln: 漏洞对象
        
    Returns:
        描述文本
    """
    evidence = getattr(vuln, "evidence", None)
    parts = []

    if getattr(vuln, "payload", None):
        parts.append("已命中攻击载荷")

    if getattr(vuln, "attack_path", None):
        parts.append("已记录攻击路径")

    if evidence:
        parts.append("已保留证据链")

    if not evidence:
        return "，".join(parts) if parts else None

    if "matchers" in evidence:
        matchers = evidence["matchers"]
        if isinstance(matchers, list) and matchers:
            parts.append(f"命中 {len(matchers)} 条验证规则")

    if "encoding_used" in evidence and evidence["encoding_used"]:
        parts.append(f"载荷编码: {evidence['encoding_used']}")

    if parts:
        return "，".join(parts)

    return None
