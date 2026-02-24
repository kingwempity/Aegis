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
            description=_get_description(v.evidence),
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


def _get_description(evidence: Optional[dict]) -> Optional[str]:
    """
    从证据中提取描述信息。
    
    Args:
        evidence: 漏洞证据字典
        
    Returns:
        描述文本
    """
    if not evidence:
        return None
    
    # 尝试从证据中提取有用信息
    parts = []
    
    if "matchers" in evidence:
        matchers = evidence["matchers"]
        if isinstance(matchers, list) and matchers:
            parts.append(f"匹配规则: {len(matchers)} 个")
    
    if "encoding_used" in evidence:
        parts.append(f"编码类型: {evidence['encoding_used']}")
    
    if parts:
        return " | ".join(parts)
    
    return None
