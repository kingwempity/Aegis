"""
aegis.app.api.v1.endpoints.stats
--------------------------------
仪表盘统计 API，从数据库查询真实统计数据。
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.database import get_db
from app.db.query_utils import fetch_top_threat_rows
from app.models.task import ScanTask, Vulnerability
from app.models.discovery import DiscoveryResult

router = APIRouter()

class VulnStats(BaseModel):
    """漏洞统计数据模型"""
    critical: int
    high: int
    medium: int
    low: int

class TopThreat(BaseModel):
    """主要威胁数据模型"""
    id: int
    title: str
    severity: str
    target_url: str

class DashboardStats(BaseModel):
    """仪表盘统计数据模型"""
    running_scans: int
    pending_scans: int
    total_scans: int
    open_ports: int
    total_targets: int
    vulnerabilities: VulnStats
    total_vulnerabilities: int = 0  # 全部漏洞数（与分母口径一致）
    validated_findings: int = 0  # 已保留证据链的漏洞数
    top_threats: List[TopThreat] = []  # 新增：主要威胁列表

# 简单的内存缓存，避免频繁查询数据库
_stats_cache: Optional[DashboardStats] = None
_last_cache_time: Optional[datetime] = None
CACHE_TTL = timedelta(seconds=10)  # 缓存 10 秒


@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    获取仪表盘统计数据。
    
    从数据库查询：
    - 运行中/等待中的扫描任务数
    - 总扫描任务数
    - 开放端口数（从资产发现结果）
    - 目标总数
    - 各级别漏洞数量
    
    Args:
        db: 数据库会话
        
    Returns:
        DashboardStats: 仪表盘统计数据
    """
    global _stats_cache, _last_cache_time
    
    # 使用缓存减少数据库压力
    now = datetime.now()
    if _stats_cache and _last_cache_time and (now - _last_cache_time) < CACHE_TTL:
        return _stats_cache

    # 查询扫描任务统计
    running_scans = db.query(ScanTask).filter(ScanTask.status == "RUNNING").count()
    pending_scans = db.query(ScanTask).filter(ScanTask.status == "PENDING").count()
    total_scans = db.query(ScanTask).count()
    
    # 查询开放端口数（从发现结果中统计）
    # 注意：open_ports 是逗号分隔的字符串，需要计算端口数量
    open_ports = 0
    try:
        discovery_results = db.query(DiscoveryResult).all()
        for result in discovery_results:
            if result.open_ports:
                ports = [p.strip() for p in result.open_ports.split(",") if p.strip()]
                open_ports += len(ports)
    except Exception:
        open_ports = 0
    
    # 查询目标总数（从扫描任务中获取唯一URL数）
    total_targets = db.query(ScanTask.target_url).distinct().count()
    
    # 查询漏洞统计（按严重程度分组）
    # 注意：扫描器使用的严重程度是 High, Medium, Low, Info 等
    # 前端显示的是 critical, high, medium, low
    vulnerability_counts = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.severity).all()
    
    # 初始化统计字典
    severity_map = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }
    
    # 映射严重程度名称
    severity_mapping = {
        # 扫描器输出的严重程度 -> 前端显示的严重程度
        "Critical": "critical",
        "High": "high",
        "Medium": "medium",
        "Low": "low",
        "Info": "low",  # Info 级别归入 low
        "info": "low",
    }
    
    for severity, count in vulnerability_counts:
        if not severity:
            severity_map["low"] += count
            continue
        normalized_severity = severity_mapping.get(severity, severity.lower())
        if normalized_severity in severity_map:
            severity_map[normalized_severity] += count
        else:
            severity_map["low"] += count

    total_vulnerabilities = int(db.query(func.count(Vulnerability.id)).scalar() or 0)
    evidence_flag = case((Vulnerability.evidence.isnot(None), 1), else_=0)
    validated_findings = int(db.query(func.sum(evidence_flag)).scalar() or 0)
    validated_findings = min(validated_findings, total_vulnerabilities)
    
    # Top 威胁：仅查询轻量列，避免对大 JSON 字段排序导致 sort buffer 溢出
    top_threats = [
        TopThreat(
            id=row.id,
            title=row.vuln_name or "未知漏洞",
            severity=_normalize_severity(row.severity),
            target_url=row.url or "",
        )
        for row in fetch_top_threat_rows(db, limit=5)
    ]
    
    stats = DashboardStats(
        running_scans=running_scans,
        pending_scans=pending_scans,
        total_scans=total_scans,
        open_ports=open_ports,
        total_targets=total_targets,
        vulnerabilities=VulnStats(
            critical=severity_map["critical"],
            high=severity_map["high"],
            medium=severity_map["medium"],
            low=severity_map["low"],
        ),
        total_vulnerabilities=total_vulnerabilities,
        validated_findings=validated_findings,
        top_threats=top_threats
    )
    
    # 更新缓存
    _stats_cache = stats
    _last_cache_time = now
    
    return stats


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
