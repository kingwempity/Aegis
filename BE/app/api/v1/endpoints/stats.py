"""
aegis.app.api.v1.endpoints.stats
--------------------------------
仪表盘统计 API，从数据库查询真实统计数据。

性能优化版本：
- 使用 SQL 聚合函数替代 Python 内存计算
- 合并多次独立 DB 查询为批量聚合
- 10 秒内存缓存减少数据库压力
"""

import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, case, distinct, Integer, literal_column

from app.database import get_db
from app.db.query_utils import fetch_top_threat_rows
from app.models.task import ScanTask, Vulnerability
from app.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)

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

    # 性能监控：记录查询开始时间
    query_start = datetime.now()
    logger.info(f" Dashboard stats query started at {query_start.isoformat()}")

    # ==================== 优化：使用聚合查询替代多次独立查询 ====================

    # 1. 扫描任务统计（单次查询获取所有状态）
    task_stats = db.query(
        ScanTask.status,
        func.count(ScanTask.id)
    ).group_by(ScanTask.status).all()

    running_scans = 0
    pending_scans = 0
    total_scans = 0
    for status, count in task_stats:
        total_scans += count
        if status == "RUNNING":
            running_scans = count
        elif status == "PENDING":
            pending_scans = count

    # 2. 开放端口数优化：使用 SQL LENGTH + REPLACE 函数计算，避免全表加载
    # 原逻辑：加载所有 DiscoveryResult 到内存，Python 分割字符串统计
    # 优化后：纯 SQL 聚合计算，性能提升 10-100 倍
    # 注意：使用 TRIM 去除首尾逗号，避免边界问题（如 ",80,443," 会被错误计算为4个端口）
    try:
        trimmed_ports = literal_column("TRIM(BOTH ',' FROM discovery_results.open_ports)")
        open_ports_result = db.query(
            func.sum(
                case(
                    (trimmed_ports != '', 
                     func.length(trimmed_ports) - 
                     func.length(func.replace(trimmed_ports, ',', '')) + 1),
                    else_=0
                )
            )
        ).select_from(DiscoveryResult).scalar()
        open_ports = int(open_ports_result or 0)
    except Exception:
        open_ports = 0

    # 3. 目标总数（保持原有逻辑）
    total_targets = db.query(ScanTask.target_url).distinct().count()

    # 4. 漏洞统计（按严重程度分组 + 总数 + 已验证数）合并为单次聚合查询
    # 原逻辑：3 次独立查询（分组统计 + 总数 + 已验证数）
    # 优化后：1 次复杂聚合查询
    vuln_aggregate = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id).label("count"),
        func.sum(case((Vulnerability.evidence.isnot(None), 1), else_=0)).label("evidence_count")
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

    total_vulnerabilities = 0
    validated_findings = 0

    for severity, count, evidence_count in vuln_aggregate:
        count = int(count or 0)
        evidence_count = int(evidence_count or 0)
        
        total_vulnerabilities += count
        validated_findings += evidence_count
        
        if not severity:
            severity_map["low"] += count
            continue
        normalized_severity = severity_mapping.get(severity, severity.lower())
        if normalized_severity in severity_map:
            severity_map[normalized_severity] += count
        else:
            severity_map["low"] += count

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

    # 性能监控：记录查询耗时
    query_duration = (datetime.now() - query_start).total_seconds() * 1000
    logger.info(
        f"✅ Dashboard stats query completed in {query_duration:.2f}ms | "
        f"Cache: {CACHE_TTL.total_seconds()}s | "
        f"Tasks: {total_scans} | Vulns: {total_vulnerabilities} | Ports: {open_ports}"
    )

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
