"""
轻量数据库查询工具

避免在 ORDER BY / 列表接口中加载 evidence、attack_path 等大 JSON 字段，
防止 MySQL sort buffer 溢出 (errno 1038)。
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.task import Vulnerability


def severity_rank_expr():
    """严重程度排序权重（数值越小越优先）。"""
    return case(
        (Vulnerability.severity.in_(["Critical", "critical", "CRITICAL"]), 1),
        (Vulnerability.severity.in_(["High", "high", "HIGH"]), 2),
        (Vulnerability.severity.in_(["Medium", "medium", "MEDIUM"]), 3),
        (Vulnerability.severity.in_(["Low", "low", "LOW"]), 4),
        else_=5,
    )


def risk_points_expr():
    """单条漏洞风险分值（与报告列表逻辑一致）。"""
    sev = func.lower(func.coalesce(Vulnerability.severity, ""))
    return case(
        (sev.like("%critical%"), 20),
        (sev.like("%high%"), 20),
        (sev.like("%medium%"), 10),
        else_=5,
    )


def aggregate_vuln_stats_by_task(
    db: Session, task_ids: List[int]
) -> Dict[int, Dict[str, int]]:
    """
    按任务聚合漏洞统计，不读取 JSON 大字段。

    Returns:
        task_id -> {vuln_count, payload_count, attack_path_count, evidence_count, risk_score}
    """
    if not task_ids:
        return {}

    payload_flag = case((Vulnerability.payload.isnot(None), 1), else_=0)
    path_flag = case((Vulnerability.attack_path.isnot(None), 1), else_=0)
    evidence_flag = case((Vulnerability.evidence.isnot(None), 1), else_=0)

    rows = (
        db.query(
            Vulnerability.task_id,
            func.count(Vulnerability.id),
            func.sum(payload_flag),
            func.sum(path_flag),
            func.sum(evidence_flag),
            func.sum(risk_points_expr()),
        )
        .filter(Vulnerability.task_id.in_(task_ids))
        .group_by(Vulnerability.task_id)
        .all()
    )

    result: Dict[int, Dict[str, int]] = {}
    for task_id, vuln_count, payload_count, path_count, evidence_count, risk_sum in rows:
        result[int(task_id)] = {
            "vuln_count": int(vuln_count or 0),
            "payload_count": int(payload_count or 0),
            "attack_path_count": int(path_count or 0),
            "evidence_count": int(evidence_count or 0),
            "risk_score": min(int(risk_sum or 0), 100),
        }
    return result


def fetch_top_threat_rows(db: Session, limit: int = 5) -> List[Tuple]:
    """
    获取仪表盘 Top 威胁（仅轻量列 + 按严重程度/id 排序）。
    """
    return (
        db.query(
            Vulnerability.id,
            Vulnerability.vuln_name,
            Vulnerability.severity,
            Vulnerability.url,
        )
        .order_by(severity_rank_expr(), Vulnerability.id.desc())
        .limit(limit)
        .all()
    )


def fetch_vulnerability_list_rows(
    db: Session,
    severity_values: Optional[List[str]] = None,
    limit: int = 500,
) -> List:
    """
    漏洞列表轻量查询（不含 evidence / attack_path / payload 正文）。
    """
    payload_present = Vulnerability.payload.isnot(None)
    path_present = Vulnerability.attack_path.isnot(None)
    evidence_present = Vulnerability.evidence.isnot(None)

    query = db.query(
        Vulnerability.id,
        Vulnerability.vuln_name,
        Vulnerability.severity,
        Vulnerability.url,
        Vulnerability.vuln_type,
        Vulnerability.parameter,
        Vulnerability.created_at,
        payload_present.label("payload_present"),
        path_present.label("attack_path_present"),
        evidence_present.label("evidence_present"),
    )

    if severity_values:
        query = query.filter(Vulnerability.severity.in_(severity_values))

    return query.order_by(Vulnerability.id.desc()).limit(limit).all()
