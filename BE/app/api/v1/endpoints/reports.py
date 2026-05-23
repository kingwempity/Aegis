"""
报告管理 API 端点

提供报告列表查询、报告生成和下载功能，支持多种导出格式。

性能优化版本：
- 使用 eager loading 预加载关联数据
- 避免懒加载导致的 N+1 查询
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session, joinedload
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import os
import logging

from app.db.database import get_db
from app.db.query_utils import aggregate_vuln_stats_by_task
from app.models.task import ScanTask
from app.services.report import ReportGenerator

router = APIRouter()

logger = logging.getLogger(__name__)


class ReportResponse(BaseModel):
    """报告响应模型"""
    id: int
    task_id: int
    display_id: int
    target_url: str
    risk_score: float
    vuln_count: int
    validated_findings: int
    payload_count: int
    attack_path_count: int
    scan_strategy: Optional[str] = None
    created_at: datetime


class ReportFormatResponse(BaseModel):
    """支持的导出格式响应"""
    format: str
    label: str
    description: str
    mime_type: str


# 支持的导出格式
SUPPORTED_FORMATS = {
    "html": {
        "label": "HTML",
        "description": "网页格式，可直接在浏览器中查看",
        "mime_type": "text/html"
    },
    "pdf": {
        "label": "PDF",
        "description": "文档格式，适合打印和存档",
        "mime_type": "application/pdf"
    },
    "markdown": {
        "label": "Markdown",
        "description": "纯文本格式，可导入到其他工具",
        "mime_type": "text/markdown"
    },
    "excel": {
        "label": "Excel",
        "description": "表格格式，适合数据分析和筛选",
        "mime_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    },
    "json": {
        "label": "JSON",
        "description": "数据格式，适合程序处理和集成",
        "mime_type": "application/json"
    }
}


@router.get("", response_model=List[ReportResponse])
@router.get("/", response_model=List[ReportResponse])
def get_reports(db: Session = Depends(get_db)):
    """
    获取所有已完成任务的报告列表
    
    Returns:
        List[ReportResponse]: 报告列表
    """
    # 查询所有已完成的任务
    completed_tasks = (
        db.query(ScanTask)
        .filter(ScanTask.status == "COMPLETED")
        .order_by(ScanTask.id.desc())
        .all()
    )

    task_ids = [task.id for task in completed_tasks]
    vuln_stats = aggregate_vuln_stats_by_task(db, task_ids)

    reports = []
    for task in completed_tasks:
        stats = vuln_stats.get(
            task.id,
            {
                "vuln_count": 0,
                "payload_count": 0,
                "attack_path_count": 0,
                "evidence_count": 0,
                "risk_score": 0,
            },
        )
        reports.append({
            "id": task.id,
            "task_id": task.id,
            "display_id": task.display_id,
            "target_url": task.target_url,
            "risk_score": stats["risk_score"],
            "vuln_count": stats["vuln_count"],
            "validated_findings": stats["evidence_count"],
            "payload_count": stats["payload_count"],
            "attack_path_count": stats["attack_path_count"],
            "scan_strategy": task.scan_strategy,
            "created_at": task.updated_at or task.created_at,
        })

    return reports


@router.get("/formats", response_model=List[ReportFormatResponse])
def get_supported_formats():
    """
    获取支持的导出格式列表
    
    Returns:
        List[ReportFormatResponse]: 支持的格式列表
    """
    formats = []
    for format_key, format_info in SUPPORTED_FORMATS.items():
        formats.append({
            "format": format_key,
            "label": format_info["label"],
            "description": format_info["description"],
            "mime_type": format_info["mime_type"]
        })
    return formats


@router.get("/{task_id}/html")
def download_html_report(task_id: int, db: Session = Depends(get_db)):
    """
    生成并下载任务的 HTML 报告
    
    Args:
        task_id: 任务ID
        
    Returns:
        FileResponse: HTML文件响应
    """
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="任务尚未完成，无法生成报告")
        
    filename = f"report_{task_id}.html"
    generator = ReportGenerator()
    try:
        file_path = generator.generate_html(task, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail="报告文件生成失败")
            
        return FileResponse(
            path=file_path, 
            filename=filename, 
            media_type="text/html"
        )
    except Exception as e:
        logger.error(f"生成HTML报告失败: {e}")
        raise HTTPException(status_code=500, detail=f"报告生成失败: {str(e)}")


@router.get("/{task_id}/export")
def export_report(
    task_id: int, 
    format: str = Query(default="html", description="导出格式: html, pdf, markdown, excel, json"),
    include_evidence: bool = Query(default=True, description="是否包含攻击证据"),
    db: Session = Depends(get_db)
):
    """
    导出指定格式的报告
    
    Args:
        task_id: 任务ID
        format: 导出格式 (html/pdf/markdown/excel/json)
        include_evidence: 是否包含攻击证据
        
    Returns:
        FileResponse: 报告文件响应
    """
    # 验证格式参数
    format = format.lower()
    if format not in SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400, 
            detail=f"不支持的导出格式: {format}。支持的格式: {', '.join(SUPPORTED_FORMATS.keys())}"
        )
    
    # 查询任务
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="任务尚未完成，无法生成报告")
    
    # 生成报告
    generator = ReportGenerator()
    try:
        file_path, filename = generator.generate(task, format)
        
        if not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail="报告文件生成失败")
        
        mime_type = SUPPORTED_FORMATS[format]["mime_type"]
        
        return FileResponse(
            path=file_path,
            filename=filename,
            media_type=mime_type
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"导出报告失败 (格式: {format}): {e}")
        raise HTTPException(status_code=500, detail=f"报告导出失败: {str(e)}")


@router.get("/{task_id}/preview")
def preview_report(task_id: int, db: Session = Depends(get_db)):
    """
    预览报告（返回JSON格式的报告数据）
    
    性能优化：使用 joinedload 预加载漏洞数据，避免懒加载 N+1 查询
    
    Args:
        task_id: 任务ID
        
    Returns:
        JSONResponse: 报告数据
    """
    task = (
        db.query(ScanTask)
        .options(joinedload(ScanTask.vulnerabilities))
        .filter(ScanTask.id == task_id)
        .first()
    )
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="任务尚未完成")
    
    generator = ReportGenerator()
    summary = generator._get_summary(task)
    
    vulnerabilities = []
    for vuln in task.vulnerabilities:
        vuln_type = getattr(vuln, 'vuln_type', None)
        parameter = getattr(vuln, 'parameter', None)
        cvss_score = getattr(vuln, 'cvss_score', None)
        description = getattr(vuln, 'description', None)
        remediation = getattr(vuln, 'remediation', None)
        attack_path = getattr(vuln, "attack_path", None) or {}
        evidence = getattr(vuln, "evidence", None) or {}
        
        attack_steps = []
        attack_artifacts = []
        attack_status = None
        final_reason = None
        attack_chain_summary = None
        
        if isinstance(attack_path, dict):
            raw_steps = attack_path.get("steps", [])
            attack_status = attack_path.get("status")
            final_reason = attack_path.get("final_reason")
            
            for idx, step in enumerate(raw_steps):
                step_data = {
                    "step": step.get("step", idx + 1),
                    "stage_id": step.get("stage_id") or step.get("id") or f"stage-{idx}",
                    "stage_name": step.get("stage_name") or step.get("name"),
                    "stage_title": step.get("stage_title") or step.get("title"),
                    "stage_goal": step.get("stage_goal") or step.get("goal"),
                    "method": step.get("method"),
                    "url": step.get("url"),
                    "description": step.get("description"),
                    "matched_conditions": step.get("matched_conditions", []),
                    "artifacts": step.get("artifacts", []),
                    "extracted": step.get("extracted"),
                    "success": step.get("success"),
                    "duration_ms": step.get("duration_ms"),
                    "status": step.get("status"),
                    "timestamp": step.get("timestamp"),
                    "result": step.get("result"),
                }
                
                if step.get("request"):
                    step_data["request"] = step["request"]
                if step.get("response"):
                    step_data["response"] = step["response"]
                if step.get("payload"):
                    step_data["payload"] = step["payload"]
                
                step_evidence = step.get("evidence", {})
                if step_evidence:
                    step_data["evidence"] = {
                        "request": step_evidence.get("request"),
                        "response": step_evidence.get("response"),
                        "matched_conditions": step_evidence.get("matched_conditions", []),
                        "matched_patterns": step_evidence.get("matched_patterns", []),
                        "timing_ms": step_evidence.get("timing_ms"),
                    }
                elif evidence and isinstance(evidence, dict):
                    if idx == 0:
                        raw_matchers = evidence.get("matchers", [])
                        safe_conditions = []
                        for m in raw_matchers:
                            if isinstance(m, str):
                                safe_conditions.append(m)
                            elif isinstance(m, dict):
                                m_type = m.get("type", "unknown")
                                if m_type == "word" and m.get("words"):
                                    safe_conditions.append(f"关键词匹配: {', '.join(str(w) for w in m['words'][:5])}")
                                elif m_type == "regex" and m.get("regex"):
                                    safe_conditions.append(f"正则匹配: {m['regex'][:80]}")
                                elif m_type == "status" and m.get("status"):
                                    safe_conditions.append(f"状态码匹配: {', '.join(str(s) for s in m['status'])}")
                                elif m_type == "binary" and m.get("binary"):
                                    safe_conditions.append("二进制模式匹配")
                                elif m_type == "dsl" and m.get("dsl"):
                                    safe_conditions.append(f"DSL表达式: {', '.join(str(d) for d in m['dsl'][:3])}")
                                else:
                                    safe_conditions.append(f"匹配器({m_type})")
                            else:
                                safe_conditions.append(str(m))

                        fallback_conditions = evidence.get("matched_keywords", [])
                        if fallback_conditions and isinstance(fallback_conditions, list):
                            for kw in fallback_conditions:
                                if isinstance(kw, str) and kw not in safe_conditions:
                                    safe_conditions.append(kw)

                        step_data["evidence"] = {
                            "request": evidence.get("request"),
                            "response": evidence.get("response"),
                            "matched_conditions": safe_conditions,
                            "matched_patterns": evidence.get("matched_patterns", []),
                            "timing_ms": evidence.get("response_time_ms") or evidence.get("timing_ms"),
                        }
                
                attack_steps.append(step_data)
            
            attack_artifacts = attack_path.get("artifacts", [])
            
            if raw_steps:
                successful_stages = sum(1 for s in raw_steps if s.get("success") is True or s.get("status") == "validated")
                failed_stages = sum(1 for s in raw_steps if s.get("success") is False or s.get("status") == "failed")
                total_duration = sum(s.get("duration_ms", 0) or 0 for s in raw_steps)
                
                attack_chain_summary = {
                    "total_stages": len(raw_steps),
                    "successful_stages": successful_stages,
                    "failed_stages": failed_stages,
                    "total_duration_ms": total_duration if total_duration > 0 else None,
                    "attack_vector": attack_path.get("attack_vector"),
                    "entry_point": attack_path.get("entry_point"),
                }
        
        vuln_data = {
            "id": vuln.id,
            "title": vuln.vuln_name,
            "type": vuln_type,
            "severity": vuln.severity,
            "cvss_score": cvss_score,
            "url": vuln.url,
            "parameter": parameter,
            "description": description,
            "remediation": remediation,
            "payload_present": bool(getattr(vuln, "payload", None)),
            "attack_path_present": bool(getattr(vuln, "attack_path", None)),
            "evidence_present": bool(getattr(vuln, "evidence", None)),
            "attack_status": attack_status,
            "attack_stage_count": len(attack_steps),
            "attack_artifact_count": len(attack_artifacts),
            "attack_final_reason": final_reason,
            "attack_steps": attack_steps,
            "attack_artifacts": attack_artifacts,
        }
        
        if attack_chain_summary:
            vuln_data["attack_chain_summary"] = attack_chain_summary
        
        vulnerabilities.append(vuln_data)

    payload_count = len([v for v in task.vulnerabilities if getattr(v, "payload", None)])
    attack_path_count = len([v for v in task.vulnerabilities if getattr(v, "attack_path", None)])
    validated_findings = len([v for v in task.vulnerabilities if getattr(v, "evidence", None)])
    validated_attack_paths = len([
        v for v in task.vulnerabilities
        if isinstance(getattr(v, "attack_path", None), dict)
        and getattr(v, "attack_path", {}).get("status") == "validated"
    ])
    artifact_count = sum([
        len((getattr(v, "attack_path", None) or {}).get("artifacts", []))
        for v in task.vulnerabilities
        if isinstance(getattr(v, "attack_path", None), dict)
    ])
    
    report_data = {
        "task_id": task.id,
        "target_url": task.target_url,
        "status": task.status,
        "scan_strategy": task.scan_strategy,
        "scan_time": task.updated_at.isoformat() if task.updated_at else None,
        "summary": summary,
        "attack_simulation_summary": {
            "validated_findings": validated_findings,
            "payload_count": payload_count,
            "attack_path_count": attack_path_count,
            "validated_attack_paths": validated_attack_paths,
            "artifact_count": artifact_count,
        },
        "vulnerabilities": vulnerabilities
    }
    
    return JSONResponse(content=report_data)


@router.delete("/{task_id}")
def delete_report(task_id: int, db: Session = Depends(get_db)):
    """
    删除报告（删除对应任务及其漏洞记录）
    
    Args:
        task_id: 任务ID
        
    Returns:
        dict: 删除结果
    """
    task = db.query(ScanTask).filter(ScanTask.id == task_id).with_for_update().first()
    if not task:
        return {"message": "报告已删除或不存在"}

    db.delete(task)
    db.flush()
    tasks = (
        db.query(ScanTask)
        .order_by(ScanTask.created_at.asc(), ScanTask.id.asc())
        .with_for_update()
        .all()
    )
    for index, current_task in enumerate(tasks, start=1):
        if current_task.display_id != index:
            current_task.display_id = index
    db.flush()
    db.commit()
    return {"message": "报告已删除"}
