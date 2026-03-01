"""
报告管理 API 端点

提供报告列表查询、报告生成和下载功能，支持多种导出格式。
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import os
import logging

from app.db.database import get_db
from app.models.task import ScanTask
from app.services.report import ReportGenerator

router = APIRouter()

logger = logging.getLogger(__name__)


class ReportResponse(BaseModel):
    """报告响应模型"""
    id: int
    task_id: int
    target_url: str
    risk_score: float
    vuln_count: int
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


@router.get("/", response_model=List[ReportResponse])
def get_reports(db: Session = Depends(get_db)):
    """
    获取所有已完成任务的报告列表
    
    Returns:
        List[ReportResponse]: 报告列表
    """
    # 查询所有已完成的任务
    completed_tasks = db.query(ScanTask).filter(
        ScanTask.status == "COMPLETED"
    ).order_by(ScanTask.id.desc()).all()
    
    reports = []
    for task in completed_tasks:
        # 计算风险分数 (简单逻辑：高危 20分，中危 10分，低危 5分，封顶 100)
        vuln_count = len(task.vulnerabilities)
        score = 0
        for v in task.vulnerabilities:
            sev = (v.severity or "").lower()
            if 'high' in sev or 'critical' in sev:
                score += 20
            elif 'medium' in sev:
                score += 10
            else:
                score += 5
        
        reports.append({
            "id": task.id,
            "task_id": task.id,
            "target_url": task.target_url,
            "risk_score": min(score, 100),
            "vuln_count": vuln_count,
            "created_at": task.updated_at or task.created_at
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
    
    Args:
        task_id: 任务ID
        
    Returns:
        JSONResponse: 报告数据
    """
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="任务尚未完成")
    
    # 构建报告数据
    generator = ReportGenerator()
    summary = generator._get_summary(task)
    
    vulnerabilities = []
    for vuln in task.vulnerabilities:
        # 安全获取可能不存在的新字段
        vuln_type = getattr(vuln, 'vuln_type', None)
        parameter = getattr(vuln, 'parameter', None)
        cvss_score = getattr(vuln, 'cvss_score', None)
        description = getattr(vuln, 'description', None)
        remediation = getattr(vuln, 'remediation', None)
        
        vulnerabilities.append({
            "id": vuln.id,
            "title": vuln.vuln_name,
            "type": vuln_type,
            "severity": vuln.severity,
            "cvss_score": cvss_score,
            "url": vuln.url,
            "parameter": parameter,
            "description": description,
            "remediation": remediation
        })
    
    report_data = {
        "task_id": task.id,
        "target_url": task.target_url,
        "status": task.status,
        "scan_time": task.updated_at.isoformat() if task.updated_at else None,
        "summary": summary,
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
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        return {"message": "报告已删除或不存在"}
    
    db.delete(task)
    db.commit()
    return {"message": "报告已删除"}