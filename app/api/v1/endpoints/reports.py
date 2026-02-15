from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime
import os

from app.db.database import get_db
from app.models.task import ScanTask
from app.services.report import ReportGenerator

router = APIRouter()

class ReportResponse(BaseModel):
    id: int
    task_id: int
    target_url: str
    risk_score: float
    vuln_count: int
    created_at: datetime

@router.get("/", response_model=List[ReportResponse])
def get_reports(db: Session = Depends(get_db)):
    """获取所有已完成任务的报告列表"""
    # 查询所有已完成的任务
    completed_tasks = db.query(ScanTask).filter(ScanTask.status == "COMPLETED").order_by(ScanTask.id.desc()).all()
    
    reports = []
    for task in completed_tasks:
        # 计算风险分数 (简单逻辑：高危 10分，中危 5分，低危 2分，封顶 100)
        vuln_count = len(task.vulnerabilities)
        score = 0
        for v in task.vulnerabilities:
            sev = v.severity.lower()
            if 'high' in sev or 'critical' in sev:
                score += 20
            elif 'medium' in sev:
                score += 10
            else:
                score += 5
        
        reports.append({
            "id": task.id, # 报告 ID 暂时与任务 ID 一致
            "task_id": task.id,
            "target_url": task.target_url,
            "risk_score": min(score, 100),
            "vuln_count": vuln_count,
            "created_at": task.updated_at or task.created_at
        })
    
    return reports

@router.get("/{task_id}/html")
def download_report(task_id: int, db: Session = Depends(get_db)):
    """生成并下载任务的 HTML 报告"""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    if task.status != "COMPLETED":
        raise HTTPException(status_code=400, detail="Task is not completed yet")
        
    filename = f"report_{task_id}.html"
    generator = ReportGenerator()
    try:
        file_path = generator.generate_html(task, filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail="Report file was not generated")
            
        return FileResponse(
            path=file_path, 
            filename=filename, 
            media_type="text/html"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"报告生成失败: {str(e)}")


@router.delete("/{task_id}")
def delete_report(task_id: int, db: Session = Depends(get_db)):
    """删除报告（删除对应已完成任务及其漏洞记录）"""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Report/Task not found")
    db.delete(task)
    db.commit()
    return {"message": "报告已删除"}
