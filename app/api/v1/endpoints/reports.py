from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime

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
    """获取所有报告列表"""
    # 模拟数据，实际应从数据库查询
    return [
        {
            "id": 1,
            "task_id": 1,
            "target_url": "http://example.com",
            "risk_score": 8.5,
            "vuln_count": 10,
            "created_at": datetime.now()
        }
    ]

@router.get("/{task_id}/html")
def download_report(task_id: int, db: Session = Depends(get_db)):
    """下载任务的 HTML 报告"""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    filename = f"report_{task_id}.html"
    generator = ReportGenerator()
    try:
        file_path = generator.generate_html(task, filename)
        return FileResponse(
            path=file_path, 
            filename=filename, 
            media_type="text/html"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"报告生成失败: {str(e)}")
