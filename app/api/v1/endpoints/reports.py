from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.task import ScanTask
from app.services.report import ReportGenerator

router = APIRouter()

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
