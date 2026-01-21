"""
aegis.app.api.v1.endpoints.tasks
--------------------------------
任务管理 API 接口。
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.task import ScanTask
from app.schemas.task import TaskCreate, TaskOut
from worker.celery_app import run_scan_task  # 导入异步任务

router = APIRouter()

@router.post("", response_model=TaskOut, status_code=202)
def create_scan_task(
    task_in: TaskCreate, 
    db: Session = Depends(get_db)
):
    """创建一个新的扫描任务并异步执行"""
    # 1. 写入数据库
    db_task = ScanTask(
        target_url=str(task_in.target_url),
        scan_strategy=task_in.scan_strategy,
        status="PENDING"
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)

    # 2. 触发异步任务 (关键步骤!)
    run_scan_task.delay(db_task.id, str(task_in.target_url))
    
    return db_task

@router.get("/{task_id}", response_model=TaskOut)
def read_task(task_id: int, db: Session = Depends(get_db)):
    """获取任务详情"""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task
