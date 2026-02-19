from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.task import ScanTask
from app.schemas.task import TaskCreate, TaskOut
from worker.celery_app import run_scan_task

router = APIRouter()

@router.post("", response_model=TaskOut, status_code=202)
def create_scan_task(task_in: TaskCreate, db: Session = Depends(get_db)):
    db_task = ScanTask(
        target_url=str(task_in.target_url),
        scan_strategy=task_in.scan_strategy,
        status="PENDING"
    )
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    run_scan_task.delay(db_task.id, str(task_in.target_url), task_in.scan_strategy)
    return db_task

# 新增：获取任务列表接口
@router.get("", response_model=List[TaskOut])
def read_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """获取所有任务列表"""
    tasks = db.query(ScanTask).order_by(ScanTask.id.desc()).offset(skip).limit(limit).all()
    return tasks

@router.get("/{task_id}", response_model=TaskOut)
def read_task(task_id: int, db: Session = Depends(get_db)):
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.delete("/{task_id}")
def delete_task(task_id: int, db: Session = Depends(get_db)):
    """删除扫描任务及其关联的漏洞记录。若任务已不存在则返回 200（幂等）。"""
    task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
    if not task:
        return {"message": "任务已删除或不存在"}
    db.delete(task)
    db.commit()
    return {"message": "任务已删除"}
