import logging
import threading
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import List
from app.database import get_db
from app.models.task import ScanTask
from app.schemas.task import TaskCreate, TaskOut
from worker.celery_app import run_scan_task, execute_scan_task

router = APIRouter()
logger = logging.getLogger(__name__)


def _next_display_id(db: Session) -> int:
    last_task = (
        db.query(ScanTask)
        .order_by(ScanTask.display_id.desc(), ScanTask.id.desc())
        .with_for_update()
        .first()
    )
    return (last_task.display_id if last_task else 0) + 1


def _compact_display_ids(db: Session) -> None:
    tasks = (
        db.query(ScanTask)
        .order_by(ScanTask.created_at.asc(), ScanTask.id.asc())
        .with_for_update()
        .all()
    )
    for index, task in enumerate(tasks, start=1):
        if task.display_id != index:
            task.display_id = index
    db.flush()

def _run_scan_in_background(task_id: int, target_url: str, scan_strategy: str) -> None:
    background_thread = threading.Thread(
        target=execute_scan_task,
        args=(task_id, target_url, scan_strategy),
        daemon=True,
    )
    background_thread.start()

@router.post("/create", response_model=TaskOut, status_code=202)
@router.post("", response_model=TaskOut, status_code=202)
def create_scan_task(task_in: TaskCreate, db: Session = Depends(get_db)):
    db_task = None
    for _ in range(5):
        db_task = ScanTask(
            display_id=_next_display_id(db),
            target_url=str(task_in.target_url),
            scan_strategy=task_in.scan_strategy,
            status="PENDING"
        )
        db.add(db_task)
        try:
            db.commit()
            db.refresh(db_task)
            break
        except IntegrityError:
            db.rollback()
            db_task = None
    if db_task is None:
        raise HTTPException(status_code=500, detail="创建任务失败，请稍后重试")

    try:
        run_scan_task.delay(db_task.id, str(task_in.target_url), task_in.scan_strategy)
    except Exception as exc:
        logger.exception("Celery dispatch failed, falling back to in-process background scan: %s", exc)
        _run_scan_in_background(db_task.id, str(task_in.target_url), task_in.scan_strategy)

    return db_task

# 新增：获取任务列表接口
@router.get("/list", response_model=List[TaskOut])
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
    task = db.query(ScanTask).filter(ScanTask.id == task_id).with_for_update().first()
    if not task:
        return {"message": "任务已删除或不存在"}
    db.delete(task)
    db.flush()
    _compact_display_ids(db)
    db.commit()
    return {"message": "任务已删除"}
