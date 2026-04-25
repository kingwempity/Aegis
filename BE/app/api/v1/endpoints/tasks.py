import logging
import threading
import asyncio
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


def _calculate_duration_seconds(task: ScanTask) -> float | None:
    if not task.created_at or not task.updated_at:
        return None
    return (task.updated_at - task.created_at).total_seconds()


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

def _run_scan_in_background(task_id: int, target_url: str, scan_strategy: str,
                            target_paths=None, target_vuln_types=None, target_parameters=None) -> None:
    background_thread = threading.Thread(
        target=execute_scan_task,
        args=(task_id, target_url, scan_strategy, target_paths, target_vuln_types, target_parameters),
        daemon=True,
    )
    background_thread.start()


async def _emit_task_created_notification(task_id: int, display_id: int, target_url: str, strategy: str):
    """
    发射任务创建通知事件
    
    Args:
        task_id: 任务数据库ID
        display_id: 显示ID
        target_url: 目标URL
        strategy: 扫描策略
    """
    try:
        from app.services.notification_service import notification_service
        
        await notification_service.emit_event(
            event_type="scan.created",
            data={
                "task_id": task_id,
                "display_id": display_id,
                "target_url": target_url,
                "scan_strategy": strategy,
                "status": "PENDING"
            },
            source="task_api"
        )
        
        logger.info(f"Emitted notification for task creation: #{display_id}")
        
    except Exception as e:
        logger.error(f"Failed to emit task created notification: {e}", exc_info=True)


@router.post("/create", response_model=TaskOut, status_code=202)
@router.post("", response_model=TaskOut, status_code=202)
def create_scan_task(task_in: TaskCreate, db: Session = Depends(get_db)):
    db_task = None
    for _ in range(5):
        db_task = ScanTask(
            display_id=_next_display_id(db),
            target_url=str(task_in.target_url),
            scan_strategy=task_in.scan_strategy,
            target_paths=task_in.target_paths,
            target_vuln_types=task_in.target_vuln_types,
            target_parameters=task_in.target_parameters,
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
        run_scan_task.delay(
            db_task.id,
            str(task_in.target_url),
            task_in.scan_strategy,
            task_in.target_paths,
            task_in.target_vuln_types,
            task_in.target_parameters,
        )
    except Exception as exc:
        logger.exception("Celery dispatch failed, falling back to in-process background scan: %s", exc)
        _run_scan_in_background(
            db_task.id,
            str(task_in.target_url),
            task_in.scan_strategy,
            task_in.target_paths,
            task_in.target_vuln_types,
            task_in.target_parameters,
        )

    # 发射任务创建通知（异步，不阻塞响应）
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(_emit_task_created_notification(
                db_task.id,
                db_task.display_id,
                str(task_in.target_url),
                task_in.scan_strategy
            ))
        else:
            loop.run_until_complete(_emit_task_created_notification(
                db_task.id,
                db_task.display_id,
                str(task_in.target_url),
                task_in.scan_strategy
            ))
    except Exception as e:
        logger.warning(f"Could not emit task creation notification: {e}")

    return db_task


# 新增：获取任务列表接口
@router.get("/list", response_model=List[TaskOut])
@router.get("", response_model=List[TaskOut])
def read_tasks(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """获取所有任务列表"""
    tasks = db.query(ScanTask).order_by(ScanTask.id.desc()).offset(skip).limit(limit).all()
    results = []
    for task in tasks:
        task_out = TaskOut.model_validate(task)
        task_out.duration_seconds = _calculate_duration_seconds(task)
        results.append(task_out)
    return results


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
    
    # 记录任务信息用于通知
    task_display_id = task.display_id
    task_target_url = task.target_url
    
    db.delete(task)
    db.flush()
    _compact_display_ids(db)
    db.commit()
    
    # 发射任务删除通知（使用线程安全队列）
    try:
        from app.services.notification_service import notification_service
        
        # 使用线程安全的队列接口，避免创建新的事件循环
        notification_service.emit_event_from_thread(
            event_type="scan.deleted",
            data={
                "task_id": task_id,
                "display_id": task_display_id,
                "target_url": task_target_url
            },
            source="task_api"
        )
        logger.info(f"Queued task deletion notification for task {task_id}")
        
    except Exception as e:
        logger.warning(f"Could not emit task deletion notification: {e}")
    
    return {"message": "任务已删除"}


# ==================== 扫描完成通知桥接函数 ====================

def notify_scan_completion_to_fastapi(
    task_id: int,
    target_url: str,
    vulnerabilities_found: int,
    duration_seconds: float,
    status: str = "completed"
):
    """
    从扫描器/Worker调用此函数来通知FastAPI后端扫描完成
    
    此函数设计为从Celery worker或后台线程中安全调用。
    
    使用线程安全的队列系统（Issue 1 修复）：
    - 不再每次调用创建新的事件循环
    - 通过共享的后台工作线程处理异步通知
    - 避免资源泄漏和性能问题
    
    Args:
        task_id: 任务ID
        target_url: 目标URL
        vulnerabilities_found: 发现的漏洞数量
        duration_seconds: 扫描时长（秒）
        status: 完成状态 ("completed" 或 "failed")
    """
    try:
        from app.services.notification_service import notification_service
        
        if status == "completed":
            # 使用线程安全的队列接口，由后台worker处理
            notification_service.emit_event_from_thread(
                event_type="scan.completed",
                data={
                    "task_id": task_id,
                    "target_url": target_url,
                    "vulnerabilities_found": vulnerabilities_found,
                    "duration_seconds": duration_seconds
                },
                source="scanner_worker"
            )
            logger.info(f"Queued scan completed notification for task {task_id}")
        else:
            notification_service.emit_event_from_thread(
                event_type="scan.failed",
                data={
                    "task_id": task_id,
                    "error_message": f"Scan completed with status: {status}"
                },
                source="scanner_worker"
            )
            logger.info(f"Queued scan failed notification for task {task_id}")
            
    except Exception as e:
        logger.error(f"Failed to queue scan completion notification: {e}", exc_info=True)


def notify_vulnerability_discovery_to_fastapi(
    task_id: int,
    vulnerability_data: dict
):
    """
    从扫描器调用此函数来通知发现漏洞
    
    使用线程安全的队列系统（Issue 1 修复）。
    
    Args:
        task_id: 任务ID
        vulnerability_data: 漏洞数据字典
    """
    try:
        from app.services.notification_service import notification_service
        
        # 使用线程安全的队列接口
        notification_service.emit_event_from_thread(
            event_type="vulnerability.found",
            data={
                "task_id": task_id,
                **vulnerability_data
            },
            source="scanner_worker"
        )
        logger.info(f"Queued vulnerability found notification for task {task_id}")
        
    except Exception as e:
        logger.error(f"Failed to queue vulnerability found notification: {e}", exc_info=True)
