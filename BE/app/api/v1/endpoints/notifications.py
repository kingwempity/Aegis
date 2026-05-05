"""
通知管理 API 端点

功能：
- 获取通知列表
- 标记通知已读
- 获取未读数量
- 事件发射（用于触发动态通知）
- 获取投递统计信息
- 测试通知功能

Notes:
    - 支持按分类过滤通知
    - 支持批量标记已读
    - 完全集成事件驱动架构
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime

from app.services.notification_service import (
    notification_service,
    NotificationType,
    NotificationCategory,
    NotificationPriority,
    notify_scan_created,
    notify_scan_started,
    notify_scan_in_progress,
    notify_scan_completed,
    notify_scan_failed,
    notify_vulnerability_found,
    notify_vulnerability_summary
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ============== Pydantic 模型 ==============

class NotificationResponse(BaseModel):
    """通知响应模型"""
    id: str
    type: str
    category: str
    title: str
    message: str
    time: str
    read: bool
    extra_data: dict = {}
    priority: str = "medium"
    delivery_status: str = "pending"


class NotificationListResponse(BaseModel):
    """通知列表响应模型"""
    total: int
    unread_count: int
    notifications: List[NotificationResponse]


class MarkReadRequest(BaseModel):
    """标记已读请求模型"""
    notification_ids: Optional[List[str]] = None  # 为空则标记全部


class MarkReadResponse(BaseModel):
    """标记已读响应模型"""
    success: bool
    marked_count: int


class EventEmitRequest(BaseModel):
    """事件发射请求模型"""
    event_type: str
    data: dict = {}
    source: str = "api"


class EventEmitResponse(BaseModel):
    """事件发射响应模型"""
    success: bool
    event_type: str
    notifications_created: int


class TestNotificationRequest(BaseModel):
    """测试通知请求模型"""
    type: str = "info"
    category: str = "system"
    title: str = "Test Notification"
    message: str = "This is a test notification"
    priority: str = "medium"


# ============== API 端点 ==============

@router.get("/", response_model=NotificationListResponse)
async def get_notifications(
    category: Optional[str] = Query(None, description="按分类过滤"),
    unread_only: bool = Query(False, description="只返回未读通知"),
    limit: int = Query(50, ge=1, le=100, description="返回数量限制")
):
    """
    获取通知列表
    
    Args:
        category: 按分类过滤（user_management/scan/system/security）
        unread_only: 只返回未读通知
        limit: 返回数量限制
        
    Returns:
        NotificationListResponse: 通知列表
    """
    notifications = notification_service.get_notifications(
        category=category,
        unread_only=unread_only,
        limit=limit
    )
    
    return NotificationListResponse(
        total=len(notification_service._notifications),
        unread_count=notification_service.get_unread_count(),
        notifications=[NotificationResponse(**n) for n in notifications]
    )


@router.get("/unread-count")
async def get_unread_count():
    """
    获取未读通知数量
    
    Returns:
        dict: 包含未读数量的字典
    """
    return {
        "unread_count": notification_service.get_unread_count()
    }


@router.post("/mark-read", response_model=MarkReadResponse)
async def mark_notifications_read(request: MarkReadRequest):
    """
    标记通知为已读
    
    Args:
        request: 标记已读请求，包含通知ID列表（为空则标记全部）
        
    Returns:
        MarkReadResponse: 标记结果
    """
    if request.notification_ids is None or len(request.notification_ids) == 0:
        # 标记全部已读
        count = notification_service.mark_all_as_read()
    else:
        # 标记指定通知已读
        count = 0
        for notification_id in request.notification_ids:
            if notification_service.mark_as_read(notification_id):
                count += 1
    
    return MarkReadResponse(
        success=True,
        marked_count=count
    )


@router.post("/{notification_id}/mark-read")
async def mark_single_notification_read(notification_id: str):
    """
    标记单条通知为已读
    
    Args:
        notification_id: 通知ID
        
    Returns:
        dict: 操作结果
        
    Raises:
        HTTPException: 通知不存在时返回404
    """
    success = notification_service.mark_as_read(notification_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="通知不存在")
    
    return {"success": True, "message": "已标记为已读"}


@router.delete("/{notification_id}")
async def delete_notification(notification_id: str):
    """
    删除单条通知
    
    Args:
        notification_id: 通知ID
        
    Returns:
        dict: 操作结果
        
    Raises:
        HTTPException: 通知不存在时返回404
    """
    success = notification_service.delete_notification(notification_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="通知不存在")
    
    return {"success": True, "message": "通知已删除"}


@router.delete("/clear-all")
async def clear_all_notifications():
    """
    清空所有通知
    
    Returns:
        dict: 操作结果
    """
    count = notification_service.clear_all()
    
    return {"success": True, "message": f"已清空 {count} 条通知", "cleared_count": count}


@router.post("/events/emit", response_model=EventEmitResponse)
async def emit_event(request: EventEmitRequest, background_tasks: BackgroundTasks):
    """
    发射事件以触发动态通知生成
    
    这是核心功能，允许系统各部分通过事件驱动方式创建通知。
    
    支持的事件类型：
    - scan.completed: 扫描完成
    - scan.failed: 扫描失败
    - vulnerability.found: 发现漏洞
    - user.created: 用户创建
    - user.updated: 用户更新
    - user.deleted: 用户删除
    - password_changed: 密码修改
    
    Args:
        request: 事件请求体，包含event_type、data、source
        
    Returns:
        EventEmitResponse: 事件处理结果
        
    Example:
        >>> POST /api/v1/notifications/events/emit
        >>> {
        ...     "event_type": "scan.completed",
        ...     "data": {
        ...         "task_id": 123,
        ...         "target_url": "https://example.com",
        ...         "vulnerabilities_found": 5,
        ...         "duration_seconds": 120.5
        ...     },
        ...     "source": "scanner"
        ... }
    """
    try:
        notifications_created = await notification_service.emit_event(
            event_type=request.event_type,
            data=request.data,
            source=request.source
        )
        
        logger.info(f"Event emitted: {request.event_type}, created {len(notifications_created)} notifications")
        
        return EventEmitResponse(
            success=True,
            event_type=request.event_type,
            notifications_created=len(notifications_created)
        )
        
    except Exception as e:
        logger.error(f"Failed to emit event {request.event_type}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"事件处理失败: {str(e)}")


@router.get("/stats")
async def get_notification_stats():
    """
    获取通知系统统计信息
    
    Returns:
        dict: 包含详细统计信息的字典
    """
    stats = notification_service.get_delivery_stats()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        **stats,
        "categories": {
            "user_management": len([n for n in notification_service._notifications if n.category == "user_management"]),
            "scan": len([n for n in notification_service._notifications if n.category == "scan"]),
            "system": len([n for n in notification_service._notifications if n.category == "system"]),
            "security": len([n for n in notification_service._notifications if n.category == "security"])
        },
        "types": {
            "success": len([n for n in notification_service._notifications if n.type == "success"]),
            "warning": len([n for n in notification_service._notifications if n.type == "warning"]),
            "info": len([n for n in notification_service._notifications if n.type == "info"]),
            "error": len([n for n in notification_service._notifications if n.type == "error"])
        }
    }


@router.post("/test", response_model=NotificationResponse)
async def create_test_notification(request: TestNotificationRequest, background_tasks: BackgroundTasks):
    """
    创建测试通知（用于调试和验证）
    
    Args:
        request: 测试通知请求
        
    Returns:
        NotificationResponse: 创建的测试通知
    """
    try:
        notification = await notification_service.create_and_deliver_notification(
            type=request.type,
            category=request.category,
            title=request.title,
            message=request.message,
            extra_data={"action": "test", "timestamp": datetime.now().isoformat()},
            priority=request.priority
        )
        
        logger.info(f"Test notification created: {notification.id}")
        
        return NotificationResponse(**notification.to_dict())
        
    except Exception as e:
        logger.error(f"Failed to create test notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"创建测试通知失败: {str(e)}")


@router.post("/test-scan-completed")
async def test_scan_completed_notification(
    task_id: int = 123,
    target_url: str = "https://example.com",
    vulnerabilities_found: int = 3,
    duration_seconds: float = 120.5
):
    """
    测试扫描完成通知（便捷端点）
    
    用于快速验证扫描完成通知功能是否正常工作。
    
    Args:
        task_id: 任务ID
        target_url: 目标URL
        vulnerabilities_found: 发现的漏洞数
        duration_seconds: 扫描时长
        
    Returns:
        dict: 操作结果
    """
    try:
        await notify_scan_completed(task_id, target_url, vulnerabilities_found, duration_seconds)
        
        return {
            "success": True,
            "message": f"Scan completed notification emitted for task #{task_id}",
            "data": {
                "task_id": task_id,
                "target_url": target_url,
                "vulnerabilities_found": vulnerabilities_found,
                "duration_seconds": duration_seconds
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to emit scan completed notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-vulnerability-found")
async def test_vulnerability_found_notification(
    task_id: int = 123,
    vuln_name: str = "SQL Injection",
    risk_level: str = "high",
    url: str = "https://example.com/search?q=test"
):
    """
    测试发现漏洞通知（便捷端点）
    
    Args:
        task_id: 任务ID
        vuln_name: 漏洞名称
        risk_level: 风险等级 (critical/high/medium/low/info)
        url: 漏洞URL
        
    Returns:
        dict: 操作结果
    """
    try:
        await notify_vulnerability_found(task_id, {
            "name": vuln_name,
            "risk_level": risk_level,
            "url": url
        })
        
        return {
            "success": True,
            "message": f"Vulnerability found notification emitted: {vuln_name}",
            "data": {
                "task_id": task_id,
                "vulnerability_name": vuln_name,
                "risk_level": risk_level,
                "url": url
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to emit vulnerability found notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-scan-started")
async def test_scan_started_notification(
    task_id: int = 123,
    display_id: int = 1,
    target_url: str = "https://example.com",
    scan_strategy: str = "attack_validation",
):
    """
    测试扫描启动通知（便捷端点）
    
    用于快速验证扫描启动通知功能是否正常工作。
    
    Args:
        task_id: 任务ID
        display_id: 显示ID
        target_url: 目标URL
        scan_strategy: 扫描策略
        
    Returns:
        dict: 操作结果
    """
    try:
        await notify_scan_started(
            task_id=task_id,
            display_id=display_id,
            target_url=target_url,
            scan_strategy=scan_strategy,
            target_paths=["/admin", "/api"],
            target_vuln_types=["xss", "sqli"],
            target_parameters=["id", "query"],
        )
        
        return {
            "success": True,
            "message": f"Scan started notification emitted for task #{display_id}",
            "data": {
                "task_id": task_id,
                "display_id": display_id,
                "target_url": target_url,
                "scan_strategy": scan_strategy,
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to emit scan started notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-vulnerability-summary")
async def test_vulnerability_summary_notification(
    task_id: int = 123,
    display_id: int = 1,
    target_url: str = "https://example.com",
):
    """
    测试漏洞汇总通知（便捷端点）
    
    Args:
        task_id: 任务ID
        display_id: 显示ID
        target_url: 目标URL
        
    Returns:
        dict: 操作结果
    """
    try:
        await notify_vulnerability_summary(
            task_id=task_id,
            display_id=display_id,
            target_url=target_url,
            total_count=8,
            severity_counts={
                "critical": 1,
                "high": 3,
                "medium": 2,
                "low": 2,
                "info": 0,
            },
            top_vulnerabilities=[
                {"name": "SQL Injection", "severity": "high", "url": f"{target_url}/search"},
                {"name": "XSS Reflected", "severity": "medium", "url": f"{target_url}/comment"},
                {"name": "Path Traversal", "severity": "high", "url": f"{target_url}/download"},
            ],
            scan_duration=120.5,
            scan_range={"paths": ["/admin", "/api"], "vuln_types": ["xss", "sqli"]},
        )
        
        return {
            "success": True,
            "message": f"Vulnerability summary notification emitted for task #{display_id}",
        }
        
    except Exception as e:
        logger.error(f"Failed to emit vulnerability summary notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/test-scan-in-progress")
async def test_scan_in_progress_notification(
    task_id: int = 123,
    display_id: int = 1,
    progress: int = 50,
    current_stage: str = "正在进行XSS扫描...",
    send_notification: bool = True,
):
    """
    测试扫描进行中通知（便捷端点）
    
    Args:
        task_id: 任务ID
        display_id: 显示ID
        progress: 进度 (0-100)
        current_stage: 当前阶段描述
        send_notification: 是否创建通知记录
        
    Returns:
        dict: 操作结果
    """
    try:
        await notify_scan_in_progress(
            task_id=task_id,
            display_id=display_id,
            progress=progress,
            current_stage=current_stage,
            send_notification=send_notification,
        )
        
        return {
            "success": True,
            "message": f"Scan in progress notification emitted for task #{display_id}: {progress}%",
            "data": {
                "task_id": task_id,
                "display_id": display_id,
                "progress": progress,
                "current_stage": current_stage,
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to emit scan in progress notification: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    """
    健康检查端点
    
    Returns:
        dict: 健康状态
    """
    stats = notification_service.get_delivery_stats()
    
    is_healthy = (
        stats["total_failed"] < stats["total_created"] * 0.1  # 失败率低于10%
    )
    
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "notification_system",
        "timestamp": datetime.now().isoformat(),
        "checks": {
            "delivery_rate": is_healthy,
            "websocket_integration": len(notification_service._websocket_callbacks) > 0,
            "event_handlers_registered": stats["registered_handlers"] > 0
        },
        "stats": stats
    }
