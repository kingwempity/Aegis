"""
通知管理 API 端点

功能：
- 获取通知列表
- 标记通知已读
- 获取未读数量

Notes:
    - 支持按分类过滤通知
    - 支持批量标记已读
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.services.notification_service import notification_service

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