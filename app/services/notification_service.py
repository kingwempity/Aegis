"""
通知服务

功能：
- 管理系统通知的创建、查询、标记已读
- 支持多种通知类型（用户管理、扫描任务、系统更新等）
- 通知持久化存储

Notes:
    - 通知类型包括: success, warning, info, error
    - 通知分类: user_management, scan, system
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class NotificationType(str, Enum):
    """通知类型枚举"""
    SUCCESS = "success"
    WARNING = "warning"
    INFO = "info"
    ERROR = "error"


class NotificationCategory(str, Enum):
    """通知分类枚举"""
    USER_MANAGEMENT = "user_management"  # 用户管理相关
    SCAN = "scan"                        # 扫描任务相关
    SYSTEM = "system"                    # 系统更新相关
    SECURITY = "security"                # 安全相关


@dataclass
class Notification:
    """
    通知数据类
    
    Attributes:
        id: 通知唯一ID
        type: 通知类型（success/warning/info/error）
        category: 通知分类
        title: 通知标题
        message: 通知内容
        time: 创建时间
        read: 是否已读
        extra_data: 额外数据（如用户ID、任务ID等）
    """
    id: str
    type: str
    category: str
    title: str
    message: str
    time: datetime = field(default_factory=datetime.now)
    read: bool = False
    extra_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {
            "id": self.id,
            "type": self.type,
            "category": self.category,
            "title": self.title,
            "message": self.message,
            "time": self._format_time(),
            "read": self.read,
            "extra_data": self.extra_data
        }
    
    def _format_time(self) -> str:
        """格式化时间为友好显示"""
        now = datetime.now()
        diff = now - self.time
        
        if diff.total_seconds() < 60:
            return "刚刚"
        elif diff.total_seconds() < 3600:
            minutes = int(diff.total_seconds() / 60)
            return f"{minutes}分钟前"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours}小时前"
        else:
            days = int(diff.total_seconds() / 86400)
            return f"{days}天前"


class NotificationService:
    """
    通知服务类
    
    提供通知的创建、查询、标记已读等功能。
    使用内存存储，支持扩展为数据库存储。
    
    Attributes:
        notifications: 通知列表
    """
    
    def __init__(self):
        """初始化通知服务"""
        self._notifications: List[Notification] = []
        self._initialize_default_notifications()
    
    def _initialize_default_notifications(self):
        """初始化默认通知（示例数据）"""
        now = datetime.now()
        # 添加一些示例通知
        self._notifications = [
            Notification(
                id=str(uuid.uuid4()),
                type=NotificationType.SUCCESS.value,
                category=NotificationCategory.SCAN.value,
                title="扫描完成",
                message="目标 example.com 的扫描已完成",
                time=now - timedelta(minutes=5),
                read=False
            ),
            Notification(
                id=str(uuid.uuid4()),
                type=NotificationType.WARNING.value,
                category=NotificationCategory.SCAN.value,
                title="发现漏洞",
                message="在 target.com 发现 2 个高危漏洞",
                time=now - timedelta(minutes=15),
                read=False
            ),
            Notification(
                id=str(uuid.uuid4()),
                type=NotificationType.INFO.value,
                category=NotificationCategory.SYSTEM.value,
                title="系统更新",
                message="系统已更新至最新版本 v2.1.0",
                time=now - timedelta(hours=1),
                read=False
            ),
        ]
    
    def create_notification(
        self,
        type: str,
        category: str,
        title: str,
        message: str,
        extra_data: Optional[Dict[str, Any]] = None
    ) -> Notification:
        """
        创建新通知
        
        Args:
            type: 通知类型（success/warning/info/error）
            category: 通知分类
            title: 通知标题
            message: 通知内容
            extra_data: 额外数据
            
        Returns:
            Notification: 创建的通知对象
        """
        notification = Notification(
            id=str(uuid.uuid4()),
            type=type,
            category=category,
            title=title,
            message=message,
            time=datetime.now(),
            read=False,
            extra_data=extra_data or {}
        )
        
        self._notifications.insert(0, notification)  # 新通知插入到开头
        logger.info(f"创建通知: [{category}] {title} - {message}")
        
        return notification
    
    def get_notifications(
        self,
        category: Optional[str] = None,
        unread_only: bool = False,
        limit: int = 50
    ) -> List[dict]:
        """
        获取通知列表
        
        Args:
            category: 按分类过滤（可选）
            unread_only: 只返回未读通知
            limit: 返回数量限制
            
        Returns:
            List[dict]: 通知列表（字典格式）
        """
        result = self._notifications
        
        if category:
            result = [n for n in result if n.category == category]
        
        if unread_only:
            result = [n for n in result if not n.read]
        
        return [n.to_dict() for n in result[:limit]]
    
    def get_unread_count(self) -> int:
        """
        获取未读通知数量
        
        Returns:
            int: 未读通知数量
        """
        return sum(1 for n in self._notifications if not n.read)
    
    def mark_as_read(self, notification_id: str) -> bool:
        """
        标记单条通知为已读
        
        Args:
            notification_id: 通知ID
            
        Returns:
            bool: 是否成功
        """
        for notification in self._notifications:
            if notification.id == notification_id:
                notification.read = True
                logger.info(f"通知已标记为已读: {notification_id}")
                return True
        return False
    
    def mark_all_as_read(self, category: Optional[str] = None) -> int:
        """
        标记所有通知为已读
        
        Args:
            category: 只标记指定分类的通知（可选）
            
        Returns:
            int: 标记的通知数量
        """
        count = 0
        for notification in self._notifications:
            if not notification.read:
                if category is None or notification.category == category:
                    notification.read = True
                    count += 1
        
        logger.info(f"已标记 {count} 条通知为已读")
        return count
    
    def delete_notification(self, notification_id: str) -> bool:
        """
        删除通知
        
        Args:
            notification_id: 通知ID
            
        Returns:
            bool: 是否成功
        """
        for i, notification in enumerate(self._notifications):
            if notification.id == notification_id:
                self._notifications.pop(i)
                logger.info(f"通知已删除: {notification_id}")
                return True
        return False
    
    def clear_all(self) -> int:
        """
        清空所有通知
        
        Returns:
            int: 清除的通知数量
        """
        count = len(self._notifications)
        self._notifications.clear()
        logger.info(f"已清空 {count} 条通知")
        return count


# 全局单例实例（必须在辅助函数之前创建）
notification_service = NotificationService()


# ============== 用户管理通知辅助函数 ==============

def notify_user_created(username: str, email: str, role: str, operator: str = "管理员") -> Notification:
    """
    用户创建通知
    
    Args:
        username: 用户名
        email: 邮箱
        role: 角色
        operator: 操作者
        
    Returns:
        Notification: 创建的通知
    """
    return notification_service.create_notification(
        type=NotificationType.SUCCESS.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户创建成功",
        message=f"{operator} 创建了新用户 '{username}'（{role}），邮箱：{email}",
        extra_data={
            "action": "user_created",
            "username": username,
            "email": email,
            "role": role
        }
    )


def notify_user_updated(username: str, changes: List[str], operator: str = "管理员") -> Notification:
    """
    用户更新通知
    
    Args:
        username: 用户名
        changes: 变更列表
        operator: 操作者
        
    Returns:
        Notification: 创建的通知
    """
    changes_str = "、".join(changes) if changes else "信息"
    return notification_service.create_notification(
        type=NotificationType.INFO.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户信息已更新",
        message=f"{operator} 更新了用户 '{username}' 的{changes_str}",
        extra_data={
            "action": "user_updated",
            "username": username,
            "changes": changes
        }
    )


def notify_user_deleted(username: str, operator: str = "管理员") -> Notification:
    """
    用户删除通知
    
    Args:
        username: 用户名
        operator: 操作者
        
    Returns:
        Notification: 创建的通知
    """
    return notification_service.create_notification(
        type=NotificationType.WARNING.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户已删除",
        message=f"{operator} 删除了用户 '{username}'",
        extra_data={
            "action": "user_deleted",
            "username": username
        }
    )


def notify_user_status_changed(username: str, new_status: str, operator: str = "管理员") -> Notification:
    """
    用户状态变更通知
    
    Args:
        username: 用户名
        new_status: 新状态
        operator: 操作者
        
    Returns:
        Notification: 创建的通知
    """
    return notification_service.create_notification(
        type=NotificationType.INFO.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户状态已变更",
        message=f"{operator} 将用户 '{username}' 的状态更改为 {new_status}",
        extra_data={
            "action": "user_status_changed",
            "username": username,
            "new_status": new_status
        }
    )


def notify_password_changed(username: str, operator: str = "用户") -> Notification:
    """
    密码修改通知
    
    Args:
        username: 用户名
        operator: 操作者
        
    Returns:
        Notification: 创建的通知
    """
    return notification_service.create_notification(
        type=NotificationType.SUCCESS.value,
        category=NotificationCategory.SECURITY.value,
        title="密码已修改",
        message=f"{operator} '{username}' 的密码已成功修改",
        extra_data={
            "action": "password_changed",
            "username": username
        }
    )
