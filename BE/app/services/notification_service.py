"""
通知服务

功能：
- 管理系统通知的创建、查询、标记已读
- 支持多种通知类型（用户管理、扫描任务、系统更新等）
- 事件驱动的动态通知系统
- 实时WebSocket推送
- 持久化存储支持
- 完善的错误处理和重试机制

Notes:
    - 通知类型包括: success, warning, info, error
    - 通知分类: user_management, scan, system, security
    - 支持事件订阅和动态处理器注册
"""

import logging
import asyncio
import threading
from typing import List, Optional, Dict, Any, Callable, Awaitable, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from queue import Queue
import uuid
import json
import traceback

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


class NotificationPriority(str, Enum):
    """通知优先级枚举"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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
        priority: 优先级
        time: 创建时间
        read: 是否已读
        extra_data: 额外数据（如用户ID、任务ID等）
        retry_count: 重试次数
        delivery_status: 投递状态
    """
    id: str
    type: str
    category: str
    title: str
    message: str
    time: datetime = field(default_factory=datetime.now)
    read: bool = False
    extra_data: Dict[str, Any] = field(default_factory=dict)
    priority: str = NotificationPriority.MEDIUM.value
    retry_count: int = 0
    delivery_status: str = "pending"  # pending, delivered, failed
    
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
            "extra_data": self.extra_data,
            "priority": self.priority,
            "delivery_status": self.delivery_status
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


class NotificationEvent:
    """
    事件基类，用于事件驱动架构
    """
    def __init__(self, event_type: str, data: Dict[str, Any], source: str = "system"):
        self.event_type = event_type
        self.data = data
        self.source = source
        self.timestamp = datetime.now()
        self.event_id = str(uuid.uuid4())


class EventHandler:
    """
    事件处理器，支持同步和异步处理
    """
    def __init__(self, handler: Callable, name: str = None, priority: int = 0):
        self.handler = handler
        self.name = name or handler.__name__
        self.priority = priority
        self.is_async = asyncio.iscoroutinefunction(handler)


class NotificationError(Exception):
    """通知服务异常基类"""
    pass


class NotificationDeliveryError(NotificationError):
    """通知投递异常"""
    def __init__(self, notification_id: str, reason: str, original_error: Exception = None):
        self.notification_id = notification_id
        self.reason = reason
        self.original_error = original_error
        super().__init__(f"Notification {notification_id} delivery failed: {reason}")


class NotificationService:
    """
    增强的通知服务类
    
    提供以下功能：
    - 通知的创建、查询、标记已读
    - 事件驱动的动态通知生成
    - 实时WebSocket推送
    - 错误处理和重试机制（指数退避）
    - 通知优先级管理
    - 投递状态跟踪
    - 线程安全的异步队列（用于后台任务集成）
    
    Attributes:
        _notifications: 通知列表
        _event_handlers: 事件处理器字典
        _websocket_callbacks: WebSocket回调列表
        _max_retries: 最大重试次数
        _retry_delay: 基础重试延迟（秒）
        _max_retry_delay: 最大重试延迟（秒）- 指数退避上限
        _notification_queue: 线程安全的通知队列
        _background_worker: 后台工作线程
        _worker_loop: 共享的事件循环
    """
    
    def __init__(self):
        """初始化通知服务"""
        self._notifications: List[Notification] = []
        self._event_handlers: Dict[str, List[EventHandler]] = {}
        self._websocket_callbacks: List[Callable] = []
        self._max_retries = 3
        self._retry_delay = 1  # 基础延迟（秒），将使用指数退避
        self._max_retry_delay = 60  # 最大延迟（秒）
        self._delivery_stats = {
            "total_created": 0,
            "total_delivered": 0,
            "total_failed": 0,
            "total_retried": 0
        }
        
        # 线程安全的异步通知队列系统
        self._notification_queue: Queue = Queue()
        self._background_worker: Optional[threading.Thread] = None
        self._worker_loop: Optional[asyncio.AbstractEventLoop] = None
        self._worker_running = False
        
        self._register_default_handlers()
        self._start_background_worker()
    
    def _register_default_handlers(self):
        """注册默认的事件处理器"""
        # 扫描完成事件
        self.register_event_handler("scan.completed", self._handle_scan_completed, priority=10)
        # 扫描失败事件
        self.register_event_handler("scan.failed", self._handle_scan_failed, priority=10)
        # 发现漏洞事件
        self.register_event_handler("vulnerability.found", self._handle_vulnerability_found, priority=8)
        # 用户操作事件
        self.register_event_handler("user.*", self._handle_user_event, priority=5)
        
        logger.info("Default event handlers registered")
    
    def _start_background_worker(self):
        """
        启动后台工作线程（线程安全的事件循环）
        
        创建一个长期运行的后台线程，维护单一事件循环，
        用于处理来自其他线程（如Celery worker）的通知请求。
        这样避免了每次调用都创建/销毁事件循环的资源开销。
        """
        if self._background_worker is not None and self._background_worker.is_alive():
            logger.warning("Background worker already running")
            return
        
        self._worker_running = True
        self._background_worker = threading.Thread(
            target=self._worker_loop_runner,
            daemon=True,
            name="NotificationWorker"
        )
        self._background_worker.start()
        
        logger.info("Background notification worker started (thread-safe event loop)")
    
    def _worker_loop_runner(self):
        """
        后台工作线程的主循环
        
        在独立线程中运行事件循环，从队列中消费通知任务并执行。
        使用共享的事件循环避免资源泄漏。
        """
        self._worker_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._worker_loop)
        
        try:
            logger.info(f"Worker thread {threading.current_thread().name} started with event loop")
            
            while self._worker_running:
                try:
                    # 从队列中获取任务，设置超时以便定期检查 _worker_running 标志
                    task = self._notification_queue.get(timeout=1.0)
                    
                    if task is None:  # 哨兵值，用于停止worker
                        break
                    
                    # 在共享事件循环中执行异步任务
                    if not self._worker_loop.is_closed():
                        asyncio.ensure_future(self._process_queued_task(task), loop=self._worker_loop)
                        
                except Exception as e:
                    if isinstance(e, Exception) and "empty" not in str(e).lower():
                        logger.debug(f"Worker queue get error: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Worker loop runner error: {e}", exc_info=True)
        finally:
            try:
                pending = asyncio.all_tasks(self._worker_loop)
                for task in pending:
                    task.cancel()
                
                if pending:
                    self._worker_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                
                self._worker_loop.close()
            except Exception as e:
                logger.error(f"Error closing worker loop: {e}")
            
            logger.info("Worker thread stopped and event loop closed")
    
    async def _process_queued_task(self, task: Tuple[str, Dict[str, Any], str]):
        """
        处理队列中的通知任务
        
        Args:
            task: 元组 (event_type, data, source)
        """
        event_type, data, source = task
        try:
            await self.emit_event(event_type, data, source)
            logger.info(f"Processed queued event: {event_type} from {source}")
        except Exception as e:
            logger.error(f"Failed to process queued event {event_type}: {e}", exc_info=True)
    
    def emit_event_from_thread(self, event_type: str, data: Dict[str, Any], source: str = "external_thread"):
        """
        从外部线程安全地发射事件（线程安全接口）
        
        此方法设计用于从非asyncio上下文（如Celery worker、普通线程）
        安全地触发通知事件。它将任务放入队列，由后台工作线程处理。
        
        Args:
            event_type: 事件类型
            data: 事件数据
            source: 事件源
            
        Example:
            >>> # 在Celery worker或任意线程中调用
            >>> notification_service.emit_event_from_thread(
            ...     "scan.completed",
            ...     {"task_id": 123, "vulnerabilities_found": 5},
            ...     source="celery_worker"
            ... )
        """
        if not self._worker_running or self._background_worker is None or not self._background_worker.is_alive():
            logger.warning("Background worker not available, attempting to restart...")
            self._start_background_worker()
        
        self._notification_queue.put((event_type, data, source))
        logger.debug(f"Queued event '{event_type}' from {source} for background processing")
    
    def stop_background_worker(self):
        """停止后台工作线程"""
        self._worker_running = False
        self._notification_queue.put(None)  # 发送哨兵值
        
        if self._background_worker and self._background_worker.is_alive():
            self._background_worker.join(timeout=5.0)
            if self._background_worker.is_alive():
                logger.warning("Background worker did not stop gracefully")
        
        logger.info("Background worker stop requested")
    
    def register_event_handler(
        self,
        event_pattern: str,
        handler: Callable,
        priority: int = 0,
        name: str = None
    ):
        """
        注册事件处理器
        
        Args:
            event_pattern: 事件模式（支持通配符 *）
            handler: 处理函数（同步或异步）
            priority: 优先级（数字越大越先执行）
            name: 处理器名称
            
        Example:
            >>> service.register_event_handler(
            ...     "scan.completed",
            ...     lambda event: print(f"Scan done: {event.data}")
            ... )
        """
        event_handler = EventHandler(handler, name, priority)
        
        if event_pattern not in self._event_handlers:
            self._event_handlers[event_pattern] = []
        
        self._event_handlers[event_pattern].append(event_handler)
        # 按优先级排序
        self._event_handlers[event_pattern].sort(key=lambda x: x.priority, reverse=True)
        
        logger.info(f"Registered event handler '{event_handler.name}' for event '{event_pattern}'")
    
    def unregister_event_handler(self, event_pattern: str, handler_name: str = None):
        """
        注销事件处理器
        
        Args:
            event_pattern: 事件模式
            handler_name: 处理器名称（为空则移除所有）
        """
        if event_pattern in self._event_handlers:
            if handler_name:
                self._event_handlers[event_pattern] = [
                    h for h in self._event_handlers[event_pattern]
                    if h.name != handler_name
                ]
            else:
                del self._event_handlers[event_pattern]
            
            logger.info(f"Unregistered event handler(s) for '{event_pattern}'")
    
    async def emit_event(self, event_type: str, data: Dict[str, Any], source: str = "system") -> List[Notification]:
        """
        发射事件并触发所有匹配的处理器
        
        Args:
            event_type: 事件类型
            data: 事件数据
            source: 事件源
            
        Returns:
            List[Notification]: 创建的通知列表
        """
        event = NotificationEvent(event_type, data, source)
        notifications_created = []
        
        logger.info(f"Emitting event: {event_type} from {source}")
        
        # 查找匹配的处理器
        matched_handlers = []
        for pattern, handlers in self._event_handlers.items():
            if self._match_event_pattern(pattern, event_type):
                matched_handlers.extend(handlers)
        
        # 按优先级执行处理器
        matched_handlers.sort(key=lambda x: x.priority, reverse=True)
        
        for handler in matched_handlers:
            try:
                if handler.is_async:
                    result = await handler.handler(event)
                else:
                    result = handler.handler(event)
                
                # 如果返回了通知对象，添加到列表
                if isinstance(result, Notification):
                    notifications_created.append(result)
                    await self._deliver_notification(result)
                elif isinstance(result, list):
                    for notification in result:
                        if isinstance(notification, Notification):
                            notifications_created.append(notification)
                            await self._deliver_notification(notification)
                            
            except Exception as e:
                logger.error(f"Event handler '{handler.name}' failed for event '{event_type}': {e}")
                logger.error(traceback.format_exc())
        
        return notifications_created
    
    def _match_event_pattern(self, pattern: str, event_type: str) -> bool:
        """
        匹配事件模式（支持通配符）
        
        Args:
            pattern: 模式（如 "scan.*", "user.created"）
            event_type: 实际事件类型
            
        Returns:
            bool: 是否匹配
        """
        if pattern == event_type:
            return True
        
        # 支持通配符 *
        if "*" in pattern:
            parts = pattern.split(".")
            event_parts = event_type.split(".")
            
            if len(parts) != len(event_parts):
                return False
            
            for p, e in zip(parts, event_parts):
                if p != "*" and p != e:
                    return False
            return True
        
        return False
    
    def create_notification(
        self,
        type: str,
        category: str,
        title: str,
        message: str,
        extra_data: Optional[Dict[str, Any]] = None,
        priority: str = NotificationPriority.MEDIUM.value
    ) -> Notification:
        """
        创建新通知
        
        Args:
            type: 通知类型（success/warning/info/error）
            category: 通知分类
            title: 通知标题
            message: 通知内容
            extra_data: 额外数据
            priority: 优先级
            
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
            extra_data=extra_data or {},
            priority=priority
        )
        
        self._notifications.insert(0, notification)
        self._delivery_stats["total_created"] += 1
        
        logger.info(f"Created notification: [{category}] {title} - {message} (ID: {notification.id})")
        
        return notification
    
    async def create_and_deliver_notification(
        self,
        type: str,
        category: str,
        title: str,
        message: str,
        extra_data: Optional[Dict[str, Any]] = None,
        priority: str = NotificationPriority.MEDIUM.value
    ) -> Notification:
        """
        创建通知并立即投递
        
        Args:
            type: 通知类型
            category: 通知分类
            title: 标题
            message: 内容
            extra_data: 额外数据
            priority: 优先级
            
        Returns:
            Notification: 创建并投递的通知
        """
        notification = self.create_notification(
            type=type,
            category=category,
            title=title,
            message=message,
            extra_data=extra_data,
            priority=priority
        )
        
        await self._deliver_notification(notification)
        return notification
    
    async def _deliver_notification(self, notification: Notification):
        """
        投递通知到所有连接的客户端
        
        Args:
            notification: 要投递的通知对象
        """
        try:
            # 通过WebSocket广播
            await self._broadcast_via_websocket(notification)
            
            # 更新投递状态
            notification.delivery_status = "delivered"
            self._delivery_stats["total_delivered"] += 1
            
            logger.info(f"Notification {notification.id} delivered successfully")
            
        except Exception as e:
            notification.delivery_status = "failed"
            notification.retry_count += 1
            self._delivery_stats["total_failed"] += 1
            
            logger.error(f"Failed to deliver notification {notification.id}: {e}")
            
            # 尝试重试
            if notification.retry_count < self._max_retries:
                self._schedule_retry(notification)
            else:
                logger.error(f"Max retries exceeded for notification {notification.id}, giving up")
                raise NotificationDeliveryError(
                    notification.id,
                    f"Max retries ({self._max_retries}) exceeded",
                    e
                )
    
    async def _broadcast_via_websocket(self, notification: Notification):
        """
        通过WebSocket广播通知
        
        Args:
            notification: 通知对象
        """
        notification_data = notification.to_dict()
        
        for callback in self._websocket_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(notification_data)
                else:
                    callback(notification_data)
            except Exception as e:
                logger.error(f"WebSocket callback failed: {e}")
    
    def _schedule_retry(self, notification: Notification):
        """
        安排重试投递（使用指数退避策略）
        
        实现指数退避算法：
        delay = min(base_delay * (2 ** retry_count), max_delay)
        
        这可以避免重试风暴，在系统过载时自动降低重试频率。
        
        退避时间表（base=1s, max=60s）：
        - 第1次重试: 1s * 2^0 = 1秒
        - 第2次重试: 1s * 2^1 = 2秒
        - 第3次重试: 1s * 2^2 = 4秒
        - ...以此类推，最大60秒
        
        Args:
            notification: 需要重试的通知
        """
        self._delivery_stats["total_retried"] += 1
        
        # 计算指数退避延迟
        retry_attempt = notification.retry_count
        delay = min(
            self._retry_delay * (2 ** retry_attempt),
            self._max_retry_delay
        )
        
        logger.info(
            f"Scheduling retry #{retry_attempt} for notification {notification.id} "
            f"in {delay:.1f}s (exponential backoff: base={self._retry_delay}s, "
            f"multiplier=2^{retry_attempt}, cap={self._max_retry_delay}s)"
        )
        
        # 使用异步任务执行延迟重试
        async def retry_delivery_with_backoff():
            await asyncio.sleep(delay)
            try:
                await self._deliver_notification(notification)
                logger.info(
                    f"Retry #{retry_attempt + 1} succeeded for notification {notification.id} "
                    f"(waited {delay:.1f}s with backoff)"
                )
            except Exception as e:
                logger.error(f"Retry #{retry_attempt + 1} failed for notification {notification.id}: {e}")
        
        asyncio.create_task(retry_delivery_with_backoff())
    
    def register_websocket_callback(self, callback: Callable):
        """
        注册WebSocket回调函数
        
        Args:
            callback: 回调函数，接收通知数据作为参数
        """
        self._websocket_callbacks.append(callback)
        logger.info(f"Registered WebSocket callback: {callback.__name__ if hasattr(callback, '__name__') else 'anonymous'}")
    
    def unregister_websocket_callback(self, callback: Callable):
        """
        注销WebSocket回调函数
        
        Args:
            callback: 要注销的回调函数
        """
        if callback in self._websocket_callbacks:
            self._websocket_callbacks.remove(callback)
            logger.info(f"Unregistered WebSocket callback")
    
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
        """获取未读通知数量"""
        return sum(1 for n in self._notifications if not n.read)
    
    def mark_as_read(self, notification_id: str) -> bool:
        """标记单条通知为已读"""
        for notification in self._notifications:
            if notification.id == notification_id:
                notification.read = True
                logger.info(f"Marked notification as read: {notification_id}")
                return True
        return False
    
    def mark_all_as_read(self, category: Optional[str] = None) -> int:
        """标记所有通知为已读"""
        count = 0
        for notification in self._notifications:
            if not notification.read:
                if category is None or notification.category == category:
                    notification.read = True
                    count += 1
        
        logger.info(f"Marked {count} notifications as read")
        return count
    
    def delete_notification(self, notification_id: str) -> bool:
        """删除通知"""
        for i, notification in enumerate(self._notifications):
            if notification.id == notification_id:
                self._notifications.pop(i)
                logger.info(f"Deleted notification: {notification_id}")
                return True
        return False
    
    def clear_all(self) -> int:
        """清空所有通知"""
        count = len(self._notifications)
        self._notifications.clear()
        logger.info(f"Cleared all {count} notifications")
        return count
    
    def get_delivery_stats(self) -> Dict[str, int]:
        """获取投递统计信息"""
        return {
            **self._delivery_stats,
            "pending_count": sum(1 for n in self._notifications if n.delivery_status == "pending"),
            "active_websocket_connections": len(self._websocket_callbacks),
            "registered_handlers": sum(len(h) for h in self._event_handlers.values())
        }
    
    # ==================== 默认事件处理器 ====================
    
    def _handle_scan_completed(self, event: NotificationEvent) -> Notification:
        """
        处理扫描完成事件
        """
        task_id = event.data.get("task_id", "Unknown")
        target_url = event.data.get("target_url", "Unknown target")
        vulnerabilities_found = event.data.get("vulnerabilities_found", 0)
        duration = event.data.get("duration_seconds", 0)
        
        title = "扫描任务完成"
        message = f"扫描任务 #{task_id} 已完成，发现 {vulnerabilities_found} 个漏洞，耗时 {duration:.1f} 秒"
        
        if vulnerabilities_found > 0:
            notif_type = NotificationType.WARNING.value
            priority = NotificationPriority.HIGH.value
        else:
            notif_type = NotificationType.SUCCESS.value
            priority = NotificationPriority.LOW.value
        
        return self.create_notification(
            type=notif_type,
            category=NotificationCategory.SCAN.value,
            title=title,
            message=message,
            extra_data={
                "action": "scan_completed",
                "task_id": task_id,
                "target_url": target_url,
                "vulnerabilities_found": vulnerabilities_found,
                "duration_seconds": duration
            },
            priority=priority
        )
    
    def _handle_scan_failed(self, event: NotificationEvent) -> Notification:
        """
        处理扫描失败事件
        """
        task_id = event.data.get("task_id", "Unknown")
        error_message = event.data.get("error_message", "未知错误")
        
        return self.create_notification(
            type=NotificationType.ERROR.value,
            category=NotificationCategory.SCAN.value,
            title="扫描任务失败",
            message=f"扫描任务 #{task_id} 执行失败：{error_message}",
            extra_data={
                "action": "scan_failed",
                "task_id": task_id,
                "error_message": error_message
            },
            priority=NotificationPriority.HIGH.value
        )
    
    def _handle_vulnerability_found(self, event: NotificationEvent) -> Notification:
        """
        处理发现漏洞事件
        """
        vuln_name = event.data.get("name", "未知漏洞")
        risk_level = event.data.get("risk_level", "unknown")
        url = event.data.get("url", "")
        task_id = event.data.get("task_id", "Unknown")
        
        # 根据风险等级设置通知类型和优先级
        risk_mapping = {
            "critical": (NotificationType.ERROR.value, NotificationPriority.CRITICAL.value),
            "high": (NotificationType.ERROR.value, NotificationPriority.HIGH.value),
            "medium": (NotificationType.WARNING.value, NotificationPriority.HIGH.value),
            "low": (NotificationType.WARNING.value, NotificationPriority.MEDIUM.value),
            "info": (NotificationType.INFO.value, NotificationPriority.LOW.value),
        }
        
        notif_type, priority = risk_mapping.get(
            risk_level.lower(),
            (NotificationType.INFO.value, NotificationPriority.MEDIUM.value)
        )
        
        return self.create_notification(
            type=notif_type,
            category=NotificationCategory.SECURITY.value,
            title=f"发现{risk_level.upper()}风险漏洞：{vuln_name}",
            message=f"在 {url} 发现 {risk_level} 级别漏洞：{vuln_name}",
            extra_data={
                "action": "vulnerability_found",
                "task_id": task_id,
                "vulnerability_name": vuln_name,
                "risk_level": risk_level,
                "url": url
            },
            priority=priority
        )
    
    def _handle_user_event(self, event: NotificationEvent) -> Optional[Notification]:
        """
        处理用户相关事件
        """
        action = event.data.get("action", "")
        username = event.data.get("username", "Unknown")
        
        event_handlers = {
            "user_created": lambda: (
                NotificationType.SUCCESS.value,
                f"用户创建成功",
                f"新用户 '{username}' 已成功创建"
            ),
            "user_updated": lambda: (
                NotificationType.INFO.value,
                "用户信息已更新",
                f"用户 '{username}' 的信息已更新"
            ),
            "user_deleted": lambda: (
                NotificationType.WARNING.value,
                "用户已删除",
                f"用户 '{username}' 已被删除"
            ),
            "password_changed": lambda: (
                NotificationType.SUCCESS.value,
                "密码已修改",
                f"用户 '{username}' 的密码已成功修改"
            ),
        }
        
        if action in event_handlers:
            notif_type, title, message = event_handlers[action]()
            return self.create_notification(
                type=notif_type,
                category=NotificationCategory.USER_MANAGEMENT.value,
                title=title,
                message=message,
                extra_data={"action": action, "username": username}
            )
        
        return None


# 全局单例实例
notification_service = NotificationService()


# ==================== 辅助函数（保持向后兼容） ====================

def notify_user_created(username: str, email: str, role: str, operator: str = "管理员") -> Notification:
    """用户创建通知（向后兼容）"""
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
    """用户更新通知（向后兼容）"""
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
    """用户删除通知（向后兼容）"""
    return notification_service.create_notification(
        type=NotificationType.WARNING.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户已删除",
        message=f"{operator} 删除了用户 '{username}'",
        extra_data={"action": "user_deleted", "username": username}
    )


def notify_user_status_changed(username: str, new_status: str, operator: str = "管理员") -> Notification:
    """用户状态变更通知（向后兼容）"""
    return notification_service.create_notification(
        type=NotificationType.INFO.value,
        category=NotificationCategory.USER_MANAGEMENT.value,
        title="用户状态已变更",
        message=f"{operator} 将用户 '{username}' 的状态更改为 {new_status}",
        extra_data={"action": "user_status_changed", "username": username, "new_status": new_status}
    )


def notify_password_changed(username: str, operator: str = "用户") -> Notification:
    """密码修改通知（向后兼容）"""
    return notification_service.create_notification(
        type=NotificationType.SUCCESS.value,
        category=NotificationCategory.SECURITY.value,
        title="密码已修改",
        message=f"{operator} '{username}' 的密码已成功修改",
        extra_data={"action": "password_changed", "username": username}
    )


async def notify_scan_completed(task_id: int, target_url: str, vulnerabilities_found: int, duration_seconds: float):
    """
    扫描完成通知（便捷函数）
    
    Args:
        task_id: 任务ID
        target_url: 目标URL
        vulnerabilities_found: 发现的漏洞数量
        duration_seconds: 扫描时长
    """
    await notification_service.emit_event("scan.completed", {
        "task_id": task_id,
        "target_url": target_url,
        "vulnerabilities_found": vulnerabilities_found,
        "duration_seconds": duration_seconds
    }, source="scanner")


async def notify_scan_failed(task_id: int, error_message: str):
    """
    扫描失败通知（便捷函数）
    
    Args:
        task_id: 任务ID
        error_message: 错误信息
    """
    await notification_service.emit_event("scan.failed", {
        "task_id": task_id,
        "error_message": error_message
    }, source="scanner")


async def notify_vulnerability_found(task_id: int, vulnerability_data: Dict[str, Any]):
    """
    发现漏洞通知（便捷函数）
    
    Args:
        task_id: 任务ID
        vulnerability_data: 漏洞数据
    """
    await notification_service.emit_event("vulnerability.found", {
        "task_id": task_id,
        **vulnerability_data
    }, source="scanner")
