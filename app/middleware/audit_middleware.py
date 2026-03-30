"""
审计中间件

功能：
- 自动记录所有API请求
- 记录请求方法、路径、状态码
- 记录用户信息和客户端IP
- 记录请求耗时

Notes:
    - 排除健康检查等不需要记录的路径
    - 敏感路径自动脱敏
"""

import time
import logging
from typing import Callable, Optional
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.services.audit_log import (
    get_audit_log_service,
    AuditEventType,
    AuditLogLevel,
    AuditEvent
)

logger = logging.getLogger(__name__)

# 不需要记录审计日志的路径
EXCLUDED_PATHS = [
    "/api/v1/auth/verify-token",
    "/api/v1/stats",
    "/health",
    "/favicon.ico",
    "/assets",
    "/logo.png",
]

# 敏感路径（需要脱敏记录）
SENSITIVE_PATHS = [
    "/api/v1/auth/login",
    "/api/v1/auth/login-email",
    "/api/v1/auth/send-code",
    "/api/v1/auth/change-password",
]


class AuditMiddleware(BaseHTTPMiddleware):
    """
    审计中间件
    
    自动记录所有API请求到审计日志。
    
    Attributes:
        app: ASGI应用
        audit_service: 审计日志服务
    """
    
    def __init__(self, app: ASGIApp):
        """
        初始化审计中间件
        
        Args:
            app: ASGI应用
        """
        super().__init__(app)
        self.audit_service = get_audit_log_service()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        处理请求并记录审计日志
        
        Args:
            request: HTTP请求
            call_next: 下一个处理函数
            
        Returns:
            Response: HTTP响应
        """
        # 检查是否需要记录
        path = request.url.path
        if self._should_exclude(path):
            return await call_next(request)
        
        # 记录开始时间
        start_time = time.time()
        
        # 获取请求信息
        method = request.method
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")[:500]
        
        # 获取用户信息（如果已登录）
        user_id = None
        username = None
        
        # 尝试从请求状态获取用户信息
        # 注意：这需要在认证中间件之后执行
        if hasattr(request.state, "user"):
            user = request.state.user
            user_id = user.get("id") if isinstance(user, dict) else None
            username = user.get("username") if isinstance(user, dict) else None
        
        # 处理请求
        response = await call_next(request)
        
        # 计算耗时
        duration_ms = int((time.time() - start_time) * 1000)
        
        # 确定事件类型和级别
        event_type = self._get_event_type(path, method, response.status_code)
        level = self._get_log_level(response.status_code)
        
        # 构建审计事件
        details = {
            "method": method,
            "path": self._sanitize_path(path),
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        }
        
        # 记录审计日志
        try:
            self.audit_service.log(AuditEvent(
                event_type=event_type,
                level=level,
                user_id=user_id,
                username=username,
                ip_address=client_ip,
                user_agent=user_agent,
                resource_type=self._get_resource_type(path),
                action=f"{method} {path}",
                details=details,
                status="success" if response.status_code < 400 else "failed"
            ))
        except Exception as e:
            logger.error(f"Failed to record audit log: {e}")
        
        return response
    
    def _should_exclude(self, path: str) -> bool:
        """
        检查路径是否应该排除
        
        Args:
            path: 请求路径
            
        Returns:
            bool: 是否排除
        """
        for excluded in EXCLUDED_PATHS:
            if path.startswith(excluded) or path == excluded:
                return True
        return False
    
    def _get_client_ip(self, request: Request) -> str:
        """
        获取客户端真实IP
        
        Args:
            request: HTTP请求
            
        Returns:
            str: 客户端IP
        """
        # 检查代理头
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        # 检查真实IP头
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # 使用客户端地址
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _get_event_type(self, path: str, method: str, status_code: int) -> AuditEventType:
        """
        根据路径和方法确定事件类型
        
        Args:
            path: 请求路径
            method: HTTP方法
            status_code: 响应状态码
            
        Returns:
            AuditEventType: 事件类型
        """
        # 登录相关
        if "/auth/login" in path:
            if status_code < 400:
                return AuditEventType.LOGIN_SUCCESS
            return AuditEventType.LOGIN_FAILED
        
        if "/auth/logout" in path:
            return AuditEventType.LOGOUT
        
        if "/auth/send-code" in path:
            return AuditEventType.LOGIN_CODE_SENT
        
        # 用户管理
        if "/users" in path:
            if method == "POST":
                return AuditEventType.USER_CREATED
            elif method == "PUT" or method == "PATCH":
                return AuditEventType.USER_UPDATED
            elif method == "DELETE":
                return AuditEventType.USER_DELETED
        
        # 扫描任务
        if "/tasks" in path:
            if method == "POST":
                return AuditEventType.SCAN_CREATED
            elif method == "DELETE":
                return AuditEventType.SCAN_DELETED
        
        # 报告
        if "/reports" in path:
            if method == "POST":
                return AuditEventType.REPORT_CREATED
            elif "download" in path:
                return AuditEventType.REPORT_DOWNLOADED
            elif method == "DELETE":
                return AuditEventType.REPORT_DELETED
        
        # 默认
        if status_code == 401 or status_code == 403:
            return AuditEventType.PERMISSION_DENIED
        
        return AuditEventType.SYSTEM_CONFIG_CHANGED
    
    def _get_log_level(self, status_code: int) -> AuditLogLevel:
        """
        根据状态码确定日志级别
        
        Args:
            status_code: HTTP状态码
            
        Returns:
            AuditLogLevel: 日志级别
        """
        if status_code >= 500:
            return AuditLogLevel.ERROR
        elif status_code >= 400:
            return AuditLogLevel.WARNING
        return AuditLogLevel.INFO
    
    def _sanitize_path(self, path: str) -> str:
        """
        脱敏敏感路径
        
        Args:
            path: 原始路径
            
        Returns:
            str: 脱敏后的路径
        """
        for sensitive in SENSITIVE_PATHS:
            if path.startswith(sensitive):
                return sensitive
        return path
    
    def _get_resource_type(self, path: str) -> str:
        """
        从路径提取资源类型
        
        Args:
            path: 请求路径
            
        Returns:
            str: 资源类型
        """
        parts = path.split("/")
        if len(parts) > 3:
            return parts[3]  # /api/v1/{resource_type}/...
        return "unknown"


def add_audit_middleware(app):
    """
    添加审计中间件到应用
    
    Args:
        app: FastAPI应用实例
    """
    app.add_middleware(AuditMiddleware)
    logger.info("Audit middleware added to application")