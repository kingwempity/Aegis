"""
权限控制服务

功能：
- 基于角色的访问控制（RBAC）
- 细粒度权限验证
- API权限装饰器
- 高危操作权限保护

Notes:
    - 权限格式：resource:action（如 scan:create, report:download）
    - 角色继承：Administrator > Operator > Auditor > Viewer
"""

import os
import logging
from typing import Optional, List, Dict, Set, Callable
from enum import Enum
from functools import wraps
from fastapi import HTTPException, Depends, Request

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """用户角色枚举"""
    ADMINISTRATOR = "Administrator"
    OPERATOR = "Operator"
    AUDITOR = "Auditor"
    VIEWER = "Viewer"


class Permission(str, Enum):
    """权限枚举"""
    # 扫描任务权限
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_UPDATE = "scan:update"
    SCAN_DELETE = "scan:delete"
    SCAN_START = "scan:start"
    SCAN_CANCEL = "scan:cancel"
    
    # 报告权限
    REPORT_CREATE = "report:create"
    REPORT_READ = "report:read"
    REPORT_DOWNLOAD = "report:download"
    REPORT_DELETE = "report:delete"
    
    # 漏洞权限
    VULN_READ = "vuln:read"
    VULN_EXPORT = "vuln:export"
    
    # 用户管理权限
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # 系统设置权限
    SETTINGS_READ = "settings:read"
    SETTINGS_UPDATE = "settings:update"
    
    # 审计日志权限
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"


# 角色权限映射
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMINISTRATOR: {
        # 管理员拥有所有权限
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.SCAN_DELETE, Permission.SCAN_START, Permission.SCAN_CANCEL,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_DOWNLOAD,
        Permission.REPORT_DELETE,
        Permission.VULN_READ, Permission.VULN_EXPORT,
        Permission.USER_CREATE, Permission.USER_READ, Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.SETTINGS_READ, Permission.SETTINGS_UPDATE,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
    },
    Role.OPERATOR: {
        # 操作员：扫描和报告权限
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_UPDATE,
        Permission.SCAN_START, Permission.SCAN_CANCEL,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_DOWNLOAD,
        Permission.VULN_READ,
    },
    Role.AUDITOR: {
        # 审计员：只读权限 + 报告下载
        Permission.SCAN_READ,
        Permission.REPORT_CREATE, Permission.REPORT_READ, Permission.REPORT_DOWNLOAD,
        Permission.VULN_READ, Permission.VULN_EXPORT,
        Permission.AUDIT_READ,
    },
    Role.VIEWER: {
        # 查看者：仅查看权限
        Permission.SCAN_READ,
        Permission.REPORT_READ,
        Permission.VULN_READ,
    },
}


class PermissionService:
    """
    权限服务
    
    提供权限验证和管理功能。
    """
    
    @staticmethod
    def get_permissions(role: str) -> Set[Permission]:
        """
        获取角色对应的权限集合
        
        Args:
            role: 角色名称
            
        Returns:
            Set[Permission]: 权限集合
        """
        try:
            role_enum = Role(role)
            return ROLE_PERMISSIONS.get(role_enum, set())
        except ValueError:
            logger.warning(f"Unknown role: {role}")
            return set()
    
    @staticmethod
    def has_permission(role: str, permission: Permission) -> bool:
        """
        检查角色是否拥有指定权限
        
        Args:
            role: 角色名称
            permission: 权限
            
        Returns:
            bool: 是否拥有权限
        """
        permissions = PermissionService.get_permissions(role)
        return permission in permissions
    
    @staticmethod
    def has_any_permission(role: str, permissions: List[Permission]) -> bool:
        """
        检查角色是否拥有任一权限
        
        Args:
            role: 角色名称
            permissions: 权限列表
            
        Returns:
            bool: 是否拥有任一权限
        """
        role_permissions = PermissionService.get_permissions(role)
        return any(p in role_permissions for p in permissions)
    
    @staticmethod
    def has_all_permissions(role: str, permissions: List[Permission]) -> bool:
        """
        检查角色是否拥有所有权限
        
        Args:
            role: 角色名称
            permissions: 权限列表
            
        Returns:
            bool: 是否拥有所有权限
        """
        role_permissions = PermissionService.get_permissions(role)
        return all(p in role_permissions for p in permissions)
    
    @staticmethod
    def is_admin(role: str) -> bool:
        """
        检查是否为管理员
        
        Args:
            role: 角色名称
            
        Returns:
            bool: 是否为管理员
        """
        return role == Role.ADMINISTRATOR.value
    
    @staticmethod
    def get_role_level(role: str) -> int:
        """
        获取角色等级
        
        Args:
            role: 角色名称
            
        Returns:
            int: 角色等级（越高权限越大）
        """
        levels = {
            Role.ADMINISTRATOR.value: 4,
            Role.OPERATOR.value: 3,
            Role.AUDITOR.value: 2,
            Role.VIEWER.value: 1,
        }
        return levels.get(role, 0)


# 高危API端点定义（需要特殊保护）
HIGH_RISK_ENDPOINTS: Dict[str, List[Permission]] = {
    # 用户管理相关
    "POST:/api/v1/users": [Permission.USER_CREATE],
    "PUT:/api/v1/users": [Permission.USER_UPDATE],
    "DELETE:/api/v1/users": [Permission.USER_DELETE],
    
    # 系统设置相关
    "PUT:/api/v1/settings": [Permission.SETTINGS_UPDATE],
    
    # 数据导出相关
    "GET:/api/v1/reports/export": [Permission.REPORT_DOWNLOAD],
    "GET:/api/v1/vulnerabilities/export": [Permission.VULN_EXPORT],
    "GET:/api/v1/audit/export": [Permission.AUDIT_EXPORT],
    
    # 扫描任务删除
    "DELETE:/api/v1/tasks": [Permission.SCAN_DELETE],
}


def check_permission(user: dict, permission: Permission) -> bool:
    """
    检查用户是否拥有权限
    
    Args:
        user: 用户信息字典
        permission: 权限
        
    Returns:
        bool: 是否拥有权限
    """
    if not user:
        return False
    
    role = user.get("role", "")
    return PermissionService.has_permission(role, permission)


def require_permission(permission: Permission):
    """
    权限装饰器工厂函数
    
    用于保护API端点，要求用户拥有指定权限。
    
    Args:
        permission: 所需权限
        
    Returns:
        装饰器函数
        
    Example:
        @router.post("/scan")
        @require_permission(Permission.SCAN_CREATE)
        async def create_scan(...):
            ...
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, user: dict = None, **kwargs):
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail="未登录或登录已过期"
                )
            
            if not check_permission(user, permission):
                # 记录权限拒绝
                logger.warning(
                    f"Permission denied: user={user.get('username')}, "
                    f"required={permission.value}, role={user.get('role')}"
                )
                raise HTTPException(
                    status_code=403,
                    detail=f"权限不足，需要 {permission.value} 权限"
                )
            
            return await func(*args, user=user, **kwargs)
        
        return wrapper
    
    return decorator


def require_role(min_role: Role):
    """
    角色等级装饰器工厂函数
    
    要求用户角色等级不低于指定角色。
    
    Args:
        min_role: 最低角色要求
        
    Returns:
        装饰器函数
    """
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, user: dict = None, **kwargs):
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail="未登录或登录已过期"
                )
            
            user_level = PermissionService.get_role_level(user.get("role", ""))
            required_level = PermissionService.get_role_level(min_role.value)
            
            if user_level < required_level:
                raise HTTPException(
                    status_code=403,
                    detail=f"权限不足，需要 {min_role.value} 或更高角色"
                )
            
            return await func(*args, user=user, **kwargs)
        
        return wrapper
    
    return decorator


def require_admin(func: Callable):
    """
    管理员权限装饰器
    
    要求用户为管理员。
    """
    @wraps(func)
    async def wrapper(*args, user: dict = None, **kwargs):
        if not user:
            raise HTTPException(
                status_code=401,
                detail="未登录或登录已过期"
            )
        
        if not PermissionService.is_admin(user.get("role", "")):
            raise HTTPException(
                status_code=403,
                detail="权限不足，需要管理员权限"
            )
        
        return await func(*args, user=user, **kwargs)
    
    return wrapper


class PermissionDependency:
    """
    权限依赖类
    
    用于FastAPI依赖注入方式验证权限。
    
    Example:
        @router.post("/scan")
        async def create_scan(
            ...,
            _: None = Depends(PermissionDependency(Permission.SCAN_CREATE))
        ):
            ...
    """
    
    def __init__(self, permission: Permission):
        """
        初始化权限依赖
        
        Args:
            permission: 所需权限
        """
        self.permission = permission
    
    async def __call__(self, user: dict = Depends(lambda: None)):
        """
        验证权限
        
        Args:
            user: 当前用户（通过依赖注入获取）
            
        Raises:
            HTTPException: 权限不足时抛出403
        """
        # 注意：需要配合 get_current_user 使用
        if not user:
            raise HTTPException(
                status_code=401,
                detail="未登录或登录已过期"
            )
        
        if not check_permission(user, self.permission):
            raise HTTPException(
                status_code=403,
                detail=f"权限不足，需要 {self.permission.value} 权限"
            )


def get_user_permissions(role: str) -> List[str]:
    """
    获取用户角色的所有权限列表
    
    Args:
        role: 角色名称
        
    Returns:
        List[str]: 权限列表
    """
    permissions = PermissionService.get_permissions(role)
    return [p.value for p in permissions]


def can_access_endpoint(role: str, method: str, path: str) -> bool:
    """
    检查角色是否可以访问指定端点
    
    Args:
        role: 角色名称
        method: HTTP方法
        path: 请求路径
        
    Returns:
        bool: 是否可以访问
    """
    endpoint_key = f"{method}:{path}"
    
    # 检查是否为高危端点
    for pattern, required_permissions in HIGH_RISK_ENDPOINTS.items():
        if endpoint_key.startswith(pattern.split("{")[0]):
            return PermissionService.has_any_permission(role, required_permissions)
    
    # 非高危端点，默认允许
    return True