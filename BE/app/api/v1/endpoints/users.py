"""
用户管理 API 端点

功能：
- 用户 CRUD 操作
- 用户创建时自动生成默认密码
- 用户状态管理
- 用户操作通知

Notes:
    - 默认密码格式：用户名@123（如 admin@123）
    - 密码使用 bcrypt 哈希存储
    - 用户操作会生成系统通知
"""

import os
import logging
from typing import List, Optional
from pydantic import BaseModel, EmailStr
from fastapi import APIRouter, HTTPException

# 导入通知服务（带异常保护）
try:
    from app.services.notification_service import (
        notify_user_created,
        notify_user_updated,
        notify_user_deleted,
        notify_user_status_changed,
    )
    _notification_available = True
except ImportError as e:
    logger.warning(f"Notification service not available: {e}")
    _notification_available = False
    # 创建空函数作为降级处理
    def notify_user_created(*args, **kwargs): pass
    def notify_user_updated(*args, **kwargs): pass
    def notify_user_deleted(*args, **kwargs): pass
    def notify_user_status_changed(*args, **kwargs): pass

# 导入验证码服务（用于清除邮箱变更后的验证码缓存）
try:
    from app.services.verification_code import get_verification_code_service
    _verification_code_available = True
except ImportError as e:
    logger.warning(f"Verification code service not available: {e}")
    _verification_code_available = False
    def get_verification_code_service(): return None

logger = logging.getLogger(__name__)

router = APIRouter()


# ============== Pydantic 模型 ==============

class User(BaseModel):
    """用户信息响应模型"""
    id: int
    username: str
    email: str
    role: str
    status: str


class UserCreate(BaseModel):
    """创建用户请求模型"""
    username: str
    email: EmailStr
    role: str
    status: str = "Active"


class UserUpdate(BaseModel):
    """更新用户请求模型"""
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    status: Optional[str] = None


class UserWithPassword(User):
    """包含密码信息的用户模型（仅内部使用）"""
    password_hash: str


# ============== 密码哈希工具 ==============

def hash_password(password: str) -> str:
    """
    哈希密码
    
    Args:
        password: 明文密码
        
    Returns:
        str: 哈希后的密码
    """
    try:
        import bcrypt
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    except ImportError:
        # 如果没有 bcrypt，使用简单的哈希（仅开发环境）
        import hashlib
        return hashlib.sha256(password.encode('utf-8')).hexdigest()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码
    
    Args:
        plain_password: 明文密码
        hashed_password: 哈希密码
        
    Returns:
        bool: 密码是否正确
    """
    try:
        import bcrypt
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ImportError:
        # 如果没有 bcrypt，使用简单的哈希验证（仅开发环境）
        import hashlib
        return hashlib.sha256(plain_password.encode('utf-8')).hexdigest() == hashed_password


def generate_default_password(username: str) -> str:
    """
    生成默认密码
    
    Args:
        username: 用户名
        
    Returns:
        str: 默认密码（格式：用户名@123）
    """
    return f"{username}@123"


# ============== 模拟数据库存储 ==============

def create_user_record(user_id: int, username: str, email: str, role: str, status: str) -> dict:
    """
    创建用户记录（包含默认密码）
    
    Args:
        user_id: 用户ID
        username: 用户名
        email: 邮箱
        role: 角色
        status: 状态
        
    Returns:
        dict: 用户记录
    """
    default_password = generate_default_password(username)
    return {
        "id": user_id,
        "username": username,
        "email": email,
        "role": role,
        "status": status,
        "password_hash": hash_password(default_password)
    }


# 初始化默认用户
_mock_users = [
    create_user_record(1, "admin", "admin@aegis.io", "Administrator", "Active"),
    create_user_record(2, "security_auditor", "auditor@aegis.io", "Auditor", "Active"),
]


# ============== API 端点 ==============

@router.get("", response_model=List[User])
@router.get("/", response_model=List[User])
async def get_users():
    """
    获取所有用户列表
    
    Returns:
        List[User]: 用户列表（不包含密码信息）
    """
    # 返回时不包含密码
    return [
        {"id": u["id"], "username": u["username"], "email": u["email"], "role": u["role"], "status": u["status"]}
        for u in _mock_users
    ]


@router.get("/{user_id}", response_model=User)
async def get_user(user_id: int):
    """
    获取单个用户信息
    
    Args:
        user_id: 用户ID
        
    Returns:
        User: 用户信息
        
    Raises:
        HTTPException: 用户不存在时返回404
    """
    for user in _mock_users:
        if user["id"] == user_id:
            return {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "status": user["status"]
            }
    raise HTTPException(status_code=404, detail="用户不存在")


@router.post("/", response_model=User)
async def create_user(user_in: UserCreate):
    """
    创建新用户
    
    自动生成默认密码（格式：用户名@123）
    
    Args:
        user_in: 用户创建请求
        
    Returns:
        User: 创建的用户信息
        
    Raises:
        HTTPException: 用户名或邮箱已存在时返回400
    """
    # 检查用户名是否已存在
    if any(u["username"] == user_in.username for u in _mock_users):
        raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 检查邮箱是否已存在
    if any(u["email"].lower() == user_in.email.lower() for u in _mock_users):
        raise HTTPException(status_code=400, detail="邮箱已存在")
    
    # 创建用户
    new_id = max(u["id"] for u in _mock_users) + 1 if _mock_users else 1
    new_user = create_user_record(
        user_id=new_id,
        username=user_in.username,
        email=user_in.email,
        role=user_in.role,
        status=user_in.status
    )
    
    _mock_users.append(new_user)
    
    # 记录默认密码到日志（开发环境）
    default_password = generate_default_password(user_in.username)
    logger.info(f"用户创建成功: {user_in.username}, 默认密码: {default_password}")
    
    # 发送用户创建通知
    notify_user_created(
        username=user_in.username,
        email=user_in.email,
        role=user_in.role
    )
    
    return {
        "id": new_user["id"],
        "username": new_user["username"],
        "email": new_user["email"],
        "role": new_user["role"],
        "status": new_user["status"]
    }


@router.put("/{user_id}", response_model=User)
async def update_user(user_id: int, user_in: UserUpdate):
    """
    更新用户信息
    
    Args:
        user_id: 用户ID
        user_in: 用户更新请求
        
    Returns:
        User: 更新后的用户信息
        
    Raises:
        HTTPException: 用户不存在时返回404，用户名/邮箱冲突时返回400
    """
    # 查找用户
    user_index = None
    for i, user in enumerate(_mock_users):
        if user["id"] == user_id:
            user_index = i
            break
    
    if user_index is None:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    user = _mock_users[user_index]
    
    # 检查用户名是否与其他用户冲突
    if user_in.username and user_in.username != user["username"]:
        if any(u["username"] == user_in.username and u["id"] != user_id for u in _mock_users):
            raise HTTPException(status_code=400, detail="用户名已存在")
    
    # 检查邮箱是否与其他用户冲突
    if user_in.email and user_in.email.lower() != user["email"].lower():
        if any(u["email"].lower() == user_in.email.lower() and u["id"] != user_id for u in _mock_users):
            raise HTTPException(status_code=400, detail="邮箱已存在")
    
    # 记录变更字段
    changes = []
    old_email = None  # 记录旧邮箱，用于清除验证码缓存
    
    if user_in.username is not None and user_in.username != user["username"]:
        changes.append("用户名")
        user["username"] = user_in.username
    if user_in.email is not None and user_in.email.lower() != user["email"].lower():
        changes.append("邮箱")
        old_email = user["email"]  # 保存旧邮箱
        user["email"] = user_in.email
    if user_in.role is not None and user_in.role != user["role"]:
        changes.append("角色")
        user["role"] = user_in.role
    if user_in.status is not None and user_in.status != user["status"]:
        changes.append("状态")
        user["status"] = user_in.status
    
    logger.info(f"用户更新成功: {user['username']}")
    
    # 如果邮箱变更，清除验证码缓存
    if old_email:
        try:
            code_service = get_verification_code_service()
            # 清除旧邮箱的验证码缓存
            code_service.invalidate_code(old_email.lower())
            # 也清除新邮箱的验证码缓存（防止之前有人请求过）
            code_service.invalidate_code(user["email"].lower())
            logger.info(f"已清除邮箱变更相关的验证码缓存: {old_email} -> {user['email']}")
        except Exception as e:
            logger.warning(f"清除验证码缓存失败: {e}")
    
    # 发送用户更新通知（仅当有变更时）
    if changes:
        notify_user_updated(
            username=user["username"],
            changes=changes
        )
    
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "status": user["status"]
    }


@router.delete("/{user_id}")
async def delete_user(user_id: int):
    """
    删除用户
    
    Args:
        user_id: 用户ID
        
    Returns:
        dict: 删除结果
        
    Raises:
        HTTPException: 用户不存在时返回404
    """
    global _mock_users
    
    for i, user in enumerate(_mock_users):
        if user["id"] == user_id:
            deleted_username = user["username"]
            _mock_users.pop(i)
            logger.info(f"用户删除成功: {deleted_username}")
            
            # 发送用户删除通知
            notify_user_deleted(username=deleted_username)
            
            return {"success": True, "message": "用户已删除"}
    
    raise HTTPException(status_code=404, detail="用户不存在")


# ============== 导出供认证模块使用 ==============

def get_user_by_email(email: str) -> Optional[dict]:
    """
    根据邮箱获取用户（供认证模块使用）
    
    Args:
        email: 用户邮箱
        
    Returns:
        Optional[dict]: 用户完整信息（包含密码哈希），未找到返回None
    """
    for user in _mock_users:
        if user["email"].lower() == email.lower():
            return user
    return None


def get_user_by_username(username: str) -> Optional[dict]:
    """
    根据用户名获取用户（供认证模块使用）
    
    Args:
        username: 用户名
        
    Returns:
        Optional[dict]: 用户完整信息（包含密码哈希），未找到返回None
    """
    for user in _mock_users:
        if user["username"] == username:
            return user
    return None