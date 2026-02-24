"""
认证 API 端点

功能：
- 用户名/邮箱 + 密码登录
- 用户信息获取接口
- 登出接口
- 修改密码接口

Notes:
    - 使用 JWT Token 进行身份认证
    - 默认密码格式：用户名@123
    - Token 有效期3小时
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
import jwt

# 从 users 模块导入用户查询函数，共享用户数据
from app.api.v1.endpoints.users import get_user_by_email as users_get_by_email
from app.api.v1.endpoints.users import get_user_by_username as users_get_by_username
from app.api.v1.endpoints.users import verify_password, hash_password

logger = logging.getLogger(__name__)

router = APIRouter()

# JWT 配置
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "aegis-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", "3"))

# HTTP Bearer 认证方案
security = HTTPBearer(auto_error=False)


def get_user_by_email(email: str) -> Optional[dict]:
    """根据邮箱获取用户（委托给 users 模块）"""
    return users_get_by_email(email)


def get_user_by_username(username: str) -> Optional[dict]:
    """根据用户名获取用户（委托给 users 模块）"""
    return users_get_by_username(username)


# ============== Pydantic 模型 ==============

class LoginRequest(BaseModel):
    """登录请求"""
    username: str  # 可以是用户名或邮箱
    password: str


class LoginResponse(BaseModel):
    """登录响应"""
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[dict] = None


class ChangePasswordRequest(BaseModel):
    """修改密码请求"""
    old_password: str
    new_password: str


class UserInfo(BaseModel):
    """用户信息"""
    id: int
    username: str
    email: str
    role: str
    status: str


class UserInfoResponse(BaseModel):
    """用户信息响应"""
    success: bool
    user: Optional[UserInfo] = None


# ============== JWT 工具函数 ==============

def create_jwt_token(user: dict) -> str:
    """
    创建 JWT Token
    
    Args:
        user: 用户信息字典
        
    Returns:
        str: JWT Token 字符串
    """
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token


def verify_jwt_token(token: str) -> Optional[dict]:
    """
    验证 JWT Token
    
    Args:
        token: JWT Token 字符串
        
    Returns:
        Optional[dict]: 解码后的用户信息，验证失败返回 None
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    authorization: Optional[str] = Header(None)
) -> Optional[dict]:
    """
    获取当前登录用户（依赖注入）
    
    Args:
        credentials: HTTP Bearer 认证凭据
        authorization: Authorization 头
        
    Returns:
        Optional[dict]: 用户信息，未登录返回 None
    """
    token = None
    
    # 优先从 credentials 获取
    if credentials:
        token = credentials.credentials
    # 备选：从 authorization header 获取
    elif authorization:
        if authorization.startswith("Bearer "):
            token = authorization[7:]
    
    if not token:
        return None
    
    return verify_jwt_token(token)


async def require_auth(user: Optional[dict] = Depends(get_current_user)) -> dict:
    """
    要求用户已登录（依赖注入）
    
    Args:
        user: 当前用户
        
    Returns:
        dict: 用户信息
        
    Raises:
        HTTPException: 未登录时抛出 401 错误
    """
    if not user:
        raise HTTPException(status_code=401, detail="未登录或登录已过期，请重新登录")
    return user


# ============== API 端点 ==============

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    """
    用户登录
    
    支持用户名或邮箱登录，密码验证成功后返回 JWT Token。
    
    Args:
        request: 包含用户名/邮箱和密码的请求体
        
    Returns:
        LoginResponse: 登录结果，包含 Token 和用户信息
        
    Notes:
        默认密码格式：用户名@123
        例如：admin 用户的默认密码是 admin@123
    """
    username_input = request.username.strip()
    password = request.password
    
    # 尝试通过用户名或邮箱查找用户
    user = get_user_by_username(username_input) or get_user_by_email(username_input)
    
    if not user:
        logger.warning(f"Login attempt with unknown user: {username_input}")
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # 检查用户状态
    if user.get("status") != "Active":
        raise HTTPException(status_code=403, detail="该账户已被禁用，请联系管理员")
    
    # 验证密码
    if not verify_password(password, user.get("password_hash", "")):
        logger.warning(f"Failed login attempt for user: {username_input}")
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # 创建 JWT Token
    token = create_jwt_token(user)
    
    logger.info(f"User logged in: {user['username']} ({user['email']})")
    
    return LoginResponse(
        success=True,
        message="登录成功",
        token=token,
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        }
    )


@router.get("/me", response_model=UserInfoResponse)
async def get_current_user_info(user: dict = Depends(require_auth)):
    """
    获取当前登录用户信息
    
    需要在 Header 中携带 Bearer Token。
    
    Args:
        user: 当前用户（通过依赖注入获取）
        
    Returns:
        UserInfoResponse: 用户信息
    """
    # 从数据库获取完整用户信息
    full_user = get_user_by_email(user["email"])
    
    if not full_user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    return UserInfoResponse(
        success=True,
        user=UserInfo(
            id=full_user["id"],
            username=full_user["username"],
            email=full_user["email"],
            role=full_user["role"],
            status=full_user["status"],
        )
    )


@router.post("/logout")
async def logout(user: dict = Depends(require_auth)):
    """
    登出
    
    客户端需要删除本地存储的 Token。
    服务端只记录登出日志（JWT 无状态，服务端不维护会话）。
    
    Args:
        user: 当前用户
        
    Returns:
        dict: 登出结果
    """
    logger.info(f"User logged out: {user.get('username')} ({user.get('email')})")
    return {"success": True, "message": "登出成功"}


@router.get("/verify-token")
@router.post("/verify-token")
async def verify_token(user: dict = Depends(get_current_user)):
    """
    验证 Token 是否有效
    
    支持 GET 和 POST 方法，以适应不同客户端调用方式。
    
    Args:
        user: 当前用户（通过依赖注入获取）
        
    Returns:
        dict: 验证结果
    """
    if user:
        return {"valid": True, "user": user}
    return {"valid": False}


@router.post("/change-password")
async def change_password(request: ChangePasswordRequest, user: dict = Depends(require_auth)):
    """
    修改密码
    
    Args:
        request: 包含旧密码和新密码的请求体
        user: 当前用户
        
    Returns:
        dict: 修改结果
        
    Raises:
        HTTPException: 旧密码错误时返回 400
    """
    # 获取完整用户信息
    full_user = get_user_by_email(user["email"])
    if not full_user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 验证旧密码
    if not verify_password(request.old_password, full_user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="旧密码错误")
    
    # 验证新密码格式
    if len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密码长度至少6位")
    
    # 更新密码
    full_user["password_hash"] = hash_password(request.new_password)
    
    logger.info(f"Password changed for user: {user.get('username')}")
    
    return {"success": True, "message": "密码修改成功"}