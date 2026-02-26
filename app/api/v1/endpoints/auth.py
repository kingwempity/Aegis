"""
认证 API 端点

功能：
- 用户名/邮箱 + 密码登录
- 邮箱 + 验证码登录（多因素认证支持）
- 用户信息获取接口
- 登出接口
- 修改密码接口
- 发送验证码接口

Notes:
    - 使用 JWT Token 进行身份认证
    - 默认密码格式：用户名@123
    - Token 有效期3小时
    - 验证码有效期5分钟
    - 支持双登录方式：密码登录 / 邮箱验证码登录
"""

import os
import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Header, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr, Field
import jwt

# 从 users 模块导入用户查询函数，共享用户数据
from app.api.v1.endpoints.users import get_user_by_email as users_get_by_email
from app.api.v1.endpoints.users import get_user_by_username as users_get_by_username
from app.api.v1.endpoints.users import verify_password, hash_password

# 导入验证码服务
from app.services.verification_code import get_verification_code_service

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


class SendCodeRequest(BaseModel):
    """发送验证码请求"""
    email: EmailStr


class SendCodeResponse(BaseModel):
    """发送验证码响应"""
    success: bool
    message: str
    # 开发模式下返回验证码（生产环境应移除）
    code: Optional[str] = None


class EmailLoginRequest(BaseModel):
    """邮箱验证码登录请求"""
    email: EmailStr
    code: str = Field(..., min_length=6, max_length=6, description="6位验证码")


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


# ============== 邮箱验证码登录端点 ==============

@router.post("/send-code", response_model=SendCodeResponse)
async def send_verification_code(request: SendCodeRequest, http_request: Request):
    """
    发送邮箱验证码
    
    用于邮箱验证码登录方式。验证码发送到用户邮箱，有效期5分钟。
    
    Args:
        request: 包含邮箱的请求体
        http_request: HTTP请求对象（用于获取客户端IP）
        
    Returns:
        SendCodeResponse: 发送结果
        
    Notes:
        - 验证码有效期：5分钟
        - 发送频率限制：60秒内只能发送一次
        - 开发模式下会在响应中返回验证码
        - 默认用户邮箱：admin@aegis.io, auditor@aegis.io
    """
    email = request.email.lower().strip()
    
    # 检查用户是否存在
    user = get_user_by_email(email)
    if not user:
        # 提供更友好的错误提示
        logger.warning(f"Verification code requested for non-existent email: {email}")
        raise HTTPException(
            status_code=400, 
            detail="该邮箱未注册。"
        )
    
    # 检查用户状态
    if user.get("status") != "Active":
        raise HTTPException(status_code=403, detail="该账户已被禁用，请联系管理员")
    
    # 获取客户端IP（用于日志记录）
    client_ip = http_request.client.host if http_request.client else "unknown"
    forwarded_for = http_request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # 发送验证码
    code_service = get_verification_code_service()
    success, message, code = code_service.send_code(email)
    
    if success:
        logger.info(f"Verification code sent to {email} from IP: {client_ip}")
        return SendCodeResponse(
            success=True,
            message=message,
            code=code  # 开发模式返回验证码，生产环境应为 None
        )
    else:
        logger.warning(f"Failed to send verification code to {email}: {message}")
        raise HTTPException(status_code=429, detail=message)


@router.post("/login-email", response_model=LoginResponse)
async def login_with_email(request: EmailLoginRequest, http_request: Request):
    """
    邮箱验证码登录
    
    使用邮箱和验证码进行登录，验证成功后返回 JWT Token。
    
    Args:
        request: 包含邮箱和验证码的请求体
        http_request: HTTP请求对象（用于获取客户端IP）
        
    Returns:
        LoginResponse: 登录结果，包含 Token 和用户信息
        
    Notes:
        - 验证码有效期：5分钟
        - 最大尝试次数：5次
        - 验证成功后验证码立即失效
    """
    email = request.email.lower().strip()
    code = request.code.strip()
    
    # 获取客户端IP
    client_ip = http_request.client.host if http_request.client else "unknown"
    forwarded_for = http_request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # 验证验证码
    code_service = get_verification_code_service()
    valid, message = code_service.verify_code(email, code)
    
    if not valid:
        logger.warning(f"Failed email login attempt for {email} from IP: {client_ip} - {message}")
        raise HTTPException(status_code=401, detail=message)
    
    # 获取用户信息
    user = get_user_by_email(email)
    if not user:
        # 这种情况理论上不应该发生
        logger.error(f"User not found after verification code validation: {email}")
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")
    
    # 检查用户状态
    if user.get("status") != "Active":
        raise HTTPException(status_code=403, detail="该账户已被禁用，请联系管理员")
    
    # 创建 JWT Token
    token = create_jwt_token(user)
    
    logger.info(f"User logged in via email code: {user['username']} ({user['email']}) from IP: {client_ip}")
    
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


@router.get("/can-send-code/{email}")
async def can_send_code(email: str):
    """
    检查是否可以发送验证码
    
    用于前端倒计时显示。
    
    Args:
        email: 邮箱地址
        
    Returns:
        dict: 包含是否可以发送和剩余等待时间
    """
    code_service = get_verification_code_service()
    can_send, wait_seconds = code_service.storage.can_resend(
        email.lower().strip(), 
        code_service.config
    )
    
    return {
        "can_send": can_send,
        "wait_seconds": wait_seconds
    }
