"""
aegis.app.api.v1.endpoints.auth
-------------------------------
邮箱验证码认证相关API端点。

Author: Aegis Architect
Created: 2026-03-30
"""

import re
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime
import logging
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.services.email_service import create_verification_code, verify_code

# 配置日志
logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer(auto_error=False)


# ==================== Pydantic 模型定义 ====================

class SendCodeRequest(BaseModel):
    """发送验证码请求模型。"""
    email: str
    purpose: str = "login"  # login, register, reset_password
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        """验证邮箱格式。"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('请输入有效的邮箱地址')
        return v.lower()


class VerifyCodeRequest(BaseModel):
    """验证验证码请求模型。"""
    email: str
    code: str
    purpose: str = "login"
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        """验证邮箱格式。"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('请输入有效的邮箱地址')
        return v.lower()
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v: str) -> str:
        """验证验证码格式。"""
        if not v.isdigit() or len(v) != 6:
            raise ValueError('验证码必须是6位数字')
        return v


class UserResponse(BaseModel):
    """用户信息响应模型。"""
    id: int
    email: str
    username: Optional[str]
    role: str
    status: str
    is_verified: bool
    last_login_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    """登录响应模型。"""
    success: bool
    message: str
    user: Optional[UserResponse] = None
    is_new_user: bool = False


class SendMessageResponse(BaseModel):
    """发送消息响应模型。"""
    success: bool
    message: str


# ==================== API 端点定义 ====================

@router.post("/send-code", response_model=SendMessageResponse)
async def send_verification_code(
    request: SendCodeRequest,
    db: Session = Depends(get_db)
):
    """
    发送邮箱验证码。
    
    Args:
        request: 包含邮箱地址和用途的请求体
        db: 数据库会话依赖
        
    Returns:
        SendMessageResponse: 发送结果
        
    Raises:
        HTTPException: 当发送失败时返回400错误
        
    Notes:
        - 验证码有效期为10分钟
        - 60秒内不能重复发送
        - 支持多种用途：login, register, reset_password
    """
    # 验证用途参数
    valid_purposes = ["login", "register", "reset_password"]
    if request.purpose not in valid_purposes:
        raise HTTPException(
            status_code=400,
            detail=f"无效的用途参数，支持: {', '.join(valid_purposes)}"
        )
    
    # 创建并发送验证码
    success, message, _ = create_verification_code(db, request.email, request.purpose)
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    return SendMessageResponse(success=True, message=message)


@router.post("/verify-login", response_model=LoginResponse)
async def verify_and_login(
    request: VerifyCodeRequest,
    db: Session = Depends(get_db)
):
    """
    验证验证码并登录/注册。
    
    Args:
        request: 包含邮箱、验证码和用途的请求体
        db: 数据库会话依赖
        
    Returns:
        LoginResponse: 登录结果，包含用户信息和是否新用户标识
        
    Raises:
        HTTPException: 当验证失败时返回400错误
        
    Notes:
        - 如果用户不存在，会自动创建新用户
        - 验证成功后会更新用户最后登录时间
    """
    # 验证验证码
    success, message = verify_code(db, request.email, request.code, request.purpose)
    
    if not success:
        raise HTTPException(status_code=400, detail=message)
    
    # 查找或创建用户
    user = db.query(User).filter(User.email == request.email).first()
    is_new_user = False
    
    if not user:
        # 自动创建新用户
        user = User(
            email=request.email,
            username=None,  # 用户可以后续设置
            role="Viewer",  # 默认角色
            status="Active",
            is_verified=True  # 邮箱已验证
        )
        db.add(user)
        is_new_user = True
        logger.info(f"新用户自动注册: {request.email}")
    else:
        # 更新邮箱验证状态
        if not user.is_verified:
            user.is_verified = True
    
    # 更新最后登录时间
    user.last_login_at = datetime.now()
    db.commit()
    db.refresh(user)
    
    return LoginResponse(
        success=True,
        message="登录成功" if not is_new_user else "注册成功",
        user=UserResponse.model_validate(user),
        is_new_user=is_new_user
    )


@router.get("/check-email")
async def check_email_exists(
    email: str,
    db: Session = Depends(get_db)
):
    """
    检查邮箱是否已注册。
    
    Args:
        email: 要检查的邮箱地址
        db: 数据库会话依赖
        
    Returns:
        dict: 包含邮箱是否存在的标识
        
    Notes:
        - 用于前端判断是登录还是注册流程
    """
    user = db.query(User).filter(User.email == email).first()
    
    return {
        "exists": user is not None,
        "message": "邮箱已注册" if user else "邮箱未注册"
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    email: str = None,
    db: Session = Depends(get_db)
):
    """
    获取当前用户信息。
    
    Args:
        email: 用户邮箱地址（临时方案，后续应使用JWT token）
        db: 数据库会话依赖
        
    Returns:
        UserResponse: 用户信息
        
    Raises:
        HTTPException: 当用户不存在时返回404错误
        
    Notes:
        - 当前为简化实现，后续需要集成JWT认证
    """
    if not email:
        raise HTTPException(status_code=401, detail="未提供用户标识")
    
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    return UserResponse.model_validate(user)