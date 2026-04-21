"""
aegis.app.models.user
---------------------
定义用户 (User) 和 邮箱验证码 (EmailVerificationCode) 的数据库模型。

Author: Aegis Architect
Created: 2026-03-30
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean
from app.db.database import Base


class User(Base):
    """
    用户表模型。
    
    Attributes:
        id (int): 主键 ID
        email (str): 用户邮箱地址（唯一）
        username (str): 用户名
        role (str): 用户角色 (Administrator, Auditor, Viewer)
        status (str): 账户状态 (Active, Inactive)
        is_verified (bool): 邮箱是否已验证
        last_login_at (datetime): 最后登录时间
        created_at (datetime): 创建时间
        updated_at (datetime): 更新时间
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), nullable=True)
    role = Column(String(50), default="Viewer")
    status = Column(String(20), default="Active")
    is_verified = Column(Boolean, default=False)
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class EmailVerificationCode(Base):
    """
    邮箱验证码表模型。
    
    Attributes:
        id (int): 主键 ID
        email (str): 目标邮箱地址
        code (str): 6位验证码
        purpose (str): 用途 (login, register, reset_password)
        is_used (bool): 是否已使用
        expires_at (datetime): 过期时间
        created_at (datetime): 创建时间
    """
    __tablename__ = "email_verification_codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    code = Column(String(6), nullable=False)
    purpose = Column(String(50), default="login")
    is_used = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)