"""
aegis.app.services.email_service
--------------------------------
邮箱验证码服务模块，负责发送验证码邮件。

Author: Aegis Architect
Created: 2026-03-30
"""

import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Tuple
import logging
from sqlalchemy.orm import Session

from app.models.user import EmailVerificationCode

# 配置日志
logger = logging.getLogger(__name__)

# ==================== 邮箱SMTP配置 ====================
# 邮箱SMTP服务配置（QQ邮箱）
SMTP_SERVER = "smtp.qq.com"
SMTP_PORT = 465  # SSL加密端口
SMTP_USERNAME = "aegismail@foxmail.com"  # 发件邮箱
SMTP_PASSWORD = "gxobwuqcpiiucjbh"  # 授权码
SENDER_NAME = "Aegis安全扫描平台"  # 发件人名称

# 验证码配置
CODE_LENGTH = 6  # 验证码长度
CODE_EXPIRE_MINUTES = 10  # 验证码有效期（分钟）
CODE_RESEND_INTERVAL = 60  # 重发间隔（秒）


def generate_verification_code(length: int = CODE_LENGTH) -> str:
    """
    生成指定位数的数字验证码。
    
    Args:
        length: 验证码长度，默认6位
        
    Returns:
        str: 生成的验证码字符串
        
    Notes:
        - 时间复杂度：O(n)，n为验证码长度
        - 使用随机数生成，确保安全性
    """
    return ''.join(random.choices(string.digits, k=length))


def send_verification_email(to_email: str, code: str, purpose: str = "login") -> Tuple[bool, str]:
    """
    发送验证码邮件。
    
    Args:
        to_email: 收件人邮箱地址
        code: 验证码
        purpose: 邮件用途 (login, register, reset_password)
        
    Returns:
        Tuple[bool, str]: (是否成功, 错误消息)
        
    Raises:
        无直接抛出异常，所有异常都被捕获并返回错误消息
        
    Notes:
        - 使用SSL加密连接SMTP服务器
        - 支持HTML格式邮件，提升用户体验
    """
    try:
        # 根据用途确定邮件标题和内容
        purpose_map = {
            "login": ("登录验证码", "您正在登录Aegis安全扫描平台"),
            "register": ("注册验证码", "您正在注册Aegis安全扫描平台账号"),
            "reset_password": ("重置密码验证码", "您正在重置Aegis安全扫描平台密码")
        }
        
        title_prefix, content_prefix = purpose_map.get(purpose, ("验证码", "您的验证码"))
        
        # 构建邮件内容
        subject = f"【Aegis】{title_prefix}"
        
        # HTML邮件正文
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body style="font-family: 'Microsoft YaHei', Arial, sans-serif; background-color: #f5f5f5; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden;">
                <!-- 头部 -->
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px 20px; text-align: center;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 24px;">🛡️ Aegis 安全扫描平台</h1>
                </div>
                
                <!-- 内容区 -->
                <div style="padding: 40px 30px;">
                    <p style="color: #333; font-size: 16px; line-height: 1.6;">您好，</p>
                    <p style="color: #666; font-size: 14px; line-height: 1.6;">{content_prefix}，请使用以下验证码完成操作：</p>
                    
                    <!-- 验证码展示 -->
                    <div style="background-color: #f8f9fa; border: 2px dashed #667eea; border-radius: 8px; padding: 20px; margin: 30px 0; text-align: center;">
                        <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #667eea;">{code}</span>
                    </div>
                    
                    <p style="color: #999; font-size: 13px; line-height: 1.6;">
                        ⏰ 验证码有效期为 <strong>{CODE_EXPIRE_MINUTES}分钟</strong>，请尽快使用。<br>
                        🔒 如非本人操作，请忽略此邮件，您的账户安全不会受到影响。
                    </p>
                </div>
                
                <!-- 底部 -->
                <div style="background-color: #f8f9fa; padding: 20px 30px; border-top: 1px solid #eee;">
                    <p style="color: #999; font-size: 12px; margin: 0; text-align: center;">
                        此邮件由系统自动发送，请勿直接回复。<br>
                        © 2026 Aegis 安全扫描平台 - 您的网络安全守护者
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # 纯文本备选内容
        text_content = f"""
【Aegis 安全扫描平台】

{content_prefix}，您的验证码是：{code}

验证码有效期为{CODE_EXPIRE_MINUTES}分钟，请尽快使用。
如非本人操作，请忽略此邮件。

此邮件由系统自动发送，请勿直接回复。
© 2026 Aegis 安全扫描平台
        """
        
        # 创建邮件对象
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{SENDER_NAME} <{SMTP_USERNAME}>"
        message["To"] = to_email
        
        # 添加文本和HTML内容
        message.attach(MIMEText(text_content, "plain", "utf-8"))
        message.attach(MIMEText(html_content, "html", "utf-8"))
        
        # 发送邮件（使用SSL加密连接）
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, to_email, message.as_string())
        
        logger.info(f"验证码邮件发送成功: {to_email}, 用途: {purpose}")
        return True, "验证码发送成功"
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"SMTP认证失败，请检查邮箱配置: {e}"
        logger.error(error_msg)
        return False, "邮件服务配置错误"
    except smtplib.SMTPException as e:
        error_msg = f"SMTP发送失败: {e}"
        logger.error(error_msg)
        return False, "邮件发送失败，请稍后重试"
    except Exception as e:
        error_msg = f"发送邮件时发生未知错误: {e}"
        logger.error(error_msg, exc_info=True)
        return False, "发送验证码失败，请稍后重试"


def create_verification_code(db: Session, email: str, purpose: str = "login") -> Tuple[bool, str, Optional[str]]:
    """
    创建并发送验证码。
    
    Args:
        db: 数据库会话
        email: 目标邮箱地址
        purpose: 用途 (login, register, reset_password)
        
    Returns:
        Tuple[bool, str, Optional[str]]: (是否成功, 消息, 验证码)
        
    Notes:
        - 会检查是否在重发间隔时间内
        - 自动使失效之前的未使用验证码
    """
    try:
        now = datetime.now()
        
        # 检查是否在重发间隔时间内
        recent_code = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.created_at > now - timedelta(seconds=CODE_RESEND_INTERVAL)
        ).first()
        
        if recent_code:
            remaining = CODE_RESEND_INTERVAL - int((now - recent_code.created_at).total_seconds())
            return False, f"请等待{remaining}秒后再重新获取验证码", None
        
        # 使失效该邮箱之前未使用的验证码
        db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.is_used == False
        ).update({"is_used": True})
        
        # 生成新验证码
        code = generate_verification_code()
        expires_at = now + timedelta(minutes=CODE_EXPIRE_MINUTES)
        
        # 保存到数据库
        verification_code = EmailVerificationCode(
            email=email,
            code=code,
            purpose=purpose,
            expires_at=expires_at
        )
        db.add(verification_code)
        db.commit()
        
        # 发送邮件
        success, message = send_verification_email(email, code, purpose)
        
        if success:
            return True, "验证码已发送到您的邮箱", code
        else:
            # 发送失败，回滚数据库
            db.delete(verification_code)
            db.commit()
            return False, message, None
            
    except Exception as e:
        db.rollback()
        logger.error(f"创建验证码失败: {e}", exc_info=True)
        return False, "创建验证码失败，请稍后重试", None


def verify_code(db: Session, email: str, code: str, purpose: str = "login") -> Tuple[bool, str]:
    """
    验证验证码是否正确。
    
    Args:
        db: 数据库会话
        email: 邮箱地址
        code: 用户输入的验证码
        purpose: 用途 (login, register, reset_password)
        
    Returns:
        Tuple[bool, str]: (是否验证成功, 消息)
        
    Notes:
        - 验证成功后会自动标记验证码为已使用
        - 支持验证码过期检测
    """
    try:
        now = datetime.now()
        
        # 查找有效的验证码
        verification_code = db.query(EmailVerificationCode).filter(
            EmailVerificationCode.email == email,
            EmailVerificationCode.code == code,
            EmailVerificationCode.purpose == purpose,
            EmailVerificationCode.is_used == False
        ).first()
        
        if not verification_code:
            return False, "验证码错误或已失效"
        
        # 检查是否过期
        if verification_code.expires_at < now:
            return False, "验证码已过期，请重新获取"
        
        # 标记为已使用
        verification_code.is_used = True
        db.commit()
        
        return True, "验证成功"
        
    except Exception as e:
        db.rollback()
        logger.error(f"验证验证码失败: {e}", exc_info=True)
        return False, "验证失败，请稍后重试"