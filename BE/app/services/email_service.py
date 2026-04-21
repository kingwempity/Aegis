"""
邮件发送服务

功能：
- 发送验证码邮件
- 支持 SMTP 配置（QQ邮箱）
- 真实发送邮件到用户邮箱

Notes:
    - 已配置QQ邮箱SMTP服务
    - 邮箱：aegismail@foxmail.com
    - 使用SSL加密连接（端口465）
"""

import os
import logging
from typing import Optional, Tuple
import smtplib
import ssl
from email.header import Header
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, parseaddr
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def _get_env_value(name: str, default: str) -> str:
    """
    获取环境变量值，并将空字符串视为未配置。

    Args:
        name: 环境变量名
        default: 默认值

    Returns:
        str: 清理后的配置值
    """
    value = os.getenv(name)
    if value is None:
        return default

    value = value.strip()
    return value if value else default


def _get_env_bool(name: str, default: bool) -> bool:
    """
    解析布尔型环境变量，兼容 true/false/1/0/yes/no。
    """
    value = os.getenv(name)
    if value is None or not value.strip():
        return default

    return value.strip().lower() in {"1", "true", "yes", "on"}


def _format_address(display_name: str, email_address: str) -> str:
    """
    使用 RFC 兼容的方式格式化邮箱地址头。
    """
    _, parsed_email = parseaddr(email_address)
    if not parsed_email:
        raise ValueError("发件邮箱格式无效")

    encoded_name = str(Header(display_name, "utf-8")) if display_name else ""
    return formataddr((encoded_name, parsed_email))


@dataclass
class EmailConfig:
    """
    邮件配置类
    
    Attributes:
        smtp_host: SMTP 服务器地址
        smtp_port: SMTP 服务器端口
        smtp_user: SMTP 用户名（发件邮箱）
        smtp_password: SMTP 密码（授权码）
        from_email: 发件人邮箱
        from_name: 发件人名称
        use_ssl: 是否使用 SSL
    """
    smtp_host: str = "smtp.qq.com"
    smtp_port: int = 465
    smtp_user: str = "aegismail@foxmail.com"
    smtp_password: str = "gxobwuqcpiiucjbh"
    from_email: str = "aegismail@foxmail.com"
    from_name: str = "Aegis 安全扫描系统"
    use_ssl: bool = True


def get_email_config() -> EmailConfig:
    """
    从环境变量获取邮件配置，如未配置则使用默认值
    
    Returns:
        EmailConfig: 邮件配置对象
        
    Notes:
        可通过环境变量覆盖默认配置：
        - SMTP_HOST: SMTP服务器地址
        - SMTP_PORT: SMTP端口
        - SMTP_USER: SMTP用户名
        - SMTP_PASSWORD: SMTP密码/授权码
    """
    smtp_host = _get_env_value("SMTP_HOST", "smtp.qq.com")
    smtp_port = int(_get_env_value("SMTP_PORT", "465"))
    smtp_user = _get_env_value("SMTP_USER", "aegismail@foxmail.com")
    smtp_password = _get_env_value("SMTP_PASSWORD", "gxobwuqcpiiucjbh")
    from_email = _get_env_value("SMTP_FROM_EMAIL", smtp_user)
    from_name = _get_env_value("SMTP_FROM_NAME", "Aegis 安全扫描系统")
    use_ssl = _get_env_bool("SMTP_USE_SSL", smtp_port == 465)

    return EmailConfig(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_password=smtp_password,
        from_email=from_email,
        from_name=from_name,
        use_ssl=use_ssl,
    )


class EmailService:
    """
    邮件服务类
    
    提供发送验证码邮件的功能，使用QQ邮箱SMTP服务真实发送邮件。
    
    Attributes:
        config: 邮件配置
    """
    
    def __init__(self, config: Optional[EmailConfig] = None):
        """
        初始化邮件服务
        
        Args:
            config: 邮件配置，默认从环境变量读取
        """
        self.config = config or get_email_config()
    
    def send_verification_code(self, to_email: str, code: str) -> Tuple[bool, str]:
        """
        发送验证码邮件
        
        Args:
            to_email: 收件人邮箱
            code: 验证码
            
        Returns:
            Tuple[bool, str]: (是否成功, 消息)
            
        Notes:
            - 使用SSL加密连接SMTP服务器
            - 验证码有效期为5分钟
        """
        try:
            msg = self._create_verification_email(to_email, code)
            self._send_email_via_smtp(to_email, msg)
            logger.info(f"验证码邮件发送成功: {to_email}")
            return True, "验证码已发送到您的邮箱"
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP认证失败: {e}")
            return False, "邮件服务认证失败，请检查邮箱授权码配置"
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP连接失败: {e}")
            return False, "无法连接到邮件服务器，请检查网络或防火墙设置"
        except smtplib.SMTPException as e:
            logger.error(f"SMTP发送失败 to {to_email}: {e}")
            return False, f"邮件发送失败: {str(e)}"
        except TimeoutError as e:
            logger.error(f"SMTP连接超时: {e}")
            return False, "邮件服务器连接超时，请稍后重试"
        except Exception as e:
            logger.error(f"发送邮件时发生错误 to {to_email}: {e}", exc_info=True)
            return False, f"邮件发送失败: {str(e)}"
    
    def _create_verification_email(self, to_email: str, code: str) -> MIMEMultipart:
        """
        创建验证码邮件内容
        
        Args:
            to_email: 收件人邮箱
            code: 验证码
            
        Returns:
            MIMEMultipart: 邮件对象
            
        Notes:
            - 包含纯文本和HTML两种格式
            - HTML格式提供更好的视觉体验
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = str(Header("【Aegis】登录验证码", "utf-8"))
        msg["From"] = _format_address(self.config.from_name, self.config.from_email)
        msg["To"] = parseaddr(to_email)[1] or to_email
        
        # 纯文本内容（备选）
        text_content = f"""
您好！

您正在登录 Aegis 安全扫描系统，您的验证码是：

{code}

验证码有效期为 5 分钟，请尽快使用。

如果这不是您的操作，请忽略此邮件，您的账户安全不会受到影响。

---
Aegis 安全扫描系统
此邮件由系统自动发送，请勿直接回复。
"""
        
        # HTML 内容（精美模板）
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: 'Microsoft YaHei', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f5f5f5; margin: 0; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); overflow: hidden;">
        
        <!-- 头部 -->
        <div style="background: linear-gradient(135deg, #ff6b00 0%, #ff8c00 100%); padding: 30px 20px; text-align: center;">
            <h1 style="color: #ffffff; margin: 0; font-size: 24px; font-weight: 600;">🛡️ Aegis 安全扫描系统</h1>
        </div>
        
        <!-- 内容区 -->
        <div style="padding: 40px 30px;">
            <p style="color: #333; font-size: 16px; line-height: 1.6; margin: 0 0 20px 0;">您好！</p>
            <p style="color: #666; font-size: 14px; line-height: 1.6; margin: 0 0 30px 0;">
                您正在登录 <strong style="color: #ff6b00;">Aegis 安全扫描系统</strong>，请使用以下验证码完成登录：
            </p>
            
            <!-- 验证码展示 -->
            <div style="background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); border: 2px dashed #ff6b00; border-radius: 12px; padding: 25px; margin: 30px 0; text-align: center;">
                <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #ff6b00; font-family: 'Courier New', monospace;">{code}</span>
            </div>
            
            <div style="background-color: #fff3e0; border-left: 4px solid #ff6b00; padding: 15px 20px; margin: 25px 0; border-radius: 0 8px 8px 0;">
                <p style="color: #e65100; font-size: 13px; margin: 0; line-height: 1.6;">
                    ⏰ <strong>验证码有效期为 5 分钟</strong>，请尽快使用。<br>
                    🔒 如非本人操作，请忽略此邮件，您的账户安全不会受到影响。
                </p>
            </div>
        </div>
        
        <!-- 底部 -->
        <div style="background-color: #f8f9fa; padding: 25px 30px; border-top: 1px solid #eee; text-align: center;">
            <p style="color: #999; font-size: 12px; margin: 0; line-height: 1.8;">
                此邮件由系统自动发送，请勿直接回复。<br>
                © 2026 Aegis 安全扫描系统 - 您的网络安全守护者
            </p>
        </div>
        
    </div>
</body>
</html>
"""
        
        msg.attach(MIMEText(text_content, "plain", "utf-8"))
        msg.attach(MIMEText(html_content, "html", "utf-8"))
        
        return msg
    
    def _send_email_via_smtp(self, to_email: str, msg: MIMEMultipart) -> None:
        """
        通过 SMTP 发送邮件（SSL加密）
        
        Args:
            to_email: 收件人邮箱
            msg: 邮件对象
            
        Notes:
            - 使用SMTP_SSL建立加密连接
            - QQ邮箱要求使用授权码而非邮箱密码
        """
        if not self.config.smtp_host:
            raise ValueError("SMTP_HOST 未配置")
        if not self.config.smtp_user:
            raise ValueError("SMTP_USER 未配置")
        if not self.config.smtp_password:
            raise ValueError("SMTP_PASSWORD 未配置")

        logger.info(
            "Connecting to SMTP server %s:%s (ssl=%s) for %s",
            self.config.smtp_host,
            self.config.smtp_port,
            self.config.use_ssl,
            to_email,
        )

        if self.config.use_ssl:
            # 使用SSL加密连接（端口465）
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(
                self.config.smtp_host,
                self.config.smtp_port,
                timeout=30,
                context=context,
            )
            try:
                server.ehlo()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.from_email, to_email, msg.as_string())
            finally:
                try:
                    server.quit()
                except smtplib.SMTPServerDisconnected:
                    pass
        else:
            # 使用STARTTLS（端口587）
            server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30)
            try:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.from_email, to_email, msg.as_string())
            finally:
                try:
                    server.quit()
                except smtplib.SMTPServerDisconnected:
                    pass


# 全局单例实例
email_service = EmailService()
