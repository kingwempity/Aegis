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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass

logger = logging.getLogger(__name__)


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
    return EmailConfig(
        smtp_host=os.getenv("SMTP_HOST", "smtp.qq.com"),
        smtp_port=int(os.getenv("SMTP_PORT", "465")),
        smtp_user=os.getenv("SMTP_USER", "aegismail@foxmail.com"),
        smtp_password=os.getenv("SMTP_PASSWORD", "gxobwuqcpiiucjbh"),
        from_email=os.getenv("SMTP_FROM_EMAIL", "aegismail@foxmail.com"),
        from_name=os.getenv("SMTP_FROM_NAME", "Aegis 安全扫描系统"),
        use_ssl=os.getenv("SMTP_USE_SSL", "true").lower() == "true",
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
        msg["Subject"] = f"【Aegis】登录验证码"
        msg["From"] = f"{self.config.from_name} <{self.config.from_email}>"
        msg["To"] = to_email
        
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
        if self.config.use_ssl:
            # 使用SSL加密连接（端口465）
            server = smtplib.SMTP_SSL(self.config.smtp_host, self.config.smtp_port, timeout=30)
            try:
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.from_email, to_email, msg.as_string())
            finally:
                server.quit()
        else:
            # 使用STARTTLS（端口587）
            server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30)
            try:
                server.starttls()
                server.login(self.config.smtp_user, self.config.smtp_password)
                server.sendmail(self.config.from_email, to_email, msg.as_string())
            finally:
                server.quit()


# 全局单例实例
email_service = EmailService()