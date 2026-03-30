"""
邮件发送服务

功能：
- 发送验证码邮件
- 支持 SMTP 配置
- 开发环境下支持控制台输出验证码

Notes:
    - 生产环境需要配置 SMTP 服务器
    - 开发环境可设置 EMAIL_DEBUG=True 在控制台查看验证码
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
        smtp_user: SMTP 用户名
        smtp_password: SMTP 密码
        from_email: 发件人邮箱
        from_name: 发件人名称
        use_tls: 是否使用 TLS
        debug: 是否为调试模式
    """
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = "noreply@aegis.io"
    from_name: str = "Aegis 安全扫描系统"
    use_tls: bool = True
    debug: bool = True


def get_email_config() -> EmailConfig:
    """
    从环境变量获取邮件配置
    
    Returns:
        EmailConfig: 邮件配置对象
    """
    return EmailConfig(
        smtp_host=os.getenv("SMTP_HOST", ""),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER", ""),
        smtp_password=os.getenv("SMTP_PASSWORD", ""),
        from_email=os.getenv("SMTP_FROM_EMAIL", "noreply@aegis.io"),
        from_name=os.getenv("SMTP_FROM_NAME", "Aegis 安全扫描系统"),
        use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
        debug=os.getenv("EMAIL_DEBUG", "true").lower() == "true",
    )


class EmailService:
    """
    邮件服务类
    
    提供发送验证码邮件的功能，支持开发模式和生产模式。
    
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
        """
        # 开发模式：直接输出到控制台
        if self.config.debug or not self.config.smtp_host:
            logger.info(f"\n{'='*50}")
            logger.info(f"[验证码] 收件人: {to_email}")
            logger.info(f"[验证码] 验证码: {code}")
            logger.info(f"[验证码] 有效期: 5分钟")
            logger.info(f"{'='*50}\n")
            print(f"\n📧 验证码已发送到 {to_email}: {code} (有效期5分钟)\n")
            return True, f"验证码已发送（开发模式：{code}）"
        
        # 生产模式：通过 SMTP 发送
        try:
            msg = self._create_verification_email(to_email, code)
            self._send_email_via_smtp(to_email, msg)
            logger.info(f"Verification code email sent to {to_email}")
            return True, "验证码已发送到您的邮箱"
        except smtplib.SMTPException as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False, f"邮件发送失败: {str(e)}"
        except Exception as e:
            logger.error(f"Unexpected error sending email to {to_email}: {e}")
            return False, f"邮件发送失败，请稍后重试"
    
    def _create_verification_email(self, to_email: str, code: str) -> MIMEMultipart:
        """
        创建验证码邮件内容
        
        Args:
            to_email: 收件人邮箱
            code: 验证码
            
        Returns:
            MIMEMultipart: 邮件对象
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"【{self.config.from_name}】登录验证码"
        msg["From"] = f"{self.config.from_name} <{self.config.from_email}>"
        msg["To"] = to_email
        
        # 纯文本内容
        text_content = f"""
您好！

您正在登录 {self.config.from_name}，您的验证码是：

{code}

验证码有效期为 5 分钟，请尽快使用。

如果这不是您的操作，请忽略此邮件。

---
{self.config.from_name}
"""
        
        # HTML 内容
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 40px 20px; }}
        .code-box {{ 
            background: linear-gradient(135deg, #ff6b00 0%, #ff8c00 100%);
            color: white; 
            font-size: 32px; 
            font-weight: bold; 
            letter-spacing: 8px;
            padding: 20px 40px; 
            border-radius: 12px; 
            text-align: center;
            margin: 30px 0;
        }}
        .footer {{ color: #666; font-size: 14px; margin-top: 40px; border-top: 1px solid #eee; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>您好！</h2>
        <p>您正在登录 <strong>{self.config.from_name}</strong>，您的验证码是：</p>
        <div class="code-box">{code}</div>
        <p>验证码有效期为 <strong>5 分钟</strong>，请尽快使用。</p>
        <p style="color: #888;">如果这不是您的操作，请忽略此邮件。</p>
        <div class="footer">
            <p>{self.config.from_name}</p>
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
        通过 SMTP 发送邮件
        
        Args:
            to_email: 收件人邮箱
            msg: 邮件对象
        """
        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
            if self.config.use_tls:
                server.starttls()
            server.login(self.config.smtp_user, self.config.smtp_password)
            server.sendmail(self.config.from_email, to_email, msg.as_string())


# 导入 Tuple 类型
from typing import Tuple

# 全局单例实例
email_service = EmailService()