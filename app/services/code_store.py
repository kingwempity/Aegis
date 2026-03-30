"""
验证码存储服务

功能：
- 生成随机验证码
- 存储验证码（内存存储，支持过期时间）
- 验证验证码

Notes:
    - 使用内存字典存储，重启后丢失
    - 生产环境建议使用 Redis
    - 验证码默认有效期5分钟
"""

import random
import string
import time
from typing import Optional, Dict, Tuple
import logging

logger = logging.getLogger(__name__)


class VerificationCodeStore:
    """
    验证码存储类
    
    使用内存字典存储验证码，支持过期时间和发送频率限制。
    
    Attributes:
        _codes: 存储验证码的字典 {email: (code, expire_time)}
        _rate_limit: 存储发送时间的字典 {email: last_send_time}
        code_length: 验证码长度
        expire_seconds: 验证码有效期（秒）
        rate_limit_seconds: 发送频率限制（秒）
    """
    
    def __init__(self, code_length: int = 6, expire_seconds: int = 300, rate_limit_seconds: int = 60):
        """
        初始化验证码存储
        
        Args:
            code_length: 验证码长度，默认6位
            expire_seconds: 验证码有效期，默认300秒（5分钟）
            rate_limit_seconds: 发送频率限制，默认60秒
        """
        self._codes: Dict[str, Tuple[str, float]] = {}
        self._rate_limit: Dict[str, float] = {}
        self.code_length = code_length
        self.expire_seconds = expire_seconds
        self.rate_limit_seconds = rate_limit_seconds
    
    def generate_code(self) -> str:
        """
        生成随机验证码
        
        Returns:
            str: 指定长度的数字验证码
        """
        return ''.join(random.choices(string.digits, k=self.code_length))
    
    def store_code(self, email: str) -> Tuple[bool, str, Optional[int]]:
        """
        存储验证码
        
        Args:
            email: 用户邮箱
            
        Returns:
            Tuple[bool, str, Optional[int]]: 
                - 是否成功
                - 消息（成功时为验证码，失败时为错误信息）
                - 剩余等待时间（秒），仅在频率限制时返回
        """
        current_time = time.time()
        
        # 检查发送频率限制
        if email in self._rate_limit:
            last_send_time = self._rate_limit[email]
            elapsed = current_time - last_send_time
            if elapsed < self.rate_limit_seconds:
                remaining = int(self.rate_limit_seconds - elapsed)
                logger.warning(f"Rate limit hit for {email}, remaining: {remaining}s")
                return False, f"发送过于频繁，请等待 {remaining} 秒后再试", remaining
        
        # 生成并存储验证码
        code = self.generate_code()
        expire_time = current_time + self.expire_seconds
        self._codes[email] = (code, expire_time)
        self._rate_limit[email] = current_time
        
        logger.info(f"Verification code generated for {email}, expires in {self.expire_seconds}s")
        return True, code, None
    
    def verify_code(self, email: str, code: str) -> Tuple[bool, str]:
        """
        验证验证码
        
        Args:
            email: 用户邮箱
            code: 用户输入的验证码
            
        Returns:
            Tuple[bool, str]: (是否验证成功, 消息)
        """
        current_time = time.time()
        
        # 检查验证码是否存在
        if email not in self._codes:
            logger.warning(f"No verification code found for {email}")
            return False, "验证码不存在或已过期，请重新获取"
        
        stored_code, expire_time = self._codes[email]
        
        # 检查是否过期
        if current_time > expire_time:
            del self._codes[email]
            logger.warning(f"Verification code expired for {email}")
            return False, "验证码已过期，请重新获取"
        
        # 验证码匹配
        if stored_code != code:
            logger.warning(f"Invalid verification code for {email}")
            return False, "验证码错误"
        
        # 验证成功，删除验证码
        del self._codes[email]
        logger.info(f"Verification successful for {email}")
        return True, "验证成功"
    
    def cleanup_expired(self) -> int:
        """
        清理过期的验证码
        
        Returns:
            int: 清理的验证码数量
        """
        current_time = time.time()
        expired_emails = [
            email for email, (_, expire_time) in self._codes.items()
            if current_time > expire_time
        ]
        
        for email in expired_emails:
            del self._codes[email]
            self._rate_limit.pop(email, None)
        
        if expired_emails:
            logger.info(f"Cleaned up {len(expired_emails)} expired verification codes")
        
        return len(expired_emails)


# 全局单例实例
code_store = VerificationCodeStore()