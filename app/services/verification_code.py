"""
验证码服务模块

功能：
- 生成6位数字验证码
- 验证码存储（Redis）
- 验证码校验
- 防暴力破解（尝试次数限制）

Notes:
    - 验证码有效期：5分钟
    - 最大尝试次数：5次
    - 发送频率限制：60秒内只能发送一次
    - 存储使用Redis，支持分布式部署
"""

import os
import random
import string
import time
import logging
from typing import Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# 尝试导入 Redis，如果失败则使用内存存储
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VerificationCodeConfig:
    """
    验证码配置类
    
    Attributes:
        code_length: 验证码长度
        expire_seconds: 过期时间（秒）
        max_attempts: 最大尝试次数
        resend_interval: 重发间隔（秒）
    """
    code_length: int = 6
    expire_seconds: int = 300  # 5分钟
    max_attempts: int = 5
    resend_interval: int = 60  # 60秒


class VerificationCodeStorage:
    """
    验证码存储基类
    
    定义验证码存储的接口规范。
    """
    
    def store(self, key: str, code: str, config: VerificationCodeConfig) -> bool:
        """存储验证码"""
        raise NotImplementedError
    
    def verify(self, key: str, code: str, config: VerificationCodeConfig) -> Tuple[bool, str]:
        """验证验证码"""
        raise NotImplementedError
    
    def can_resend(self, key: str, config: VerificationCodeConfig) -> Tuple[bool, int]:
        """检查是否可以重新发送"""
        raise NotImplementedError
    
    def delete(self, key: str) -> bool:
        """删除验证码"""
        raise NotImplementedError


class RedisStorage(VerificationCodeStorage):
    """
    Redis 存储实现
    
    使用 Redis 存储验证码，支持分布式部署。
    
    存储结构：
    - verification_code:{email} -> {code}:{attempts}:{created_at}
    """
    
    def __init__(self, redis_url: str):
        """
        初始化 Redis 存储
        
        Args:
            redis_url: Redis 连接URL
            
        Raises:
            ConnectionError: 当 Redis 无法连接时抛出
        """
        self.client = redis.from_url(redis_url, decode_responses=True)
        self._connected = False
        if not self._ping():
            raise ConnectionError(f"Cannot connect to Redis at {redis_url}")
        
    def _ping(self) -> bool:
        """
        检测 Redis 连接是否可用
        
        Returns:
            bool: 连接是否可用
        """
        try:
            self.client.ping()
            self._connected = True
            logger.info("Verification code storage: Redis mode (connected)")
            return True
        except Exception as e:
            self._connected = False
            logger.warning(f"Redis connection failed: {e}")
            return False
    
    def store(self, key: str, code: str, config: VerificationCodeConfig) -> bool:
        """
        存储验证码到 Redis
        
        Args:
            key: 存储键（通常是邮箱）
            code: 验证码
            config: 配置
            
        Returns:
            bool: 是否成功
        """
        redis_key = f"verification_code:{key}"
        # 格式：code:attempts:created_at
        value = f"{code}:0:{int(time.time())}"
        
        try:
            self.client.setex(redis_key, config.expire_seconds, value)
            logger.debug(f"Verification code stored for {key}")
            return True
        except Exception as e:
            logger.error(f"Failed to store verification code: {e}")
            return False
    
    def verify(self, key: str, code: str, config: VerificationCodeConfig) -> Tuple[bool, str]:
        """
        验证验证码
        
        Args:
            key: 存储键（通常是邮箱）
            code: 用户输入的验证码
            config: 配置
            
        Returns:
            Tuple[bool, str]: (是否验证成功, 消息)
        """
        redis_key = f"verification_code:{key}"
        
        try:
            value = self.client.get(redis_key)
            
            if not value:
                return False, "验证码已过期或不存在，请重新获取"
            
            parts = value.split(":")
            stored_code = parts[0]
            attempts = int(parts[1]) if len(parts) > 1 else 0
            
            # 检查尝试次数
            if attempts >= config.max_attempts:
                self.client.delete(redis_key)
                return False, "验证码尝试次数过多，请重新获取"
            
            # 验证码匹配
            if code == stored_code:
                self.client.delete(redis_key)
                return True, "验证成功"
            
            # 增加尝试次数
            new_value = f"{stored_code}:{attempts + 1}:{parts[2] if len(parts) > 2 else int(time.time())}"
            self.client.set(redis_key, new_value)
            
            remaining = config.max_attempts - attempts - 1
            return False, f"验证码错误，还剩 {remaining} 次尝试机会"
            
        except Exception as e:
            logger.error(f"Failed to verify code: {e}")
            return False, "验证失败，请稍后重试"
    
    def can_resend(self, key: str, config: VerificationCodeConfig) -> Tuple[bool, int]:
        """
        检查是否可以重新发送验证码
        
        Args:
            key: 存储键（通常是邮箱）
            config: 配置
            
        Returns:
            Tuple[bool, int]: (是否可以重发, 剩余等待秒数)
        """
        redis_key = f"verification_code:{key}"
        
        try:
            value = self.client.get(redis_key)
            
            if not value:
                return True, 0
            
            parts = value.split(":")
            created_at = int(parts[2]) if len(parts) > 2 else 0
            
            elapsed = int(time.time()) - created_at
            if elapsed >= config.resend_interval:
                return True, 0
            
            remaining = config.resend_interval - elapsed
            return False, remaining
            
        except Exception as e:
            logger.error(f"Failed to check resend status: {e}")
            return True, 0
    
    def delete(self, key: str) -> bool:
        """
        删除验证码
        
        Args:
            key: 存储键
            
        Returns:
            bool: 是否成功
        """
        redis_key = f"verification_code:{key}"
        try:
            self.client.delete(redis_key)
            return True
        except Exception as e:
            logger.error(f"Failed to delete verification code: {e}")
            return False


class MemoryStorage(VerificationCodeStorage):
    """
    内存存储实现
    
    用于开发环境或不具备 Redis 的场景。
    注意：单机模式，不支持分布式部署。
    """
    
    def __init__(self):
        """初始化内存存储"""
        self._store: dict = {}
        logger.warning("Verification code storage: Memory mode (not recommended for production)")
    
    def store(self, key: str, code: str, config: VerificationCodeConfig) -> bool:
        """存储验证码到内存"""
        self._store[key] = {
            "code": code,
            "attempts": 0,
            "created_at": time.time(),
            "expires_at": time.time() + config.expire_seconds
        }
        return True
    
    def verify(self, key: str, code: str, config: VerificationCodeConfig) -> Tuple[bool, str]:
        """验证验证码"""
        # 清理过期数据
        self._cleanup()
        
        if key not in self._store:
            return False, "验证码已过期或不存在，请重新获取"
        
        data = self._store[key]
        
        # 检查过期
        if time.time() > data["expires_at"]:
            del self._store[key]
            return False, "验证码已过期，请重新获取"
        
        # 检查尝试次数
        if data["attempts"] >= config.max_attempts:
            del self._store[key]
            return False, "验证码尝试次数过多，请重新获取"
        
        # 验证码匹配
        if code == data["code"]:
            del self._store[key]
            return True, "验证成功"
        
        # 增加尝试次数
        data["attempts"] += 1
        remaining = config.max_attempts - data["attempts"]
        return False, f"验证码错误，还剩 {remaining} 次尝试机会"
    
    def can_resend(self, key: str, config: VerificationCodeConfig) -> Tuple[bool, int]:
        """检查是否可以重新发送"""
        self._cleanup()
        
        if key not in self._store:
            return True, 0
        
        data = self._store[key]
        elapsed = int(time.time() - data["created_at"])
        
        if elapsed >= config.resend_interval:
            return True, 0
        
        remaining = config.resend_interval - elapsed
        return False, remaining
    
    def delete(self, key: str) -> bool:
        """删除验证码"""
        if key in self._store:
            del self._store[key]
        return True
    
    def _cleanup(self):
        """清理过期的验证码"""
        now = time.time()
        expired_keys = [k for k, v in self._store.items() if v["expires_at"] < now]
        for k in expired_keys:
            del self._store[k]


class VerificationCodeService:
    """
    验证码服务
    
    提供验证码生成、存储、验证的完整功能。
    
    Attributes:
        config: 验证码配置
        storage: 存储后端
    """
    
    def __init__(
        self, 
        config: Optional[VerificationCodeConfig] = None,
        redis_url: Optional[str] = None
    ):
        """
        初始化验证码服务
        
        Args:
            config: 验证码配置，默认使用标准配置
            redis_url: Redis 连接URL，如果不提供则使用内存存储
        """
        self.config = config or VerificationCodeConfig()
        
        # 选择存储后端
        if redis_url and REDIS_AVAILABLE:
            try:
                self.storage = RedisStorage(redis_url)
            except Exception as e:
                logger.warning(f"Failed to connect to Redis, falling back to memory: {e}")
                self.storage = MemoryStorage()
        else:
            self.storage = MemoryStorage()
    
    def generate_code(self) -> str:
        """
        生成随机验证码
        
        Returns:
            str: 指定长度的数字验证码
        """
        return ''.join(random.choices(string.digits, k=self.config.code_length))
    
    def send_code(self, email: str) -> Tuple[bool, str]:
        """
        发送验证码
        
        Args:
            email: 目标邮箱
            
        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        # 检查是否可以重发
        can_send, wait_seconds = self.storage.can_resend(email, self.config)
        if not can_send:
            return False, f"请等待 {wait_seconds} 秒后再试"
        
        # 生成验证码
        code = self.generate_code()
        
        # 存储验证码
        if not self.storage.store(email, code, self.config):
            return False, "验证码存储失败，请稍后重试"
        
        # 发送验证码（调用邮件服务）
        from app.services.email_service import email_service
        
        success, message = email_service.send_verification_code(email, code)
        
        if success:
            return True, "验证码已发送到您的邮箱，请查收"
        else:
            # 发送失败，清理存储
            self.storage.delete(email)
            return False, message
    
    def verify_code(self, email: str, code: str) -> Tuple[bool, str]:
        """
        验证验证码
        
        Args:
            email: 邮箱
            code: 用户输入的验证码
            
        Returns:
            Tuple[bool, str]: (是否验证成功, 消息)
        """
        if not code or len(code) != self.config.code_length:
            return False, f"请输入 {self.config.code_length} 位验证码"
        
        return self.storage.verify(email, code, self.config)
    
    def invalidate_code(self, email: str) -> bool:
        """
        使验证码失效
        
        Args:
            email: 邮箱
            
        Returns:
            bool: 是否成功
        """
        return self.storage.delete(email)


# 全局单例实例
_verification_code_service: Optional[VerificationCodeService] = None


def get_verification_code_service() -> VerificationCodeService:
    """
    获取验证码服务单例
    
    Returns:
        VerificationCodeService: 验证码服务实例
    """
    global _verification_code_service
    
    if _verification_code_service is None:
        try:
            redis_url = os.getenv("REDIS_URL")
            _verification_code_service = VerificationCodeService(redis_url=redis_url)
        except Exception as e:
            # 确保任何异常都被捕获，降级到内存存储
            logger.error(f"Failed to initialize verification code service: {e}")
            _verification_code_service = VerificationCodeService(redis_url=None)
    
    return _verification_code_service
