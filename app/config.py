"""
Aegis 配置管理 (Python 3.6 兼容版)
================================
基于环境变量的配置管理，兼容Python 3.6环境。
"""

import os
from typing import List, Optional


class Settings:
    """应用设置类"""

    # 应用基础配置
    env: str = os.getenv("ENV", "development")
    debug: bool = os.getenv("DEBUG", "false").lower() == "true"
    api_port: int = int(os.getenv("API_PORT", "8000"))

    # 数据库配置
    mysql_host: str = os.getenv("MYSQL_HOST", "aegis-db")
    mysql_port: int = int(os.getenv("MYSQL_PORT", "3306"))
    mysql_database: str = os.getenv("MYSQL_DATABASE", "aegis")
    mysql_user: str = os.getenv("MYSQL_USER", "root")
    mysql_password: str = os.getenv("MYSQL_PASSWORD", "aegis_password")

    # Redis配置
    redis_host: str = os.getenv("REDIS_HOST", "aegis-redis")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))
    redis_password: Optional[str] = os.getenv("REDIS_PASSWORD")

    # Celery配置
    celery_broker_url: str = os.getenv("CELERY_BROKER_URL", f"redis://{redis_host}:{redis_port}/0")
    celery_result_backend: str = os.getenv("CELERY_RESULT_BACKEND", f"redis://{redis_host}:{redis_port}/1")
    celery_workers: int = int(os.getenv("CELERY_WORKERS", "2"))

    # 安全配置
    secret_key: str = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "your-jwt-secret-key-here")
    jwt_access_token_expire_minutes: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

    # 扫描引擎配置
    max_concurrent_requests: int = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    default_qps_limit: int = int(os.getenv("DEFAULT_QPS_LIMIT", "5"))
    request_timeout: int = int(os.getenv("REQUEST_TIMEOUT", "30"))
    max_retries: int = int(os.getenv("MAX_RETRIES", "3"))

    # Playwright配置
    playwright_timeout: int = int(os.getenv("PLAYWRIGHT_TIMEOUT", "30000"))
    playwright_headless: bool = os.getenv("PLAYWRIGHT_HEADLESS", "true").lower() == "true"

    # 日志配置
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    log_file_path: str = os.getenv("LOG_FILE_PATH", "logs/aegis.log")

    # 文件上传配置
    max_upload_size: int = int(os.getenv("MAX_UPLOAD_SIZE", "10485760"))  # 10MB
    allowed_extensions: List[str] = os.getenv("ALLOWED_EXTENSIONS", "yaml,yml,json").split(",")

    # CORS配置
    cors_origins: List[str] = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:8080").split(",")

    # 管理员配置
    admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
    admin_password: str = os.getenv("ADMIN_PASSWORD", "admin123")

    @property
    def database_url(self) -> str:
        """生成数据库URL"""
        return f"mysql+pymysql://{self.mysql_user}:{self.mysql_password}@{self.mysql_host}:{self.mysql_port}/{self.mysql_database}"

    @property
    def redis_url(self) -> str:
        """生成Redis URL"""
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}"
        return f"redis://{self.redis_host}:{self.redis_port}"


# 全局设置实例
settings = Settings()