from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
import time
from typing import Generator

# 数据库连接配置
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "aegis_password")
DB_NAME = os.getenv("DB_NAME", "aegis")
DB_PORT = os.getenv("DB_PORT", "3306")

# 备选主机列表：优先尝试 Docker 服务名，其次尝试 localhost
DB_HOSTS = [os.getenv("DB_HOST", "aegis-db"), "localhost", "127.0.0.1"]

def get_engine_with_retry():
    """
    尝试多个主机地址创建数据库引擎，适配 Docker 和宿主机环境。
    """
    last_exception = None
    for host in DB_HOSTS:
        url = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{host}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
        try:
            # 尝试创建引擎
            temp_engine = create_engine(
                url, 
                pool_pre_ping=True, 
                pool_recycle=3600,
                connect_args={"connect_timeout": 2}
            )
            # 测试连接
            with temp_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print(f" Successfully connected to database at {host}")
            return temp_engine
        except Exception as e:
            print(f" Failed to connect to database at {host}: {e}")
            last_exception = e
            continue
    
    # 如果所有都失败，返回一个默认引擎（虽然它也会报错，但能保持对象存在）
    default_url = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOSTS[0]}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
    return create_engine(default_url)

# --- 核心对象定义与导出 ---
# 确保这些变量在模块层级被定义，以便其他模块导入
engine = get_engine_with_retry()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 导出 SQLALCHEMY_DATABASE_URL 供兼容性使用
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOSTS[0]}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

def get_db() -> Generator[Session, None, None]:
    """
    获取数据库会话的依赖项。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
