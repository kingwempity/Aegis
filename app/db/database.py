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

def create_engine_with_retry():
    """
    尝试多个主机地址创建数据库引擎，适配 Docker 和宿主机环境。
    """
    last_exception = None
    for host in DB_HOSTS:
        url = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{host}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
        try:
            # 尝试连接（设置较短的超时时间用于快速切换）
            engine = create_engine(
                url, 
                pool_pre_ping=True, 
                pool_recycle=3600,
                connect_args={"connect_timeout": 2}
            )
            # 测试连接是否真的可用
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print(f"✓ Successfully connected to database at {host}")
            return engine
        except Exception as e:
            print(f"⚠ Failed to connect to database at {host}: {e}")
            last_exception = e
            continue
    
    raise last_exception

try:
    engine = create_engine_with_retry()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = declarative_base()
except Exception as e:
    print(f"Critical Error: Could not initialize database engine: {e}")
    # 提供一个空的 Base 以防止导入错误，但后续数据库操作会失败
    Base = declarative_base()
    SessionLocal = None

def get_db() -> Generator[Session, None, None]:
    """
    获取数据库会话的依赖项。
    """
    if SessionLocal is None:
        raise Exception("Database session factory is not initialized. Check connection settings.")
    
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
