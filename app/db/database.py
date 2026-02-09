from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os
from typing import Generator

# 数据库连接配置
# 优先从环境变量读取，适配 Docker 环境
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "aegis_password") # 默认匹配 docker-compose.yml
DB_HOST = os.getenv("DB_HOST", "aegis-db") # 默认匹配 docker-compose.yml 中的服务名
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "aegis")

# 完整的数据库URL
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"
)

try:
    # 创建 SQLAlchemy 引擎
    # pool_pre_ping=True 用于自动重连，适配数据库启动延迟
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=3600,
        echo=False
    )

    # 创建数据库会话类
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # 声明式基类
    Base = declarative_base()
except Exception as e:
    print(f"Error initializing database engine: {e}")
    raise

def get_db() -> Generator[Session, None, None]:
    """
    获取数据库会话的依赖项。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
