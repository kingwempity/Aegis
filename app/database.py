"""
Aegis 数据库连接配置
--------------------
管理 SQLAlchemy 引擎和会话。
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# 从环境变量获取连接字符串，默认为 Docker 内部地址
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "mysql+pymysql://root:aegis_password@aegis-db/aegis"
)

# 创建引擎
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,  # 自动检查连接有效性
    pool_recycle=3600    # 每小时回收连接，防止 MySQL 超时断开
)

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 供模型继承的基类
Base = declarative_base()

def get_db():
    """获取数据库会话的依赖项"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
