"""
Aegis 数据库连接配置
--------------------
管理 SQLAlchemy 引擎、会话和数据库初始化。
支持环境变量配置和连接池优化。
"""
import os
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import QueuePool

# 从环境变量获取数据库配置
DB_HOST = os.getenv("DB_HOST", "aegis-db")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "aegis")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "aegis_password")

# 完整的数据库URL
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

# 创建优化的引擎配置
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    # 连接池配置
    poolclass=QueuePool,
    pool_size=10,          # 连接池大小
    max_overflow=20,       # 最大溢出连接数
    pool_timeout=30,       # 获取连接超时时间
    pool_recycle=3600,     # 连接回收时间（1小时）
    pool_pre_ping=True,    # 自动检查连接有效性

    # 其他配置
    echo=False,            # 生产环境关闭SQL日志
    future=True,           # 使用SQLAlchemy 2.0风格
)

# 创建会话工厂
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False  # 防止会话过期问题
)

# 供模型继承的基类
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    获取数据库会话的依赖项

    Yields:
        Session: 数据库会话对象
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_database_if_not_exists():
    """
    如果数据库不存在则创建数据库

    注意：需要使用root权限连接MySQL
    """
    # 连接到MySQL服务器（不指定数据库）
    root_url = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}"
    root_engine = create_engine(root_url, pool_pre_ping=True)

    try:
        with root_engine.connect() as conn:
            # 创建数据库（如果不存在）
            conn.execute(text(f"CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"))
            conn.commit()
        print(f"✓ 数据库 '{DB_NAME}' 创建成功")
    except Exception as e:
        print(f"⚠ 数据库创建失败: {e}")
    finally:
        root_engine.dispose()


def create_tables():
    """
    创建所有数据库表
    """
    try:
        Base.metadata.create_all(bind=engine)
        print("✓ 数据库表创建成功")
    except Exception as e:
        print(f"✗ 数据库表创建失败: {e}")
        raise


def drop_tables():
    """
    删除所有数据库表（开发环境使用）
    """
    try:
        Base.metadata.drop_all(bind=engine)
        print("✓ 数据库表删除成功")
    except Exception as e:
        print(f"✗ 数据库表删除失败: {e}")
        raise


def test_connection() -> bool:
    """
    测试数据库连接

    Returns:
        bool: 连接是否成功
    """
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1 as test"))
            row = result.fetchone()
            if row and row[0] == 1:
                print("✓ 数据库连接测试成功")
                return True
    except Exception as e:
        print(f"✗ 数据库连接测试失败: {e}")
        return False

    return False
