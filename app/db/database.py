from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# 数据库连接配置
# 优先从环境变量读取，否则使用默认值
# 格式：mysql+pymysql://user:password@host:port/database
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root123456") # 请替换为您的实际密码
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "3306")
DB_NAME = os.getenv("DB_NAME", "aegis")

SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}?charset=utf8mb4"

try:
    # 创建 SQLAlchemy 引擎
    # pool_pre_ping=True 用于自动重连
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

def get_db():
    """
    获取数据库会话的依赖项。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
