from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# 数据库连接 URL，这里使用 MySQL
# 格式：mysql+mysqlconnector://user:password@host:port/database
# 实际项目中应从配置文件或环境变量中读取
SQLALCHEMY_DATABASE_URL = "mysql+mysqlconnector://user:password@localhost:3306/aegis_db"

# 创建 SQLAlchemy 引擎
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# 创建数据库会话类
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 声明式基类，用于定义 ORM 模型
Base = declarative_base()

def get_db():
    """
    获取数据库会话的依赖项。
    每次请求都会创建一个新的会话，并在请求完成后关闭。
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
