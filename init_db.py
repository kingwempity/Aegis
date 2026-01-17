import sys
import os

# 核心：将当前目录（/app）加入搜索路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

try:
    from app.database import engine, Base
    from app.models.task import ScanTask, Vulnerability
    
    def init_db():
        print("开始初始化 Aegis 数据库表...")
        Base.metadata.create_all(bind=engine)
        print("数据库表创建成功！")

    if __name__ == "__main__":
        init_db()
except ImportError as e:
    print(f"导入失败: {e}")
    print(f"当前搜索路径: {sys.path}")
