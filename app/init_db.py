"""
Aegis 数据库初始化脚本
----------------------
根据模型定义在 MySQL 中自动创建所有数据表。
"""
import sys
import os

# 将当前目录加入路径，确保能导入 app 模块
sys.path.append(os.getcwd())

from app.database import engine, Base
from app.models.task import ScanTask, Vulnerability

def init_db():
    print("🚀 开始初始化 Aegis 数据库表...")
    try:
        # 创建所有定义的表
        Base.metadata.create_all(bind=engine)
        print("✅ 数据库表创建成功！")
    except Exception as e:
        print(f"❌ 数据库初始化失败: {e}")

if __name__ == "__main__":
    init_db()
