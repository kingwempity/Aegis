"""
Aegis 数据库连接配置重定向
--------------------------
为了保持项目结构一致性，所有数据库配置已迁移至 app/db/database.py。
此文件仅作为兼容性导入保留。
"""
from app.db.database import engine, SessionLocal, Base, get_db, SQLALCHEMY_DATABASE_URL

# 导出所有必要的组件
__all__ = ["engine", "SessionLocal", "Base", "get_db", "SQLALCHEMY_DATABASE_URL"]
