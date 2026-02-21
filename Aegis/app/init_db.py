"""
init_db.py
----------
数据库初始化脚本。负责创建所有定义的 SQLAlchemy 模型表。

Usage:
    python init_db.py
"""
import sys
import os
import logging

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 关键步骤：将当前目录添加到 sys.path，解决 'ModuleNotFoundError: No module named app'
sys.path.append(os.getcwd())

try:
    from app.database import engine, Base
    # 必须显式导入模型，否则 Base.metadata 无法识别它们
    from app.models.task import ScanTask, Vulnerability
except ImportError as e:
    logger.error(f"导入模块失败，请检查目录结构或 __init__.py 文件: {e}")
    sys.exit(1)

def init_db():
    """
    执行数据库表创建操作。
    """
    logger.info(f"正在连接数据库: {engine.url}")
    try:
        # create_all 会检查表是否存在，不存在则创建
        Base.metadata.create_all(bind=engine)
        logger.info("数据库表初始化成功！(Tables created: scan_tasks, vulnerabilities)")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        # 如果是连接拒绝，通常是 Docker 网络问题或 MySQL 尚未完全启动
        if "Connection refused" in str(e):
            logger.error("提示: 请检查 MySQL 容器是否正在运行，且端口 3306 可访问。")

if __name__ == "__main__":
    init_db()