"""
init_db.py
----------
数据库初始化脚本。负责创建所有定义的 SQLAlchemy 模型表，并迁移新字段。

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
    from sqlalchemy import text, inspect
    # 必须显式导入模型，否则 Base.metadata 无法识别它们
    from app.models.task import ScanTask, Vulnerability
except ImportError as e:
    logger.error(f"导入模块失败，请检查目录结构或 __init__.py 文件: {e}")
    sys.exit(1)


def migrate_vulnerabilities_table():
    """
    为 vulnerabilities 表添加新字段（如果不存在）。
    
    支持增量迁移，不会影响现有数据。
    """
    # 新字段定义：(列名, 列类型SQL)
    new_columns = [
        ("attack_path", "JSON"),
        ("vuln_type", "VARCHAR(50)"),
        ("parameter", "VARCHAR(100)"),
        ("method", "VARCHAR(10)"),
        ("description", "TEXT"),
        ("remediation", "TEXT"),
        ("cvss_score", "INT"),
        ("detected_at", "DATETIME"),
    ]
    
    try:
        inspector = inspect(engine)
        
        # 检查表是否存在
        if 'vulnerabilities' not in inspector.get_table_names():
            logger.info("vulnerabilities 表不存在，将由 create_all 创建")
            return
        
        # 获取现有列
        existing_columns = {col['name'] for col in inspector.get_columns('vulnerabilities')}
        
        # 添加缺失的列
        with engine.connect() as conn:
            for col_name, col_type in new_columns:
                if col_name not in existing_columns:
                    try:
                        # 根据数据库类型调整 SQL
                        dialect = engine.dialect.name
                        
                        if dialect == 'sqlite':
                            # SQLite 不支持 JSON，使用 TEXT
                            if col_type == 'JSON':
                                col_type = 'TEXT'
                            sql = f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"
                        else:
                            # MySQL
                            sql = f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"
                        
                        conn.execute(text(sql))
                        conn.commit()
                        logger.info(f"✅ 添加新列: {col_name}")
                    except Exception as e:
                        if "duplicate column" in str(e).lower() or "already exists" in str(e).lower():
                            logger.info(f"⏭️ 列已存在: {col_name}")
                        else:
                            logger.warning(f"⚠️ 添加列失败 {col_name}: {e}")
                else:
                    logger.debug(f"⏭️ 列已存在: {col_name}")
        
        logger.info("数据库字段迁移完成")
        
    except Exception as e:
        logger.warning(f"数据库迁移检查失败（可能是新数据库）: {e}")


def init_db():
    """
    执行数据库表创建操作，并迁移新字段。
    """
    logger.info(f"正在连接数据库: {engine.url}")
    try:
        # create_all 会检查表是否存在，不存在则创建
        Base.metadata.create_all(bind=engine)
        logger.info("数据库表初始化成功！(Tables created: scan_tasks, vulnerabilities)")
        
        # 执行增量迁移
        migrate_vulnerabilities_table()
        
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        # 如果是连接拒绝，通常是 Docker 网络问题或 MySQL 尚未完全启动
        if "Connection refused" in str(e):
            logger.error("提示: 请检查 MySQL 容器是否正在运行，且端口 3306 可访问。")


if __name__ == "__main__":
    init_db()