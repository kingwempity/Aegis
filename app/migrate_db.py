"""
数据库迁移脚本：为 vulnerabilities 表添加新字段

运行方式：
    python -m app.migrate_db
"""

import sqlite3
import os
import sys

# 数据库路径
DB_PATH = os.environ.get("DATABASE_URL", "data/aegis.db")

# 如果是 MySQL 连接字符串，提取数据库信息
if DB_PATH.startswith("mysql"):
    # 使用 SQLAlchemy 进行迁移
    from sqlalchemy import create_engine, text
    from app.database import DATABASE_URL
    
    def migrate_mysql():
        """MySQL 数据库迁移"""
        engine = create_engine(DATABASE_URL)
        
        migrations = [
            "ALTER TABLE vulnerabilities ADD COLUMN attack_path JSON",
            "ALTER TABLE vulnerabilities ADD COLUMN vuln_type VARCHAR(50)",
            "ALTER TABLE vulnerabilities ADD COLUMN parameter VARCHAR(100)",
            "ALTER TABLE vulnerabilities ADD COLUMN method VARCHAR(10)",
            "ALTER TABLE vulnerabilities ADD COLUMN description TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvss_score INT",
            "ALTER TABLE vulnerabilities ADD COLUMN detected_at DATETIME",
        ]
        
        with engine.connect() as conn:
            for sql in migrations:
                try:
                    conn.execute(text(sql))
                    conn.commit()
                    print(f"✅ 执行成功: {sql[:50]}...")
                except Exception as e:
                    if "Duplicate column" in str(e) or "already exists" in str(e):
                        print(f"⏭️ 列已存在，跳过: {sql[:50]}...")
                    else:
                        print(f"⚠️ 执行失败: {sql[:50]}... - {e}")
        
        print("✅ MySQL 数据库迁移完成")
    
    if __name__ == "__main__":
        migrate_mysql()

else:
    # SQLite 数据库迁移
    def migrate_sqlite():
        """SQLite 数据库迁移"""
        # 确保数据目录存在
        os.makedirs(os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else ".", exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 要添加的新列
        new_columns = [
            ("attack_path", "TEXT"),  # SQLite 用 TEXT 存储 JSON
            ("vuln_type", "VARCHAR(50)"),
            ("parameter", "VARCHAR(100)"),
            ("method", "VARCHAR(10)"),
            ("description", "TEXT"),
            ("remediation", "TEXT"),
            ("cvss_score", "INTEGER"),
            ("detected_at", "DATETIME"),
        ]
        
        # 获取现有列
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        # 添加缺失的列
        for col_name, col_type in new_columns:
            if col_name not in existing_columns:
                try:
                    sql = f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_type}"
                    cursor.execute(sql)
                    conn.commit()
                    print(f"✅ 添加列: {col_name}")
                except sqlite3.OperationalError as e:
                    if "duplicate column name" in str(e).lower():
                        print(f"⏭️ 列已存在: {col_name}")
                    else:
                        print(f"⚠️ 添加列失败 {col_name}: {e}")
            else:
                print(f"⏭️ 列已存在: {col_name}")
        
        conn.close()
        print("✅ SQLite 数据库迁移完成")
    
    if __name__ == "__main__":
        migrate_sqlite()