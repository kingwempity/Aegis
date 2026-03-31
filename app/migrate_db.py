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
    from app.database import SQLALCHEMY_DATABASE_URL
    
    def migrate_mysql():
        """MySQL 数据库迁移"""
        engine = create_engine(SQLALCHEMY_DATABASE_URL)
        
        migrations = [
            "ALTER TABLE vulnerabilities ADD COLUMN attack_path JSON",
            "ALTER TABLE vulnerabilities ADD COLUMN vuln_type VARCHAR(50)",
            "ALTER TABLE vulnerabilities ADD COLUMN parameter VARCHAR(100)",
            "ALTER TABLE vulnerabilities ADD COLUMN method VARCHAR(10)",
            "ALTER TABLE vulnerabilities ADD COLUMN description TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT",
            "ALTER TABLE vulnerabilities ADD COLUMN cvss_score INT",
            "ALTER TABLE vulnerabilities ADD COLUMN detected_at DATETIME",
            "ALTER TABLE scan_tasks ADD COLUMN display_id INT NULL",
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

            # 回填连续 display_id
            task_ids = conn.execute(text("SELECT id FROM scan_tasks ORDER BY created_at ASC, id ASC")).fetchall()
            for index, row in enumerate(task_ids, start=1):
                conn.execute(
                    text("UPDATE scan_tasks SET display_id = :display_id WHERE id = :task_id"),
                    {"display_id": index, "task_id": row[0]},
                )
            conn.commit()

            # 创建唯一索引
            try:
                conn.execute(text("CREATE UNIQUE INDEX idx_scan_tasks_display_id_unique ON scan_tasks(display_id)"))
                conn.commit()
                print("✅ display_id 唯一索引创建完成")
            except Exception as e:
                if "Duplicate key name" in str(e) or "already exists" in str(e):
                    print("⏭️ display_id 唯一索引已存在")
                else:
                    print(f"⚠️ display_id 唯一索引创建失败: {e}")
        
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
            ("display_id", "INTEGER"),
        ]
        
        # 获取现有列
        cursor.execute("PRAGMA table_info(vulnerabilities)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        
        # 添加缺失的列
        for col_name, col_type in new_columns:
            target_table = "scan_tasks" if col_name == "display_id" else "vulnerabilities"
            cursor.execute(f"PRAGMA table_info({target_table})")
            target_existing_columns = {row[1] for row in cursor.fetchall()}
            if col_name not in target_existing_columns:
                try:
                    sql = f"ALTER TABLE {target_table} ADD COLUMN {col_name} {col_type}"
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

        # 回填连续 display_id
        cursor.execute("SELECT id FROM scan_tasks ORDER BY created_at ASC, id ASC")
        rows = cursor.fetchall()
        for index, (task_id,) in enumerate(rows, start=1):
            cursor.execute("UPDATE scan_tasks SET display_id = ? WHERE id = ?", (index, task_id))
        conn.commit()

        # 创建唯一索引
        try:
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_tasks_display_id_unique ON scan_tasks(display_id)")
            conn.commit()
            print("✅ display_id 唯一索引创建完成")
        except sqlite3.OperationalError as e:
            print(f"⚠️ display_id 唯一索引创建失败: {e}")
        
        conn.close()
        print("✅ SQLite 数据库迁移完成")
    
    if __name__ == "__main__":
        migrate_sqlite()
