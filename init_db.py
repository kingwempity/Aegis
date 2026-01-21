#!/usr/bin/env python3
"""
Aegis 数据库初始化脚本
----------------------
负责创建数据库、表结构和初始化数据。
支持开发环境和生产环境的数据库初始化。
"""
import sys
import os
from pathlib import Path

# 将项目根目录添加到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """主初始化函数"""
    print("开始初始化 Aegis 数据库...")

    try:
        # 导入数据库模块
        from app.database import (
            create_database_if_not_exists,
            create_tables,
            test_connection,
            engine
        )
        from app.models.task import ScanTask, Vulnerability, ReportTask, ScanLog

        # 步骤1: 测试基础连接
        print("\n 测试数据库连接...")
        if not test_connection():
            print("数据库连接失败，请检查配置")
            sys.exit(1)

        # 步骤2: 创建数据库（如果不存在）
        print("\n 创建数据库...")
        create_database_if_not_exists()

        # 步骤3: 重新测试连接（确保数据库存在）
        print("\n重新连接数据库...")
        if not test_connection():
            print("数据库连接失败")
            sys.exit(1)

        # 步骤4: 创建表结构
        print("\n创建表结构...")
        create_tables()

        # 步骤5: 验证表创建
        print("\n验证表创建...")
        tables_to_check = [
            'scan_tasks',
            'vulnerabilities',
            'report_tasks',
            'scan_logs'
        ]

        with engine.connect() as conn:
            for table in tables_to_check:
                try:
                    result = conn.execute(f"SHOW TABLES LIKE '{table}'")
                    if result.fetchone():
                        print(f"  ✓ 表 '{table}' 创建成功")
                    else:
                        print(f"   表 '{table}' 创建失败")
                        sys.exit(1)
                except Exception as e:
                    print(f"  验证表 '{table}' 时出错: {e}")
                    sys.exit(1)

        print("\n Aegis 数据库初始化完成！")
        print("已创建的表:")
        print("  - scan_tasks: 扫描任务表")
        print("  - vulnerabilities: 漏洞结果表")
        print("  - report_tasks: 报告生成任务表")
        print("  - scan_logs: 扫描日志表")

    except ImportError as e:
        print(f"导入模块失败: {e}")
        print(f"请确保在项目根目录运行此脚本")
        print(f"当前工作目录: {os.getcwd()}")
        print(f"Python路径: {sys.path}")
        sys.exit(1)

    except Exception as e:
        print(f"数据库初始化失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
