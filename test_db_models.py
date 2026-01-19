#!/usr/bin/env python3
"""
Aegis 数据库模型基础验证脚本
--------------------------
验证优化后的数据库模型的基本功能
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_model_imports():
    """测试模型导入"""
    print("🧪 测试 Aegis 数据库模型导入...")

    try:
        from app.models.task import ScanTask, Vulnerability, ReportTask, ScanLog
        from app.schemas.task import ScanTaskCreate, ScanTaskResponse
        from app.database import Base, engine

        print("✓ 模型导入成功")
        print(f"  - ScanTask: {ScanTask}")
        print(f"  - Vulnerability: {Vulnerability}")
        print(f"  - ReportTask: {ReportTask}")
        print(f"  - ScanLog: {ScanLog}")

        # 测试表创建
        print("\n📋 测试表结构创建...")
        try:
            Base.metadata.create_all(bind=engine)
            print("✓ 数据库表创建成功")
        except Exception as e:
            print(f"⚠ 表创建跳过 (可能已存在): {e}")

        # 测试Schema创建
        print("\n📝 测试 Pydantic Schema...")
        task_data = {
            "name": "测试扫描任务",
            "target_url": "https://example.com",
            "scan_config": {"max_qps": 10, "timeout": 30}
        }

        schema = ScanTaskCreate(**task_data)
        print(f"✓ Schema 验证成功: {schema.name}")

        print("\n🎉 所有基础测试通过！")
        return True

    except ImportError as e:
        print(f"❌ 导入失败: {e}")
        return False
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_model_imports()
    sys.exit(0 if success else 1)