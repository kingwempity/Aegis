#!/usr/bin/env python3
"""
Python 3.6兼容性测试脚本
=======================
验证当前代码是否与Python 3.6兼容
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_python36_compatibility():
    """测试Python 3.6兼容性"""
    print(f"🐍 Python版本: {sys.version}")
    print(f"📁 当前目录: {os.getcwd()}")

    try:
        print("\n📦 测试模块导入...")

        # 测试SQLAlchemy
        import sqlalchemy
        print(f"✓ SQLAlchemy {sqlalchemy.__version__}")

        # 测试Pydantic v1.x
        import pydantic
        print(f"✓ Pydantic {pydantic.VERSION}")

        # 测试FastAPI
        import fastapi
        print(f"✓ FastAPI {fastapi.__version__}")

        # 测试其他关键模块
        import httpx
        print(f"✓ httpx {httpx.__version__}")

        import yaml
        print("✓ PyYAML")

        import pymysql
        print("✓ PyMySQL")

        print("\n🔧 测试应用模块导入...")

        # 测试数据库模块
        from app.database import engine, SessionLocal, get_db
        print("✓ 数据库模块")

        # 测试模型模块
        from app.models.task import ScanTask, Vulnerability, ReportTask, ScanLog
        print("✓ 数据模型")

        # 测试Schema模块
        from app.schemas.task import ScanTaskCreate, ScanTaskResponse
        print("✓ Pydantic Schemas")

        # 测试主应用
        from app.main import app
        print("✓ FastAPI应用")

        print("\n✅ Python 3.6兼容性测试通过！")
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
    success = test_python36_compatibility()
    sys.exit(0 if success else 1)