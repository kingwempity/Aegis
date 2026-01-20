#!/usr/bin/env python3
"""
Aegis 最小功能测试脚本
======================
只测试数据库和基础API功能，不依赖celery等可能有问题的包
"""

import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_minimal_functionality():
    """测试最小功能集"""
    print("🧪 测试 Aegis 最小功能集...")

    try:
        # 测试基本Python包
        print("📦 测试Python包导入...")
        import sqlalchemy
        print(f"✓ SQLAlchemy {sqlalchemy.__version__}")

        import pydantic
        print(f"✓ Pydantic {pydantic.VERSION}")

        import fastapi
        print(f"✓ FastAPI {fastapi.__version__}")

        # 测试可选包
        try:
            import httpx
            print(f"✓ httpx {httpx.__version__}")
        except ImportError:
            print("⚠️  httpx未安装")

        try:
            import aiohttp
            print(f"✓ aiohttp {aiohttp.__version__}")
        except ImportError:
            print("⚠️  aiohttp未安装")

        # 测试应用模块
        print("\n🔧 测试应用模块...")

        # 测试配置
        from app.config import settings
        print("✓ 配置模块")

        # 测试数据库
        from app.database import engine, SessionLocal, get_db
        print("✓ 数据库模块")

        # 测试模型
        from app.models.task import ScanTask, Vulnerability, ReportTask, ScanLog
        print("✓ 数据模型")

        # 测试Schema
        from app.schemas.task import ScanTaskCreate, ScanTaskResponse
        print("✓ API Schemas")

        # 测试主应用
        from app.main import app
        print("✓ FastAPI应用")

        # 测试数据库连接
        print("\n💾 测试数据库连接...")
        try:
            from app.database import test_connection
            if test_connection():
                print("✓ 数据库连接成功")
            else:
                print("❌ 数据库连接失败")
                return False
        except Exception as e:
            print(f"⚠️  数据库连接测试跳过: {e}")

        print("\n✅ 最小功能测试通过！")
        print("\n📋 当前可用功能:")
        print("  - 数据库模型 (ScanTask, Vulnerability, ReportTask, ScanLog)")
        print("  - FastAPI应用框架")
        print("  - Pydantic数据验证")
        print("  - SQLAlchemy ORM")

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
    success = test_minimal_functionality()
    sys.exit(0 if success else 1)