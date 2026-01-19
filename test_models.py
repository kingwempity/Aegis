#!/usr/bin/env python3
"""
Aegis 数据库模型测试脚本
----------------------
测试数据库模型的创建、关系和基本操作。
"""
import sys
import os
from pathlib import Path

# 添加项目根目录到Python路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_models():
    """测试数据库模型"""
    print("🧪 测试 Aegis 数据库模型...")

    try:
        from app.database import test_connection, create_tables, SessionLocal
        from app.models import ScanTask, Vulnerability, ReportTask, ScanLog
        from datetime import datetime

        # 测试数据库连接
        if not test_connection():
            return False

        # 创建表结构
        create_tables()

        # 测试模型创建
        print("\n📝 测试模型创建...")

        db = SessionLocal()
        try:
            # 创建扫描任务
            task = ScanTask(
                name="测试扫描任务",
                target_url="https://example.com",
                scan_config={"qps_limit": 5, "timeout": 30},
                cookies="session=abc123"
            )
            db.add(task)
            db.commit()
            db.refresh(task)

            print(f"✓ 创建扫描任务: {task.id}")

            # 创建漏洞记录
            vuln = Vulnerability(
                task_id=task.id,
                vuln_type="xss",
                title="反射型XSS漏洞",
                severity="high",
                url="https://example.com/search?q=<script>alert(1)</script>",
                payload="<script>alert(1)</script>",
                evidence={
                    "request": "GET /search?q=<script>alert(1)</script>",
                    "response": "<html><body><script>alert(1)</script></body></html>"
                }
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)

            print(f"✓ 创建漏洞记录: {vuln.id}")

            # 创建报告任务
            report = ReportTask(
                task_id=task.id,
                report_type="pdf",
                report_title="安全扫描报告"
            )
            db.add(report)
            db.commit()
            db.refresh(report)

            print(f"✓ 创建报告任务: {report.id}")

            # 创建日志记录
            log = ScanLog(
                task_id=task.id,
                level="info",
                message="开始扫描 https://example.com",
                url="https://example.com"
            )
            db.add(log)
            db.commit()
            db.refresh(log)

            print(f"✓ 创建日志记录: {log.id}")

            # 测试关系查询
            print("\n🔗 测试模型关系...")

            # 查询任务及其关联对象
            task_with_relations = db.query(ScanTask).filter(ScanTask.id == task.id).first()
            if task_with_relations:
                print(f"✓ 任务关联漏洞数量: {len(task_with_relations.vulnerabilities)}")
                print(f"✓ 任务关联报告数量: {len(task_with_relations.report_tasks)}")
                print(f"✓ 任务关联日志数量: {len(task_with_relations.logs)}")

            # 查询漏洞及其任务
            vuln_with_task = db.query(Vulnerability).filter(Vulnerability.id == vuln.id).first()
            if vuln_with_task and vuln_with_task.task:
                print(f"✓ 漏洞关联任务: {vuln_with_task.task.name}")

            print("\n🎉 所有模型测试通过！")

            # 清理测试数据
            db.delete(log)
            db.delete(report)
            db.delete(vuln)
            db.delete(task)
            db.commit()

            print("🧹 测试数据清理完成")

            return True

        finally:
            db.close()

    except Exception as e:
        print(f"❌ 模型测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_models()
    sys.exit(0 if success else 1)