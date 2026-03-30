import os
import asyncio
from celery import Celery
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.core import ScannerEngine

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)

def execute_scan_task(task_id: int, target_url: str, scan_strategy: str = "default"):
    db = SessionLocal()
    print(f"🚀 [Worker] 启动扫描引擎: ID={task_id}, Target={target_url}")
    task = None
    
    try:
        # 更新状态 -> RUNNING
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status = "RUNNING"
            db.commit()

        # === 调用核心引擎 ===
        # 由于 Celery 是同步的，我们需要用 asyncio.run 来运行异步扫描器
        engine = ScannerEngine(target_url, strategy=scan_strategy)
        found_vulns = asyncio.run(engine.run())
        
        # 保存漏洞结果
        for v in found_vulns:
            vuln_record = Vulnerability(
                task_id=task_id,
                vuln_name=v["vuln_name"],
                severity=v["severity"],
                url=v["url"],
                payload=v.get("payload"),
                evidence=v["evidence"]
            )
            db.add(vuln_record)
        # ====================

        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        db.commit()
        print(f"✅ [Worker] 扫描完成，发现 {len(found_vulns)} 个漏洞")

    except Exception as e:
        print(f"❌ [Worker] 引擎异常: {e}")
        if task:
            task.status = "FAILED"
        db.commit()
    finally:
        db.close()


@celery_app.task(bind=True)
def run_scan_task(self, task_id: int, target_url: str, scan_strategy: str = "default"):
    execute_scan_task(task_id, target_url, scan_strategy)
