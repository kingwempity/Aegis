import os
import asyncio
import logging
import traceback
from celery import Celery
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.core import ScannerEngine

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 设置 scanner 模块的日志级别
logging.getLogger('scanner.engine.core').setLevel(logging.DEBUG)

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)

def execute_scan_task(task_id: int, target_url: str, scan_strategy: str = "default"):
    db = SessionLocal()
    logger.info(f"🚀 [Worker] 启动扫描引擎: ID={task_id}, Target={target_url}, Strategy={scan_strategy}")
    task = None
    
    try:
        # 更新状态 -> RUNNING
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if task:
            task.status = "RUNNING"
            db.commit()

        # === 调用核心引擎 ===
        engine = ScannerEngine(target_url, strategy=scan_strategy)
        logger.info(f"📋 [Worker] 加载插件数量: {len(engine.plugins)}")
        
        found_vulns = asyncio.run(engine.run())
        
        # 打印扫描统计
        stats = engine._stats.to_dict()
        logger.info(f"📊 [Worker] 扫描统计: 总请求={stats['total_requests']}, 成功={stats['successful_requests']}, 失败={stats['failed_requests']}, 漏洞={stats['vulnerabilities_found']}")
        
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
            logger.info(f"🔴 [Worker] 发现漏洞: {v['vuln_name']} @ {v['url']}")
        # ====================

        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        db.commit()
        logger.info(f"✅ [Worker] 扫描完成，发现 {len(found_vulns)} 个漏洞")

    except Exception as e:
        logger.error(f"❌ [Worker] 引擎异常: {e}")
        logger.error(traceback.format_exc())
        if task:
            task.status = "FAILED"
        db.commit()
    finally:
        db.close()


@celery_app.task(bind=True)
def run_scan_task(self, task_id: int, target_url: str, scan_strategy: str = "default"):
    execute_scan_task(task_id, target_url, scan_strategy)
