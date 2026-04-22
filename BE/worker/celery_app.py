import os
import asyncio
import logging
import traceback
import time
import json
from celery import Celery
import httpx
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.simulator import AttackSimulator

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)

def execute_scan_task(task_id: int, target_url: str, scan_strategy: str = "intelligent"):
    """
    执行模拟攻击扫描任务 (LLM 增强版)
    """
    db = SessionLocal()
    start_time = time.time()
    
    logger.info("=" * 60)
    logger.info(f"🚀 [Worker] 启动模拟攻击引擎 (Simulation Mode)")
    logger.info(f"   任务ID: {task_id}")
    logger.info(f"   目标URL: {target_url}")
    logger.info(f"   策略: {scan_strategy}")
    logger.info("=" * 60)
    
    task = None
    
    try:
        # 更新状态 -> RUNNING
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            logger.error(f"❌ [Worker] 任务不存在: {task_id}")
            return
        
        task.status = "RUNNING"
        db.commit()

        # === 调用模拟攻击引擎 ===
        logger.info("🔧 [Worker] 初始化 AttackSimulator...")
        simulator = AttackSimulator(target=target_url, strategy=scan_strategy)
        
        # 执行模拟攻击
        logger.info("🎯 [Worker] 开始执行 LLM 驱动的攻击循环...")
        # 兼容 Python 3.6
        if hasattr(asyncio, 'run'):
            result = asyncio.run(simulator.run_simulation())
        else:
            loop = asyncio.get_event_loop()
            result = loop.run_until_complete(simulator.run_simulation())
        
        found_vulns = result.get("vulnerabilities", [])
        execution_time = time.time() - start_time
        
        # 保存漏洞结果
        vuln_count = len(found_vulns)
        if vuln_count > 0:
            logger.info(f"🔴 [Worker] 发现 {vuln_count} 个确认漏洞:")
            
            for idx, v in enumerate(found_vulns, 1):
                vuln_record = Vulnerability(
                    task_id=task_id,
                    vuln_name="Simulation-Confirmed Vulnerability",
                    severity="HIGH", # 模拟攻击确认的通常是高危
                    url=v["url"],
                    payload=v.get("payload"),
                    evidence=json.dumps({
                        "evidence": v["evidence"],
                        "llm_analysis": v.get("llm_analysis")
                    }, ensure_ascii=False)
                )
                db.add(vuln_record)
                
                logger.info(f"  [{idx}] 目标URL: {v['url']}")
                logger.info(f"      分析: {v.get('llm_analysis')}")
        else:
            logger.info("ℹ️  [Worker] 未发现漏洞")
        
        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        task.vulnerabilities_found = vuln_count
        db.commit()
        
        logger.info("=" * 60)
        logger.info(f"✅ [Worker] 模拟攻击任务完成")
        logger.info(f"   耗时: {execution_time:.2f} 秒")
        logger.info("=" * 60)

    except Exception as e:
        error_msg = f"❌ [Worker] 引擎异常: {e}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        if task:
            task.status = "FAILED"
            db.commit()
    finally:
        db.close()

@celery_app.task(bind=True)
def run_scan_task(self, task_id: int, target_url: str, scan_strategy: str = "intelligent"):
    execute_scan_task(task_id, target_url, scan_strategy)
