import os
import asyncio
import logging
import traceback
import time
from celery import Celery
import httpx
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.core import ScannerEngine

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 设置 scanner 模块的日志级别为 DEBUG，以便获取详细信息
logging.getLogger('scanner.engine.core').setLevel(logging.DEBUG)
logging.getLogger('scanner.engine.attack').setLevel(logging.INFO)

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)

def execute_scan_task(task_id: int, target_url: str, scan_strategy: str = "default"):
    """
    执行扫描任务
    
    Args:
        task_id: 任务ID
        target_url: 目标URL
        scan_strategy: 扫描策略
    """
    db = SessionLocal()
    start_time = time.time()
    
    logger.info("=" * 60)
    logger.info(f"🚀 [Worker] 启动扫描引擎")
    logger.info(f"   任务ID: {task_id}")
    logger.info(f"   目标URL: {target_url}")
    logger.info(f"   扫描策略: {scan_strategy}")
    logger.info(f"   开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
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
        logger.info(f"✅ [Worker] 任务状态已更新为 RUNNING")

        # === 调用核心引擎 ===
        logger.info("🔧 [Worker] 初始化扫描引擎...")
        
        engine = ScannerEngine(
            target=target_url,
            strategy=scan_strategy,
            timeout=30.0,  # 30秒超时
            max_concurrent=5  # 最大并发数
        )
        
        plugin_count = len(engine.plugins)
        plugin_ids = [p.get('id', 'unknown') for p in engine.plugins]
        
        logger.info(f"📋 [Worker] 插件加载完成")
        logger.info(f"   插件数量: {plugin_count}")
        logger.info(f"   插件列表: {plugin_ids}")
        
        if plugin_count == 0:
            logger.warning("⚠️ [Worker] 未加载任何插件！请检查插件目录配置")
        
        # 执行扫描
        logger.info("🎯 [Worker] 开始执行扫描...")
        found_vulns = asyncio.run(engine.run())
        
        # 计算执行时间
        execution_time = time.time() - start_time
        
        # 打印扫描统计
        stats = engine._stats.to_dict()
        
        logger.info("-" * 60)
        logger.info(f"📊 [Worker] 扫描统计报告")
        logger.info(f"   总请求数: {stats['total_requests']}")
        logger.info(f"   成功请求: {stats['successful_requests']}")
        logger.info(f"   失败请求: {stats['failed_requests']}")
        logger.info(f"   发现漏洞: {stats['vulnerabilities_found']}")
        logger.info(f"   访问路径: {stats['paths_visited']}")
        logger.info(f"   发现路径: {stats['paths_discovered']}")
        logger.info(f"   执行耗时: {execution_time:.2f} 秒")
        logger.info("-" * 60)
        
        # 保存漏洞结果
        vuln_count = len(found_vulns)
        if vuln_count > 0:
            logger.info(f"🔴 [Worker] 发现 {vuln_count} 个漏洞:")
            
            for idx, v in enumerate(found_vulns, 1):
                vuln_record = Vulnerability(
                    task_id=task_id,
                    vuln_name=v["vuln_name"],
                    severity=v["severity"],
                    url=v["url"],
                    payload=v.get("payload"),
                    evidence=v["evidence"]
                )
                db.add(vuln_record)
                
                logger.info(f"  [{idx}] 漏洞名称: {v['vuln_name']}")
                logger.info(f"      严重程度: {v['severity']}")
                logger.info(f"      目标URL: {v['url']}")
                logger.info(f"      使用Payload: {v.get('payload', 'N/A')}")
                
                # 记录响应信息（如果有）
                response_info = v.get('response', {})
                if response_info:
                    logger.info(f"      响应状态: {response_info.get('status', 'N/A')}")
                    body_snippet = response_info.get('body_snippet', '')
                    if body_snippet:
                        preview = body_snippet[:200] + "..." if len(body_snippet) > 200 else body_snippet
                        logger.info(f"      响应内容: {preview}")
                
                logger.info("")
        else:
            logger.info("ℹ️  [Worker] 未发现漏洞")
        
        # ====================
        
        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        task.vulnerabilities_found = vuln_count
        db.commit()
        
        logger.info("=" * 60)
        logger.info(f"✅ [Worker] 扫描任务完成")
        logger.info(f"   最终结果: 发现 {vuln_count} 个漏洞")
        logger.info(f"   结束时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"   总耗时: {execution_time:.2f} 秒")
        logger.info("=" * 60)

    except httpx.ConnectError as e:
        logger.error("=" * 60)
        logger.error(f"❌ [Worker] 网络连接失败")
        logger.error(f"   错误类型: ConnectError")
        logger.error(f"   错误信息: {e}")
        logger.error(f"   可能原因: 目标服务器不可达或网络问题")
        logger.error("=" * 60)
        
        if task:
            task.status = "FAILED"
            db.commit()

    except httpx.TimeoutException as e:
        logger.error("=" * 60)
        logger.error(f"❌ [Worker] 请求超时")
        logger.error(f"   错误类型: TimeoutException")
        logger.error(f"   错误信息: {e}")
        logger.error(f"   可能原因: 目标服务器响应过慢或网络延迟过高")
        logger.error("=" * 60)
        
        if task:
            task.status = "FAILED"
            db.commit()

    except Exception as e:
        logger.error("=" * 60)
        logger.error(f"❌ [Worker] 引擎异常")
        logger.error(f"   异常类型: {type(e).__name__}")
        logger.error(f"   异常信息: {e}")
        logger.error(f"   堆栈跟踪:")
        logger.error(traceback.format_exc())
        logger.error("=" * 60)
        
        if task:
            task.status = "FAILED"
            db.commit()
            
    finally:
        db.close()


@celery_app.task(bind=True)
def run_scan_task(self, task_id: int, target_url: str, scan_strategy: str = "default"):
    """Celery任务入口"""
    execute_scan_task(task_id, target_url, scan_strategy)
