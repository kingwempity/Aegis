"""
扫描任务执行器
负责异步执行扫描任务
"""
import threading
import time
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.management.base import BaseCommand
from django.utils import timezone
from scans.models import ScanTask
from .engine import VulnerabilityScanner
from scanner.engine.core import ScannerEngine
import logging

logger = logging.getLogger(__name__)


class ScanTaskExecutor:
    """
    扫描任务执行器
    使用线程池异步执行扫描任务
    """

    def __init__(self, max_workers=3):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_tasks = {}
        self._running = True

    def start(self):
        """启动执行器"""
        logger.info(f"扫描任务执行器启动，最大并发数: {self.max_workers}")

        # 启动任务调度线程
        scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        scheduler_thread.start()

        # 启动清理线程
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup_thread.start()

    def stop(self):
        """停止执行器"""
        self._running = False
        self.executor.shutdown(wait=True)
        logger.info("扫描任务执行器已停止")

    def _scheduler_loop(self):
        """任务调度循环"""
        while self._running:
            try:
                # 获取待执行的任务
                pending_tasks = ScanTask.objects.filter(
                    status='queued'
                ).order_by('created_at')[:self.max_workers]

                for task in pending_tasks:
                    if len(self.active_tasks) >= self.max_workers:
                        break

                    if task.id not in self.active_tasks:
                        # 提交任务到线程池
                        future = self.executor.submit(self._execute_scan_task, task)
                        self.active_tasks[task.id] = future
                        logger.info(f"任务 {task.task_id} 已提交执行")

                time.sleep(5)  # 每5秒检查一次

            except Exception as e:
                logger.error(f"任务调度循环异常: {str(e)}")
                time.sleep(10)

    def _execute_scan_task(self, task):
        """执行单个扫描任务"""
        try:
            logger.info(f"开始执行任务: {task.task_id}")

            # 创建基础扫描器并执行（爬虫和基础漏洞）
            scanner = VulnerabilityScanner(task)
            scanner.scan()

            # 执行高级插件扫描（针对特定 CVE）
            try:
                logger.info(f"开始执行高级插件扫描: {task.task_id}")
                plugin_engine = ScannerEngine(target=task.target_url)
                # 将发现的漏洞保存到数据库 (ScannerEngine.run 是 async 方法)
                results = asyncio.run(plugin_engine.run())
                for res in results:
                    from scans.models import Vulnerability
                    # 映射 ScannerEngine 的结果字段到数据库模型
                    Vulnerability.objects.create(
                        task=task,
                        name=res.get("vuln_name", "Unknown Plugin Vulnerability"),
                        type=res.get("plugin_id", "plugin"),
                        url=res.get("url", task.target_url),
                        method=res.get("request", {}).get("method", "GET"),
                        parameter=res.get("parameter", ""),
                        payload=res.get("payload", ""),
                        evidence=json.dumps(res.get("evidence", {})) if isinstance(res.get("evidence"), dict) else str(res.get("evidence", "")),
                        cvss_score=8.0 if res.get("severity") == "high" else 5.0,
                        risk_level=res.get("severity", "medium").lower(),
                        description=f"Detected by plugin: {res.get('plugin_id')}",
                        remediation="Please refer to CVE details for remediation steps.",
                    )
                logger.info(f"高级插件扫描完成，发现 {len(results)} 个漏洞")
            except Exception as pe:
                logger.error(f"高级插件扫描异常: {str(pe)}")

            logger.info(f"任务 {task.task_id} 执行完成")

        except Exception as e:
            logger.error(f"任务 {task.task_id} 执行失败: {str(e)}")
            task.mark_failed(str(e))

        finally:
            # 从活跃任务中移除
            if task.id in self.active_tasks:
                del self.active_tasks[task.id]

    def _cleanup_loop(self):
        """清理循环 - 处理超时的任务"""
        while self._running:
            try:
                # 检查超时的任务（假设最大执行时间为2小时）
                timeout_threshold = timezone.now() - timezone.timedelta(hours=2)

                running_tasks = ScanTask.objects.filter(
                    status='running',
                    started_at__lt=timeout_threshold
                )

                for task in running_tasks:
                    logger.warning(f"任务 {task.task_id} 执行超时，标记为失败")
                    task.mark_failed("Task execution timeout")

                time.sleep(300)  # 每5分钟检查一次

            except Exception as e:
                logger.error(f"清理循环异常: {str(e)}")
                time.sleep(300)

    def cancel_task(self, task_id, user):
        """取消指定的扫描任务"""
        try:
            task = ScanTask.objects.get(task_id=task_id, created_by=user)

            if task.status not in ['queued', 'running']:
                return False, "任务无法取消"

            # 如果任务在活跃列表中，取消Future
            if task.id in self.active_tasks:
                future = self.active_tasks[task.id]
                future.cancel()
                del self.active_tasks[task.id]

            task.mark_cancelled()
            logger.info(f"任务 {task.task_id} 已取消")
            return True, "任务已取消"

        except ScanTask.DoesNotExist:
            return False, "任务不存在"
        except Exception as e:
            logger.error(f"取消任务失败: {str(e)}")
            return False, str(e)


# 全局执行器实例
_executor = None


def get_executor():
    """获取全局执行器实例"""
    global _executor
    if _executor is None:
        _executor = ScanTaskExecutor()
    return _executor


def start_executor():
    """启动全局执行器"""
    executor = get_executor()
    executor.start()


def stop_executor():
    """停止全局执行器"""
    global _executor
    if _executor:
        _executor.stop()
        _executor = None
