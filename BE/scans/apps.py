import logging
import os
import sys
from django.apps import AppConfig

logger = logging.getLogger(__name__)


class ScansConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scans'

    def ready(self):
        """
        在服务启动时自动启动扫描执行器。
        - 默认开启，可通过 settings.AUTO_START_EXECUTOR=False 或环境变量 AUTO_START_EXECUTOR=false 关闭
        - 避免在管理命令（migrate/test/collectstatic等）及 runserver 双进程热重载的子进程中重复启动
        """
        from django.conf import settings

        if not getattr(settings, 'AUTO_START_EXECUTOR', False):
            return

        # 避免在管理命令下启动
        if len(sys.argv) > 1 and sys.argv[1] in {
            'migrate', 'makemigrations', 'collectstatic', 'test',
            'shell', 'createsuperuser', 'loaddata', 'dumpdata',
            'start_executor', 'startexecutor',
        }:
            return

        # runserver 会启动两个进程，只有主进程 RUN_MAIN=true 时启动
        if 'runserver' in sys.argv:
            if os.environ.get('RUN_MAIN') != 'true':
                return

        # 避免重复启动（同进程只启动一次）
        if getattr(self, '_executor_started', False):
            return

        try:
            from vuln_scanner.scanner.executor import start_executor
            start_executor()
            self._executor_started = True
            logger.info("扫描任务执行器已随Django自动启动")
        except Exception as e:
            logger.error(f"自动启动扫描任务执行器失败: {e}")
