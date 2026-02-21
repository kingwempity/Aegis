"""
Django管理命令：启动扫描任务执行器
"""
from django.core.management.base import BaseCommand
from vuln_scanner.scanner.executor import start_executor, stop_executor
import signal
import sys


class Command(BaseCommand):
    help = '启动扫描任务执行器'

    def add_arguments(self, parser):
        parser.add_argument(
            '--workers',
            type=int,
            default=3,
            help='最大并发工作线程数 (默认: 3)',
        )

    def handle(self, *args, **options):
        workers = options['workers']

        self.stdout.write(
            self.style.SUCCESS(f'启动扫描任务执行器 (workers={workers})...')
        )

        # 设置信号处理器以优雅关闭
        def signal_handler(signum, frame):
            self.stdout.write(self.style.WARNING('接收到停止信号，正在关闭执行器...'))
            stop_executor()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # 启动执行器
            start_executor()
            self.stdout.write(self.style.SUCCESS('扫描任务执行器已启动'))

            # 保持运行
            while True:
                import time
                time.sleep(1)

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING('接收到键盘中断，正在关闭...'))
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'执行器运行出错: {str(e)}')
            )
        finally:
            stop_executor()
            self.stdout.write(self.style.SUCCESS('扫描任务执行器已停止'))
