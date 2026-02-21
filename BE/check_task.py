#!/usr/bin/env python
"""
检查任务是否存在
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 配置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

from scans.models import ScanTask

def check_task():
    """检查任务是否存在"""
    task_id = 'task_20251229_21d685'
    task = ScanTask.objects.filter(task_id=task_id).first()
    print(f'Task exists: {task is not None}')
    if task:
        print(f'Task status: {task.status}')
        print(f'Task owner: {task.created_by.username if task.created_by else "None"}')

if __name__ == '__main__':
    check_task()