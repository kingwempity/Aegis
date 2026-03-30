#!/usr/bin/env python
"""
检查URL路由
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 配置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

from django.urls import get_resolver, reverse
from django.test import RequestFactory

def check_url():
    """检查URL路由"""
    resolver = get_resolver()
    
    # 测试URL解析
    path = '/api/v1/tasks/task_20251229_21d685/report/export/'
    match = resolver.resolve(path)
    print(f'URL: {path}')
    print(f'URL name: {match.url_name}')
    print(f'View function: {match.func}')
    
    # 测试反向解析
    try:
        reversed_url = reverse('scans:export', kwargs={'task_id': 'task_20251229_21d685'})
        print(f'Reversed URL: {reversed_url}')
    except Exception as e:
        print(f'Reverse error: {e}')
    
    # 测试请求工厂
    factory = RequestFactory()
    request = factory.get(path, {'format': 'pdf', 'include_evidence': 'false'})
    print(f'Request path: {request.path}')
    print(f'Request GET params: {dict(request.GET)}')

if __name__ == '__main__':
    check_url()