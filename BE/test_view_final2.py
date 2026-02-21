#!/usr/bin/env python
"""
测试视图函数
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 配置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

from django.test import RequestFactory
from django.contrib.auth import get_user_model
from scans.views import ScanReportExportView

def test_view():
    """测试视图函数"""
    print("开始测试视图函数...")

    # 获取用户
    User = get_user_model()
    try:
        user = User.objects.get(username='admin')
        print(f"找到用户: {user.username}")
    except User.DoesNotExist:
        print("用户不存在")
        return

    # 创建请求工厂
    factory = RequestFactory()
    
    # 创建模拟请求
    task_id = 'task_20251229_21d685'
    request = factory.get('/api/v1/tasks/task_20251229_21d685/report/export', {
        'format': 'pdf',
        'include_evidence': 'false'
    })
    request.user = user

    # 创建视图实例
    view = ScanReportExportView()
    
    try:
        # 调用get方法
        response = view.get(request, task_id=task_id)
        print(f"响应状态码: {response.status_code}")
        print(f"Content-Type: {response.get('Content-Type', 'N/A')}")
        print(f"Content length: {len(response.content)}")
        
        if response.status_code == 200:
            # 保存PDF文件
            with open('test_export_view.pdf', 'wb') as f:
                f.write(response.content)
            print("PDF文件已保存为 test_export_view.pdf")
            print(f"文件大小: {len(response.content)} bytes")
        else:
            print(f"响应内容: {response.content.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"测试失败: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_view()