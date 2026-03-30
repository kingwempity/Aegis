#!/usr/bin/env python
"""
测试PDF导出功能
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 配置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

from django.test import Client
from django.contrib.auth import get_user_model

def test_pdf_export():
    """测试PDF导出功能"""
    print("开始测试PDF导出功能...")

    # 获取用户
    User = get_user_model()
    try:
        user = User.objects.get(username='admin')
        print(f"找到用户: {user.username}")
    except User.DoesNotExist:
        print("用户不存在")
        return

    # 创建测试客户端
    client = Client()
    client.force_login(user)

    # 测试PDF导出
    task_id = 'task_20251229_21d685'
    url = f'/api/v1/tasks/{task_id}/report/export/'
    
    try:
        response = client.get(url, {'format': 'pdf', 'include_evidence': 'false'})
        print(f"响应状态码: {response.status_code}")
        print(f"Content-Type: {response.get('Content-Type', 'N/A')}")
        
        if response.status_code == 200:
            # 保存PDF文件
            with open('test_export.pdf', 'wb') as f:
                f.write(response.content)
            print("PDF文件已保存为 test_export.pdf")
            print(f"文件大小: {len(response.content)} bytes")
        else:
            print(f"响应内容: {response.content.decode('utf-8', errors='ignore')}")
    except Exception as e:
        print(f"测试失败: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    test_pdf_export()