#!/usr/bin/env python
"""
测试PDF导出API
"""
import requests
import json

def test_pdf_export():
    """测试PDF导出API"""
    print("测试PDF导出API...")

    # 1. 获取认证token
    token_url = 'http://127.0.0.1:8000/api/v1/auth/token/'
    login_data = {
        'username': 'admin',
        'password': 'admin123'
    }

    print("1. 获取认证token...")
    token_response = requests.post(token_url, json=login_data)

    if token_response.status_code != 200:
        print(f"获取token失败: {token_response.status_code}")
        print(f"响应: {token_response.text}")
        return

    token_data = token_response.json()
    access_token = token_data.get('access')
    print(f"✓ 获取到access token: {access_token[:20]}...")

    # 2. 测试PDF导出
    export_url = 'http://127.0.0.1:8000/api/v1/tasks/task_20251221_c64066/report/export/?format=pdf&include_evidence=false'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    print("2. 测试PDF导出...")
    export_response = requests.get(export_url, headers=headers)

    print(f"响应状态码: {export_response.status_code}")
    print(f"Content-Type: {export_response.headers.get('Content-Type', 'N/A')}")

    if export_response.status_code == 200:
        print("✓ PDF导出成功!")
        print(f"文件大小: {len(export_response.content)} bytes")

        # 保存PDF文件
        with open('api_test_export.pdf', 'wb') as f:
            f.write(export_response.content)
        print("PDF文件已保存为 api_test_export.pdf")
    else:
        print("✗ PDF导出失败!")
        print(f"响应内容: {export_response.text}")

if __name__ == '__main__':
    test_pdf_export()
