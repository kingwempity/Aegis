"""
基于模拟攻击的Web应用程序漏洞检测系统 - ASGI配置
支持WebSocket实时通信
"""

import os
import django
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

# 设置Django设置模块
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

# 导入路由配置
from scans.routing import websocket_urlpatterns

application = ProtocolTypeRouter({
    # Django的HTTP请求处理
    "http": get_asgi_application(),

    # WebSocket请求处理
    "websocket": URLRouter(
        websocket_urlpatterns
    ),
})
