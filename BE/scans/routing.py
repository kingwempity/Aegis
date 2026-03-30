"""
WebSocket路由配置
定义WebSocket URL路由
"""
from django.urls import re_path
from vuln_scanner.consumers import TaskStatusConsumer

websocket_urlpatterns = [
    re_path(r'^ws/tasks/(?P<task_id>[^/]+)/$', TaskStatusConsumer.as_asgi()),
]
