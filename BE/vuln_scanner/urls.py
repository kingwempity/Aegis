"""
基于模拟攻击的Web应用程序漏洞检测系统 - URL配置
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse
from django.shortcuts import redirect
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from . import consumers

def api_root(request):
    """
    API根路径处理
    显示API信息和可用端点
    """
    return JsonResponse({
        "message": "基于模拟攻击的Web应用程序漏洞检测系统 API",
        "version": "v1.0",
        "endpoints": {
            "admin": "/admin/",
            "api": {
                "auth": {
                    "register": "/api/v1/auth/register/",
                    "login": "/api/v1/auth/login/",
                    "refresh": "/api/v1/auth/refresh/",
                    "logout": "/api/v1/auth/logout/",
                    "me": "/api/v1/auth/me/"
                },
                "tasks": {
                    "create": "/api/v1/tasks/create/",
                    "list": "/api/v1/tasks/list/",
                    "detail": "/api/v1/tasks/{task_id}/",
                    "status": "/api/v1/tasks/{task_id}/status/",
                    "cancel": "/api/v1/tasks/{task_id}/cancel/",
                    "report": "/api/v1/tasks/{task_id}/report/"
                },
                "vulnerabilities": "/api/v1/vulnerabilities/{vulnerability_id}/",
                "modules": "/api/v1/modules/",
                "stats": "/api/v1/stats/",
                "admin": "/api/v1/admin/"
            }
        },
        "documentation": "请访问 /admin/ 查看管理后台"
    })

urlpatterns = [
    # 根路径 - API信息页面
    path('', api_root, name='api_root'),

    # Django管理后台
    path('admin/', admin.site.urls),

    # JWT认证路由 (直接配置，不通过子应用)
    path('api/v1/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/v1/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # API v1路由 - 使用子应用
    path('api/v1/auth/', include('authentication.urls')),  # 用户认证
    path('api/v1/tasks/', include('scans.urls')),  # 扫描任务管理
    path('api/v1/vulnerabilities/', include('vulnerabilities.urls')),  # 漏洞检测结果
    path('api/v1/modules/', include('modules.urls')),  # 漏洞模块管理
    path('api/v1/stats/', include('stats.urls')),  # 统计与监控
    path('api/v1/admin/', include('admin_panel.urls')),  # 管理员面板

    # WebSocket路由
    path('ws/tasks/<str:task_id>/', consumers.TaskStatusConsumer.as_asgi()),

    # 健康检查 - 简单的健康检查视图
    # path('health/', include('health_check.urls')),  # 如果安装了django-health-check
]

# 开发环境下的静态文件服务
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
