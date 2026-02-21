"""
漏洞模块管理URL配置
"""
from django.urls import path
from . import views

app_name = 'modules'

urlpatterns = [
    # 获取系统支持的漏洞模块列表
    path('list/', views.ModuleListView.as_view(), name='list'),

    # 更新漏洞库
    path('update/', views.ModuleUpdateView.as_view(), name='update'),

    # 获取漏洞模块详情
    path('<str:module_id>/', views.ModuleDetailView.as_view(), name='detail'),
]
