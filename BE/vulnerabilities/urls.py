"""
漏洞检测模块URL配置
"""
from django.urls import path
from . import views

app_name = 'vulnerabilities'

urlpatterns = [
    # 获取漏洞详情
    path('<str:vulnerability_id>/', views.VulnerabilityDetailView.as_view(), name='detail'),

    # 获取攻击证据
    path('<str:vulnerability_id>/evidence/', views.VulnerabilityEvidenceView.as_view(), name='evidence'),
]
