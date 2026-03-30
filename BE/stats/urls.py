"""
统计与监控模块URL配置
"""
from django.urls import path
from . import views

app_name = 'stats'

urlpatterns = [
    # 获取系统统计信息
    path('overview/', views.SystemStatsView.as_view(), name='overview'),

    # 获取漏洞统计图表数据
    path('charts/', views.VulnerabilityChartsView.as_view(), name='charts'),
]
