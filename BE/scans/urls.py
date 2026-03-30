"""
扫描任务管理模块URL配置
"""
from django.urls import path
from . import views

app_name = 'scans'

urlpatterns = [
    # 创建扫描任务
    path('create/', views.ScanTaskCreateView.as_view(), name='create'),

    # 列出用户所有任务
    path('list/', views.ScanTaskListView.as_view(), name='list'),

    # 导出报告（必须在 report/ 之前，因为更具体）
    path('<str:task_id>/report/export/', views.ScanReportExportView.as_view(), name='export'),
    path('<str:task_id>/report/export', views.ScanReportExportView.as_view(), name='export_no_slash'),

    # 获取扫描报告（必须在 task_id/ 之前，因为更具体）
    path('<str:task_id>/report/', views.ScanReportView.as_view(), name='report'),

    # 查询任务状态
    path('<str:task_id>/status/', views.ScanTaskStatusView.as_view(), name='status'),

    # 取消扫描任务
    path('<str:task_id>/cancel/', views.ScanTaskCancelView.as_view(), name='cancel'),

    # 获取任务详情（放在最后，因为是最通用的路由）
    path('<str:task_id>/', views.ScanTaskDetailView.as_view(), name='detail'),
]
