"""
管理员面板URL配置
"""
from django.urls import path
from . import views

app_name = 'admin_panel'

urlpatterns = [
    # 管理员统计信息
    path('statistics/', views.AdminStatisticsView.as_view(), name='admin_statistics'),

    # 用户管理
    path('users/', views.AdminUserViewSet.as_view(), name='admin_users'),
    path('users/<str:user_id>/', views.AdminUserDetailView.as_view(), name='admin_user_detail'),

    # 任务管理
    path('tasks/', views.AdminTaskViewSet.as_view(), name='admin_tasks'),
    path('tasks/<str:task_id>/', views.AdminTaskDetailView.as_view(), name='admin_task_detail'),
]
