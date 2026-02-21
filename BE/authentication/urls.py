"""
用户认证模块URL配置
"""
from django.urls import path
from . import views

app_name = 'authentication'

urlpatterns = [
    # 用户注册
    path('register/', views.UserRegistrationView.as_view(), name='register'),

    # 用户登录
    path('login/', views.UserLoginView.as_view(), name='login'),

    # 刷新Token
    path('refresh/', views.CustomTokenRefreshView.as_view(), name='refresh'),

    # 用户登出
    path('logout/', views.UserLogoutView.as_view(), name='logout'),

    # 获取当前用户信息
    path('me/', views.UserProfileView.as_view(), name='me'),
]
