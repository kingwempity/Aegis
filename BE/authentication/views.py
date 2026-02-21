"""
用户认证模块视图
提供用户注册、登录、登出、Token刷新和用户信息获取功能
"""
import re
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView


class UserRegistrationView(APIView):
    """
    用户注册视图
    支持新用户注册功能
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        处理用户注册请求

        请求参数:
        - username: 用户名 (3-20字符，只能包含字母、数字和下划线)
        - email: 邮箱地址
        - password: 密码 (至少8字符，包含大小写字母和数字)
        - full_name: 全名 (可选)

        返回:
        - 成功: 用户信息和用户ID
        - 失败: 错误信息
        """
        data = request.data
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        full_name = data.get('full_name', '').strip()

        # 验证必填字段
        if not all([username, email, password]):
            return Response({
                'code': 400,
                'message': 'Missing required parameter',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 验证用户名格式
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
            return Response({
                'code': 400,
                'message': 'Invalid username format',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 验证邮箱格式 - 更加严格的验证，防止XSS和注入攻击
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            return Response({
                'code': 400,
                'message': 'Invalid email format',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 额外的安全检查 - 防止潜在的XSS向量
        dangerous_chars = ['<', '>', '"', "'", 'javascript:', 'vbscript:', 'onload', 'onerror']
        if any(char in email.lower() for char in dangerous_chars):
            return Response({
                'code': 400,
                'message': 'Invalid email format',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 验证密码强度
        if not self._validate_password_strength(password):
            return Response({
                'code': 400,
                'message': 'Password too weak',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 检查用户名是否已存在
        if User.objects.filter(username=username).exists():
            return Response({
                'code': 400,
                'message': 'Username already exists',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 检查邮箱是否已被注册
        if User.objects.filter(email=email).exists():
            return Response({
                'code': 400,
                'message': 'Email already registered',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 创建用户
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=full_name,
                is_active=True
            )

            return Response({
                'code': 200,
                'message': 'User registered successfully',
                'data': {
                    'user_id': f'user_{user.id}',
                    'username': user.username,
                    'email': user.email,
                    'created_at': user.date_joined.isoformat()
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': 'Registration failed',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _validate_password_strength(self, password):
        """
        验证密码强度
        要求: 至少8字符，包含大小写字母和数字
        """
        if len(password) < 8:
            return False

        has_upper = re.search(r'[A-Z]', password)
        has_lower = re.search(r'[a-z]', password)
        has_digit = re.search(r'\d', password)

        return all([has_upper, has_lower, has_digit])


class UserLoginView(APIView):
    """
    用户登录视图
    支持用户名/邮箱登录，返回JWT Token
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        处理用户登录请求

        请求参数:
        - username: 用户名或邮箱
        - password: 密码

        返回:
        - 成功: Access Token和Refresh Token
        - 失败: 错误信息
        """
        data = request.data
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not all([username, password]):
            return Response({
                'code': 400,
                'message': 'Username and password are required',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 尝试通过用户名或邮箱认证
        user = None

        # 先尝试用户名登录
        user = authenticate(username=username, password=password)

        # 如果失败，尝试邮箱登录
        if user is None and '@' in username:
            try:
                user_obj = User.objects.get(email=username)
                user = authenticate(username=user_obj.username, password=password)
            except User.DoesNotExist:
                pass

        if user is None:
            return Response({
                'code': 401,
                'message': 'Invalid credentials',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({
                'code': 401,
                'message': 'Account is disabled',
                'data': {}
            }, status=status.HTTP_401_UNAUTHORIZED)

        # 生成JWT Token
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # 更新最后登录时间
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        return Response({
            'code': 200,
            'message': 'Login successful',
            'data': {
                'access_token': access_token,
                'refresh_token': str(refresh),
                'token_type': 'Bearer',
                'expires_in': 3600,  # Access Token 1小时
                'user': {
                    'user_id': f'user_{user.id}',
                    'username': user.username,
                    'email': user.email,
                    'role': 'admin' if user.is_superuser else 'user'
                }
            }
        }, status=status.HTTP_200_OK)


class CustomTokenRefreshView(TokenRefreshView):
    """
    自定义Token刷新视图
    继承自TokenRefreshView，统一响应格式
    """

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)

        if response.status_code == 200:
            # 构建完整的AuthResponse格式
            data = {
                'access_token': response.data['access'],
                'token_type': 'Bearer',
                'expires_in': 3600
            }

            # 如果有新的refresh_token（当ROTATE_REFRESH_TOKENS=True时）
            if 'refresh' in response.data:
                data['refresh_token'] = response.data['refresh']

            return Response({
                'code': 200,
                'message': 'Token refreshed',
                'data': data
            })
        else:
            return Response({
                'code': response.status_code,
                'message': 'Token refresh failed',
                'data': {}
            }, status=response.status_code)


class UserLogoutView(APIView):
    """
    用户登出视图
    使当前的Access Token失效
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        处理用户登出请求

        请求头需要包含Authorization: Bearer <token>
        """
        try:
            # 获取当前用户的Refresh Token并使其失效
            # 注意: 这里需要前端在登出时传递refresh_token
            refresh_token = request.data.get('refresh_token')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            return Response({
                'code': 200,
                'message': 'Logout successful',
                'data': {}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # 即使Token处理失败，也返回成功（客户端已清除本地Token）
            return Response({
                'code': 200,
                'message': 'Logout successful',
                'data': {}
            }, status=status.HTTP_200_OK)


class UserProfileView(APIView):
    """
    用户信息视图
    获取当前登录用户的信息
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取当前用户信息

        返回用户信息包括统计数据
        """
        user = request.user

        # 计算用户的统计数据
        from scans.models import ScanTask, Vulnerability

        total_tasks = ScanTask.objects.filter(created_by=user).count()
        total_scans = total_tasks  # 假设每个任务都是一次扫描
        total_vulnerabilities = Vulnerability.objects.filter(task__created_by=user).count()

        # 最近的扫描任务
        recent_tasks = ScanTask.objects.filter(
            created_by=user
        ).order_by('-created_at')[:5]

        recent_scans = []
        for task in recent_tasks:
            recent_scans.append({
                'task_id': task.task_id,
                'task_name': task.task_name,
                'status': task.status,
                'created_at': task.created_at.isoformat(),
                'vulnerabilities_found': task.vulnerabilities_found
            })

        return Response({
            'code': 200,
            'message': 'Success',
            'data': {
                'user_id': f'user_{user.id}',
                'username': user.username,
                'email': user.email,
                'full_name': f'{user.first_name} {user.last_name}'.strip(),
                'role': 'admin' if user.is_superuser else 'user',
                'created_at': user.date_joined.isoformat(),
                'total_tasks': total_tasks,
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'recent_scans': recent_scans
            }
        }, status=status.HTTP_200_OK)
