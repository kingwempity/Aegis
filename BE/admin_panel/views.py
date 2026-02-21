"""
管理员面板视图
提供管理员相关的API接口，包括用户管理、系统统计等
"""
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.viewsets import ModelViewSet
from django.contrib.auth import get_user_model
from scans.models import ScanTask, Vulnerability

User = get_user_model()


class AdminRequiredMixin:
    """管理员权限检查混入类"""

    def check_admin_permission(self, request):
        """检查管理员权限"""
        if not request.user.is_superuser:
            return Response({
                'code': 403,
                'message': '需要管理员权限',
                'data': {}
            }, status=status.HTTP_403_FORBIDDEN)
        return None


class AdminStatisticsView(APIView, AdminRequiredMixin):
    """
    管理员统计信息视图
    提供系统级的统计数据
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取管理员统计信息

        返回系统级统计数据
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        try:
            # 用户统计
            total_users = User.objects.count()
            active_users = User.objects.filter(is_active=True).count()

            # 任务统计
            total_tasks_all = ScanTask.objects.count()

            # 漏洞统计
            total_vulnerabilities_all = Vulnerability.objects.count()

            # 基础统计信息
            from stats.models import Statistics
            try:
                basic_stats = Statistics.objects.first()
                if basic_stats:
                    base_stats = {
                        'total_scans': basic_stats.total_scans,
                        'vulnerabilities_found': basic_stats.vulnerabilities_found,
                        'critical_vulnerabilities': basic_stats.critical_vulnerabilities,
                        'active_tasks': basic_stats.active_tasks,
                        'system_uptime_hours': basic_stats.system_uptime_hours,
                    }
                else:
                    base_stats = {
                        'total_scans': 0,
                        'vulnerabilities_found': 0,
                        'critical_vulnerabilities': 0,
                        'active_tasks': 0,
                        'system_uptime_hours': 0,
                    }
            except:
                base_stats = {
                    'total_scans': 0,
                    'vulnerabilities_found': 0,
                    'critical_vulnerabilities': 0,
                    'active_tasks': 0,
                    'system_uptime_hours': 0,
                }

            return Response({
                'code': 200,
                'message': 'Success',
                'data': {
                    **base_stats,
                    'total_users': total_users,
                    'active_users': active_users,
                    'total_tasks_all': total_tasks_all,
                    'total_vulnerabilities_all': total_vulnerabilities_all,
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '获取统计信息失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminUserViewSet(APIView, AdminRequiredMixin):
    """
    管理员用户管理视图集
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取所有用户列表
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        try:
            users = User.objects.all().order_by('-date_joined')

            user_data = []
            for user in users:
                # 计算用户的任务统计
                total_tasks = ScanTask.objects.filter(created_by=user).count()
                total_vulnerabilities = Vulnerability.objects.filter(task__created_by=user).count()

                user_data.append({
                    'user_id': f'user_{user.id}',
                    'username': user.username,
                    'email': user.email,
                    'role': 'admin' if user.is_superuser else 'user',
                    'is_active': user.is_active,
                    'is_superuser': user.is_superuser,
                    'created_at': user.date_joined.isoformat(),
                    'last_login': user.last_login.isoformat() if user.last_login else None,
                    'total_tasks': total_tasks,
                    'total_scans': total_tasks,  # 假设每个任务都是一次扫描
                    'total_vulnerabilities': total_vulnerabilities,
                })

            return Response({
                'code': 200,
                'message': 'Success',
                'data': user_data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '获取用户列表失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        """
        创建新用户
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        data = request.data
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', 'user')
        is_active = data.get('is_active', True)

        # 验证必填字段
        if not all([username, email, password]):
            return Response({
                'code': 400,
                'message': '用户名、邮箱和密码都是必填项',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 检查用户名是否已存在
        if User.objects.filter(username=username).exists():
            return Response({
                'code': 400,
                'message': '用户名已存在',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 检查邮箱是否已被注册
        if User.objects.filter(email=email).exists():
            return Response({
                'code': 400,
                'message': '邮箱已被注册',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 创建用户
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                is_active=is_active,
                is_superuser=(role == 'admin'),
                is_staff=(role == 'admin')
            )

            return Response({
                'code': 200,
                'message': '用户创建成功',
                'data': {
                    'user_id': f'user_{user.id}',
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    'is_active': user.is_active,
                    'created_at': user.date_joined.isoformat()
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '创建用户失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminUserDetailView(APIView, AdminRequiredMixin):
    """
    管理员用户详情管理视图
    """
    permission_classes = [IsAuthenticated]

    def put(self, request, user_id):
        """
        更新用户信息
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        # 解析用户ID
        if not user_id.startswith('user_'):
            return Response({
                'code': 400,
                'message': '无效的用户ID格式',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_pk = int(user_id[5:])  # 移除 'user_' 前缀
            user = User.objects.get(pk=user_pk)
        except (ValueError, User.DoesNotExist):
            return Response({
                'code': 404,
                'message': '用户不存在',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        data = request.data
        email = data.get('email', '').strip()
        role = data.get('role', user.is_superuser and 'admin' or 'user')
        is_active = data.get('is_active', user.is_active)

        # 检查邮箱是否已被其他用户使用
        if email and email != user.email:
            if User.objects.filter(email=email).exclude(pk=user.pk).exists():
                return Response({
                    'code': 400,
                    'message': '邮箱已被其他用户使用',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 更新用户信息
            if email:
                user.email = email
            user.is_active = is_active
            user.is_superuser = (role == 'admin')
            user.is_staff = (role == 'admin')
            user.save()

            return Response({
                'code': 200,
                'message': '用户信息更新成功',
                'data': {
                    'user_id': f'user_{user.id}',
                    'username': user.username,
                    'email': user.email,
                    'role': role,
                    'is_active': user.is_active,
                    'updated_at': user.date_joined.isoformat()
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '更新用户信息失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, user_id):
        """
        删除用户
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        # 解析用户ID
        if not user_id.startswith('user_'):
            return Response({
                'code': 400,
                'message': '无效的用户ID格式',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_pk = int(user_id[5:])  # 移除 'user_' 前缀
            user = User.objects.get(pk=user_pk)
        except (ValueError, User.DoesNotExist):
            return Response({
                'code': 404,
                'message': '用户不存在',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        # 防止删除最后一个管理员
        if user.is_superuser:
            admin_count = User.objects.filter(is_superuser=True).count()
            if admin_count <= 1:
                return Response({
                    'code': 400,
                    'message': '不能删除最后一个管理员',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # 删除用户相关的任务和漏洞记录
            ScanTask.objects.filter(created_by=user).delete()
            Vulnerability.objects.filter(task__created_by=user).delete()

            # 删除用户
            user.delete()

            return Response({
                'code': 200,
                'message': '用户删除成功',
                'data': {}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '删除用户失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminTaskViewSet(APIView, AdminRequiredMixin):
    """
    管理员任务管理视图集
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取所有任务列表（管理员视角）
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        try:
            # 分页参数
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
            offset = (page - 1) * page_size

            # 过滤参数
            status_filter = request.query_params.get('status_filter')
            user_filter = request.query_params.get('user_filter')

            # 构建查询
            tasks_query = ScanTask.objects.select_related('created_by').all()

            if status_filter:
                tasks_query = tasks_query.filter(status=status_filter)

            if user_filter:
                if user_filter.startswith('user_'):
                    try:
                        user_pk = int(user_filter[5:])
                        tasks_query = tasks_query.filter(created_by_id=user_pk)
                    except ValueError:
                        pass  # 无效的用户ID，忽略过滤
                else:
                    # 按用户名过滤
                    tasks_query = tasks_query.filter(created_by__username__icontains=user_filter)

            # 获取总数
            total = tasks_query.count()

            # 获取分页数据
            tasks = tasks_query.order_by('-created_at')[offset:offset + page_size]

            task_data = []
            for task in tasks:
                task_data.append({
                    'task_id': task.task_id,
                    'task_name': task.task_name,
                    'target_url': task.target_url,
                    'status': task.status,
                    'progress': task.progress,
                    'vulnerabilities_found': task.vulnerabilities_found,
                    'created_at': task.created_at.isoformat(),
                    'started_at': task.started_at.isoformat() if task.started_at else None,
                    'completed_at': task.completed_at.isoformat() if task.completed_at else None,
                    'created_by': {
                        'user_id': f'user_{task.created_by.id}',
                        'username': task.created_by.username
                    }
                })

            return Response({
                'code': 200,
                'message': 'Success',
                'data': {
                    'total': total,
                    'page': page,
                    'page_size': page_size,
                    'tasks': task_data
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '获取任务列表失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminTaskDetailView(APIView, AdminRequiredMixin):
    """
    管理员任务详情管理视图
    """
    permission_classes = [IsAuthenticated]

    def delete(self, request, task_id):
        """
        删除任务（管理员权限）
        """
        # 检查管理员权限
        permission_check = self.check_admin_permission(request)
        if permission_check:
            return permission_check

        try:
            task = ScanTask.objects.get(task_id=task_id)
        except ScanTask.DoesNotExist:
            return Response({
                'code': 404,
                'message': '任务不存在',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)

        try:
            # 删除关联的漏洞记录
            Vulnerability.objects.filter(task=task).delete()

            # 删除任务
            task.delete()

            return Response({
                'code': 200,
                'message': '任务删除成功',
                'data': {}
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'code': 500,
                'message': '删除任务失败',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)