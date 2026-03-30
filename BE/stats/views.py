"""
统计与监控模块视图
提供系统统计信息和图表数据的查询功能
"""
from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from scans.models import ScanTask, Vulnerability
from django.contrib.auth.models import User
import datetime


class SystemStatsView(APIView):
    """
    系统统计信息视图
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取系统整体运行统计和扫描概况

        返回:
        - 系统统计数据
        """
        # 计算总体统计
        total_scans = ScanTask.objects.count()
        total_vulnerabilities = Vulnerability.objects.count()
        critical_vulnerabilities = Vulnerability.objects.filter(risk_level='critical').count()
        active_tasks = ScanTask.objects.filter(status__in=['queued', 'running']).count()

        # 计算系统运行时间（从第一个任务开始计算）
        first_task = ScanTask.objects.order_by('created_at').first()
        system_uptime_hours = 0
        if first_task:
            uptime = timezone.now() - first_task.created_at
            system_uptime_hours = int(uptime.total_seconds() / 3600)

        # 用户统计
        total_users = User.objects.count()
        active_users = User.objects.filter(last_login__gte=timezone.now() - datetime.timedelta(days=30)).count()

        # 最近7天统计
        seven_days_ago = timezone.now() - datetime.timedelta(days=7)
        recent_scans = ScanTask.objects.filter(created_at__gte=seven_days_ago).count()
        recent_vulnerabilities = Vulnerability.objects.filter(detected_at__gte=seven_days_ago).count()

        return Response({
            'code': 200,
            'message': 'Statistics retrieved',
            'data': {
                'total_scans': total_scans,
                'vulnerabilities_found': total_vulnerabilities,
                'critical_vulnerabilities': critical_vulnerabilities,
                'active_tasks': active_tasks,
                'system_uptime_hours': system_uptime_hours,
                'total_users': total_users,
                'active_users': active_users,
                'recent_scans_7d': recent_scans,
                'recent_vulnerabilities_7d': recent_vulnerabilities
            }
        }, status=status.HTTP_200_OK)


class VulnerabilityChartsView(APIView):
    """
    漏洞统计图表数据视图
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """
        获取用于生成ECharts的漏洞统计数据

        查询参数:
        - chart_type: 图表类型
        - time_range: 时间范围
        - task_id: 任务ID (可选)

        返回:
        - 图表数据
        """
        chart_type = request.query_params.get('chart_type', 'risk_distribution')
        time_range = request.query_params.get('time_range', '30d')
        task_id = request.query_params.get('task_id')

        # 验证chart_type
        supported_types = ['risk_distribution', 'vulnerability_trend', 'module_statistics', 'top_vulnerabilities']
        if chart_type not in supported_types:
            return Response({
                'code': 400,
                'message': 'Invalid chart type',
                'data': {}
            }, status=status.HTTP_400_BAD_REQUEST)

        # 计算时间范围
        now = timezone.now()
        if time_range == '7d':
            start_date = now - datetime.timedelta(days=7)
        elif time_range == '30d':
            start_date = now - datetime.timedelta(days=30)
        elif time_range == '90d':
            start_date = now - datetime.timedelta(days=90)
        elif time_range == '1y':
            start_date = now - datetime.timedelta(days=365)
        else:
            start_date = now - datetime.timedelta(days=30)

        # 构建查询
        vulnerabilities = Vulnerability.objects.filter(detected_at__gte=start_date)
        if task_id:
            vulnerabilities = vulnerabilities.filter(task_id=task_id)

        data = self._generate_chart_data(chart_type, vulnerabilities, start_date, now)

        return Response({
            'code': 200,
            'message': 'Success',
            'data': {
                'chart_type': chart_type,
                'data': data,
                'time_range': time_range
            }
        }, status=status.HTTP_200_OK)

    def _generate_chart_data(self, chart_type, vulnerabilities, start_date, end_date):
        """生成图表数据"""
        if chart_type == 'risk_distribution':
            # 风险等级分布
            risk_counts = vulnerabilities.values('risk_level').annotate(
                count=Count('id')
            ).order_by('risk_level')

            labels = []
            values = []
            colors = []

            risk_colors = {
                'critical': '#ff4d4f',
                'high': '#ff7a45',
                'medium': '#faad14',
                'low': '#52c41a',
                'info': '#1890ff'
            }

            for item in risk_counts:
                labels.append(item['risk_level'].capitalize())
                values.append(item['count'])
                colors.append(risk_colors.get(item['risk_level'], '#1890ff'))

            return {
                'labels': labels,
                'values': values,
                'colors': colors
            }

        elif chart_type == 'vulnerability_trend':
            # 漏洞趋势（按天统计）
            trend_data = []
            current_date = start_date.date()

            while current_date <= end_date.date():
                next_date = current_date + datetime.timedelta(days=1)
                count = vulnerabilities.filter(
                    detected_at__date=current_date
                ).count()

                trend_data.append({
                    'date': current_date.isoformat(),
                    'count': count
                })

                current_date = next_date

            return {
                'trend': trend_data
            }

        elif chart_type == 'module_statistics':
            # 按模块统计漏洞数量
            module_stats = vulnerabilities.values('type').annotate(
                count=Count('id')
            ).order_by('-count')[:10]  # Top 10

            labels = []
            values = []

            for item in module_stats:
                labels.append(item['type'].replace('_', ' ').title())
                values.append(item['count'])

            return {
                'labels': labels,
                'values': values
            }

        elif chart_type == 'top_vulnerabilities':
            # 最常见的漏洞类型
            vuln_types = vulnerabilities.values('name').annotate(
                count=Count('id')
            ).order_by('-count')[:10]

            data = []
            for item in vuln_types:
                data.append({
                    'name': item['name'],
                    'count': item['count']
                })

            return {
                'vulnerabilities': data
            }

        return {}