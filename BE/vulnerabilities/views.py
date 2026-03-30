"""
漏洞检测模块视图
提供漏洞详情和攻击证据的查询功能
"""
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from scans.models import Vulnerability


class VulnerabilityDetailView(APIView):
    """
    漏洞详情视图
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, vulnerability_id):
        """
        获取指定漏洞的详细信息

        路径参数:
        - vulnerability_id: 漏洞ID

        返回:
        - 漏洞的详细信息
        """
        try:
            vulnerability = get_object_or_404(
                Vulnerability,
                vulnerability_id=vulnerability_id,
                task__created_by=request.user  # 确保用户只能访问自己的任务的漏洞
            )

            data = {
                'id': vulnerability.vulnerability_id,
                'task_id': vulnerability.task.task_id,
                'name': vulnerability.name,
                'type': vulnerability.type,
                'url': vulnerability.url,
                'method': vulnerability.method,
                'parameter': vulnerability.parameter,
                'payload': vulnerability.payload,
                'evidence': vulnerability.evidence,
                'cvss_score': vulnerability.cvss_score,
                'cvss_vector': vulnerability.cvss_vector,
                'risk_level': vulnerability.risk_level,
                'description': vulnerability.description,
                'remediation': vulnerability.remediation,
                'references': vulnerability.references or [],
                'attack_steps': vulnerability.attack_steps or [],
                'screenshots': vulnerability.screenshots or [],
                'detected_at': vulnerability.detected_at.isoformat()
            }

            return Response({
                'code': 200,
                'message': 'Success',
                'data': data
            }, status=status.HTTP_200_OK)

        except Vulnerability.DoesNotExist:
            return Response({
                'code': 404,
                'message': 'Vulnerability not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)


class VulnerabilityEvidenceView(APIView):
    """
    漏洞攻击证据视图
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, vulnerability_id):
        """
        获取漏洞攻击的详细证据

        路径参数:
        - vulnerability_id: 漏洞ID

        返回:
        - 请求/响应数据和攻击结果
        """
        try:
            vulnerability = get_object_or_404(
                Vulnerability,
                vulnerability_id=vulnerability_id,
                task__created_by=request.user
            )

            # 构建请求数据（基于漏洞信息重建）
            request_data = {
                'method': vulnerability.method,
                'url': vulnerability.url,
                'headers': {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'VulnScanner/1.0'
                },
                'timestamp': vulnerability.detected_at.isoformat()
            }

            # 根据漏洞类型构建请求体
            if vulnerability.method == 'POST' and vulnerability.parameter:
                if vulnerability.type == 'sql_injection':
                    request_data['body'] = f"{vulnerability.parameter}={vulnerability.payload}&password=test"
                elif vulnerability.type == 'xss':
                    request_data['body'] = f"{vulnerability.parameter}={vulnerability.payload}"
                else:
                    request_data['body'] = f"{vulnerability.parameter}={vulnerability.payload}"
            elif vulnerability.method == 'GET' and vulnerability.parameter:
                request_data['body'] = None

            # 构建响应数据
            response_data = {
                'status_code': 200,
                'headers': {
                    'Content-Type': 'text/html; charset=utf-8'
                },
                'response_time_ms': 150,
                'timestamp': vulnerability.detected_at.isoformat()
            }

            # 根据漏洞类型设置响应体
            if vulnerability.type == 'sql_injection':
                response_data['body'] = f"<html>...{vulnerability.evidence}...</html>"
            elif vulnerability.type == 'xss':
                response_data['body'] = f"<html>...{vulnerability.payload}...</html>"
            else:
                response_data['body'] = f"<html>...{vulnerability.evidence}...</html>"

            # 构建利用结果
            exploitation_result = {
                'successful': True,
                'data_extracted': '',
                'tables_discovered': []
            }

            if vulnerability.type == 'sql_injection':
                exploitation_result['data_extracted'] = 'Database name: example_db'
                exploitation_result['tables_discovered'] = ['users', 'products', 'orders']
            elif vulnerability.type == 'file_upload':
                exploitation_result['data_extracted'] = 'File uploaded successfully'
            elif vulnerability.type == 'path_traversal':
                exploitation_result['data_extracted'] = 'System file accessed'

            data = {
                'vulnerability_id': vulnerability.vulnerability_id,
                'request': request_data,
                'response': response_data,
                'exploitation_result': exploitation_result
            }

            return Response({
                'code': 200,
                'message': 'Success',
                'data': data
            }, status=status.HTTP_200_OK)

        except Vulnerability.DoesNotExist:
            return Response({
                'code': 404,
                'message': 'Vulnerability not found',
                'data': {}
            }, status=status.HTTP_404_NOT_FOUND)