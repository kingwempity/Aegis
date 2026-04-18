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
import json


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

            attack_steps = vulnerability.attack_steps or []
            evidence = vulnerability.evidence
            if isinstance(evidence, str):
                try:
                    evidence = json.loads(evidence)
                except Exception:
                    evidence = {"raw": evidence}
            elif evidence is None:
                evidence = {}

            request_data = {
                'method': vulnerability.method,
                'url': vulnerability.url,
                'headers': {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Aegis-Security-Scanner/2.0'
                },
                'timestamp': vulnerability.detected_at.isoformat()
            }
            response_data = {
                'status_code': None,
                'headers': {},
                'response_time_ms': None,
                'timestamp': vulnerability.detected_at.isoformat(),
                'body': ''
            }
            exploitation_result = {
                'successful': bool(attack_steps or evidence),
                'data_extracted': '',
                'tables_discovered': [],
                'attack_status': None,
                'artifacts': [],
            }
            attack_chain = []

            if attack_steps:
                final_step = attack_steps[-1]
                request_data = {
                    'method': final_step.get('method') or vulnerability.method,
                    'url': final_step.get('url') or vulnerability.url,
                    'headers': final_step.get('request_headers') or request_data['headers'],
                    'body': final_step.get('request_body'),
                    'timestamp': vulnerability.detected_at.isoformat(),
                }
                response_data = {
                    'status_code': final_step.get('response_code'),
                    'headers': final_step.get('response_headers') or {},
                    'response_time_ms': final_step.get('response_time_ms'),
                    'timestamp': vulnerability.detected_at.isoformat(),
                    'body': final_step.get('response_body') or final_step.get('response_snippet') or '',
                }
                exploitation_result['data_extracted'] = " -> ".join([
                    step.get('action') or step.get('stage_name') or f"阶段 {idx + 1}"
                    for idx, step in enumerate(attack_steps)
                ])
                exploitation_result['artifacts'] = [
                    step.get('extracted', {})
                    for step in attack_steps
                    if step.get('extracted')
                ]
                attack_chain = [
                    {
                        'step': idx + 1,
                        'stage_id': step.get('stage_id'),
                        'stage_name': step.get('stage_name'),
                        'stage_title': step.get('stage_title'),
                        'stage_goal': step.get('stage_goal'),
                        'action': step.get('action') or step.get('stage_title') or step.get('stage_name') or f'阶段 {idx + 1}',
                        'success': step.get('success'),
                        'matched_conditions': step.get('matched_conditions', []),
                        'artifacts': step.get('artifacts', []),
                        'extracted': step.get('extracted', {}),
                        'request': {
                            'method': step.get('method') or vulnerability.method,
                            'url': step.get('url') or vulnerability.url,
                            'headers': step.get('request_headers') or {},
                            'body': step.get('request_body'),
                        },
                        'response': {
                            'status_code': step.get('response_code'),
                            'headers': step.get('response_headers') or {},
                            'response_time_ms': step.get('response_time_ms'),
                            'body': step.get('response_body') or step.get('response_snippet') or '',
                        },
                    }
                    for idx, step in enumerate(attack_steps)
                ]
                if evidence.get('framework_validation'):
                    exploitation_result['attack_status'] = (
                        'validated' if evidence['framework_validation'].get('is_valid') else 'suppressed'
                    )
            else:
                if vulnerability.method == 'POST' and vulnerability.parameter:
                    request_data['body'] = f"{vulnerability.parameter}={vulnerability.payload}"
                response_data['status_code'] = evidence.get('response_status')
                response_data['response_time_ms'] = evidence.get('response_time_ms')
                response_data['body'] = evidence.get('body_snippet', '')

            if evidence.get('attack_artifacts'):
                exploitation_result['artifacts'] = evidence.get('attack_artifacts', [])
            if evidence.get('framework_validation'):
                exploitation_result['attack_status'] = (
                    'validated' if evidence['framework_validation'].get('is_valid') else 'suppressed'
                )

            data = {
                'vulnerability_id': vulnerability.vulnerability_id,
                'request': request_data,
                'response': response_data,
                'exploitation_result': exploitation_result,
                'attack_chain': attack_chain or attack_steps,
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
