"""
扫描任务管理模块序列化器
提供模型数据的序列化功能
"""
import re
from rest_framework import serializers
from .models import ScanTask, Vulnerability, ScanResult, ScanLog


class ScanTaskSerializer(serializers.ModelSerializer):
    """
    扫描任务序列化器
    """
    created_by_username = serializers.CharField(
        source='created_by.username',
        read_only=True
    )
    duration_seconds = serializers.SerializerMethodField()

    class Meta:
        model = ScanTask
        fields = [
            'task_id', 'task_name', 'target_url', 'status', 'progress',
            'scan_profile', 'custom_modules', 'auth_token', 'auth_cookies',
            'max_depth', 'max_pages', 'timeout', 'user_agent', 'headers',
            'exclude_patterns', 'created_at', 'started_at', 'completed_at',
            'pages_scanned', 'vulnerabilities_found', 'created_by_username',
            'duration_seconds'
        ]
        read_only_fields = [
            'task_id', 'created_at', 'started_at', 'completed_at',
            'pages_scanned', 'vulnerabilities_found', 'created_by'
        ]

    def get_duration_seconds(self, obj):
        return obj.duration_seconds()

    def validate_target_url(self, value):
        """
        验证目标URL格式
        """
        if not re.match(r'^https?://', value):
            raise serializers.ValidationError("URL必须以http://或https://开头")

        # 检查URL长度
        if len(value) > 500:
            raise serializers.ValidationError("URL长度不能超过500字符")

        return value

    def validate_max_depth(self, value):
        """
        验证爬虫深度
        """
        if not (1 <= value <= 10):
            raise serializers.ValidationError("爬虫深度必须在1-10之间")
        return value

    def validate_max_pages(self, value):
        """
        验证最大页面数
        """
        if not (10 <= value <= 1000):
            raise serializers.ValidationError("最大页面数必须在10-1000之间")
        return value

    def validate_timeout(self, value):
        """
        验证超时时间
        """
        if not (10 <= value <= 300):
            raise serializers.ValidationError("超时时间必须在10-300秒之间")
        return value


class VulnerabilitySerializer(serializers.ModelSerializer):
    """
    漏洞信息序列化器
    """
    task_id = serializers.CharField(source='task.task_id', read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            'vulnerability_id', 'task_id', 'name', 'type', 'url', 'method',
            'parameter', 'payload', 'evidence', 'cvss_score', 'cvss_vector',
            'risk_level', 'description', 'remediation', 'references',
            'attack_steps', 'screenshots', 'detected_at'
        ]
        read_only_fields = [
            'vulnerability_id', 'task_id', 'detected_at'
        ]


class ScanResultSerializer(serializers.ModelSerializer):
    """
    扫描结果序列化器
    """
    task_id = serializers.CharField(source='task.task_id', read_only=True)

    class Meta:
        model = ScanResult
        fields = [
            'task_id', 'technology_stack', 'summary', 'report_data', 'generated_at'
        ]
        read_only_fields = ['task_id', 'generated_at']


class ScanLogSerializer(serializers.ModelSerializer):
    """
    扫描日志序列化器
    """
    task_id = serializers.CharField(source='task.task_id', read_only=True)

    class Meta:
        model = ScanLog
        fields = [
            'id', 'task_id', 'level', 'message', 'module', 'timestamp', 'extra_data'
        ]
        read_only_fields = ['id', 'task_id', 'timestamp']
