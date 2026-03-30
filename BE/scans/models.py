"""
扫描任务管理模块数据模型
定义扫描任务、漏洞信息等核心数据结构
"""
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
import uuid
from django.utils.crypto import get_random_string


class ScanTask(models.Model):
    """
    扫描任务模型
    存储Web应用漏洞扫描任务的基本信息和配置
    """
    # 任务状态枚举
    STATUS_CHOICES = [
        ('queued', '等待执行'),
        ('running', '执行中'),
        ('paused', '已暂停'),
        ('completed', '已完成'),
        ('failed', '执行失败'),
        ('cancelled', '已取消'),
    ]

    # 扫描配置模板
    SCAN_PROFILE_CHOICES = [
        ('quick', '快速扫描'),
        ('full', '完整扫描'),
        ('custom', '自定义扫描'),
    ]

    # 任务唯一标识
    task_id = models.CharField(
        max_length=50,
        unique=True,
        help_text="任务唯一标识符"
    )

    # 任务基本信息
    task_name = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="任务名称，可选"
    )

    # 目标信息
    target_url = models.URLField(
        max_length=500,
        help_text="目标Web应用的完整URL"
    )

    # 任务状态
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='queued',
        help_text="任务当前状态"
    )

    # 进度信息
    progress = models.IntegerField(
        default=0,
        help_text="扫描进度百分比 (0-100)"
    )

    # 扫描配置
    scan_profile = models.CharField(
        max_length=20,
        choices=SCAN_PROFILE_CHOICES,
        default='full',
        help_text="扫描配置模板"
    )

    # 自定义模块配置 (JSON格式存储)
    custom_modules = models.JSONField(
        blank=True,
        null=True,
        help_text="自定义启用的检测模块列表"
    )

    # 认证信息
    auth_token = models.TextField(
        blank=True,
        null=True,
        help_text="用于认证的会话Token"
    )
    auth_cookies = models.TextField(
        blank=True,
        null=True,
        help_text="用于认证的Cookie字符串"
    )

    # 扫描参数
    max_depth = models.IntegerField(
        default=5,
        help_text="爬虫最大深度 (1-10)"
    )
    max_pages = models.IntegerField(
        default=100,
        help_text="最大扫描页面数 (10-1000)"
    )
    timeout = models.IntegerField(
        default=30,
        help_text="请求超时时间(秒)"
    )
    user_agent = models.TextField(
        blank=True,
        null=True,
        help_text="自定义User-Agent"
    )
    headers = models.JSONField(
        blank=True,
        null=True,
        help_text="自定义HTTP请求头"
    )
    exclude_patterns = models.JSONField(
        blank=True,
        null=True,
        help_text="排除的URL模式(正则表达式)"
    )

    # 时间信息
    created_at = models.DateTimeField(
        default=timezone.now,
        help_text="任务创建时间"
    )
    started_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="任务开始执行时间"
    )
    completed_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="任务完成时间"
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        help_text="最后更新时间"
    )

    # 统计信息
    pages_scanned = models.IntegerField(
        default=0,
        help_text="已扫描页面数"
    )
    vulnerabilities_found = models.IntegerField(
        default=0,
        help_text="发现的漏洞总数"
    )

    # 关联信息
    created_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='scan_tasks',
        help_text="任务创建者"
    )

    # 元数据
    class Meta:
        ordering = ['-created_at']
        verbose_name = '扫描任务'
        verbose_name_plural = '扫描任务'
        indexes = [
            models.Index(fields=['task_id']),
            models.Index(fields=['status']),
            models.Index(fields=['created_by']),
            models.Index(fields=['created_at']),
        ]

    def save(self, *args, **kwargs):
        """保存时自动生成task_id"""
        if not self.task_id:
            self.task_id = f"task_{timezone.now().strftime('%Y%m%d')}_{uuid.uuid4().hex[:6]}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.task_id} - {self.target_url}"

    def duration_seconds(self):
        """
        计算任务执行时长（秒）
        """
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at:
            return int((timezone.now() - self.started_at).total_seconds())
        return 0

    def can_cancel(self):
        """
        检查任务是否可以取消
        """
        return self.status in ['queued', 'running', 'paused']

    def mark_started(self):
        """
        标记任务开始执行
        """
        self.status = 'running'
        self.started_at = timezone.now()
        self.save(update_fields=['status', 'started_at'])

    def mark_completed(self):
        """
        标记任务完成
        """
        self.status = 'completed'
        self.progress = 100
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'progress', 'completed_at'])

    def mark_failed(self, error_message=None):
        """
        标记任务失败
        """
        self.status = 'failed'
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at'])

    def mark_cancelled(self):
        """
        标记任务取消
        """
        self.status = 'cancelled'
        self.completed_at = timezone.now()
        self.save(update_fields=['status', 'completed_at'])


class Vulnerability(models.Model):
    """
    漏洞信息模型
    存储检测到的具体漏洞信息
    """
    # 风险等级枚举
    RISK_LEVEL_CHOICES = [
        ('info', '信息'),
        ('low', '低危'),
        ('medium', '中危'),
        ('high', '高危'),
        ('critical', '危急'),
    ]

    # HTTP方法枚举
    HTTP_METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE'),
        ('HEAD', 'HEAD'),
        ('OPTIONS', 'OPTIONS'),
        ('PATCH', 'PATCH'),
    ]

    # 漏洞唯一标识
    vulnerability_id = models.CharField(
        max_length=50,
        unique=True,
        help_text="漏洞唯一标识符"
    )

    # 关联任务
    task = models.ForeignKey(
        ScanTask,
        on_delete=models.CASCADE,
        related_name='vulnerabilities',
        help_text="关联的扫描任务"
    )

    # 漏洞基本信息
    name = models.CharField(
        max_length=200,
        help_text="漏洞名称"
    )
    type = models.CharField(
        max_length=100,
        help_text="漏洞类型"
    )

    # 发现位置
    url = models.URLField(
        max_length=500,
        help_text="漏洞发现URL"
    )
    method = models.CharField(
        max_length=10,
        choices=HTTP_METHOD_CHOICES,
        default='GET',
        help_text="HTTP请求方法"
    )
    parameter = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="涉及的参数名"
    )

    # 攻击信息
    payload = models.TextField(
        blank=True,
        null=True,
        help_text="攻击载荷"
    )
    evidence = models.TextField(
        blank=True,
        null=True,
        help_text="漏洞证据"
    )

    # 风险评估
    cvss_score = models.FloatField(
        default=0.0,
        help_text="CVSS评分 (0.0-10.0)"
    )
    cvss_vector = models.CharField(
        max_length=200,
        blank=True,
        null=True,
        help_text="CVSS向量字符串"
    )
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        default='info',
        help_text="风险等级"
    )

    # 修复信息
    description = models.TextField(
        blank=True,
        null=True,
        help_text="漏洞详细描述"
    )
    remediation = models.TextField(
        blank=True,
        null=True,
        help_text="修复建议"
    )
    references = models.JSONField(
        blank=True,
        null=True,
        help_text="参考链接列表"
    )

    # 检测信息
    detected_at = models.DateTimeField(
        default=timezone.now,
        help_text="漏洞检测时间"
    )

    # 攻击过程记录
    attack_steps = models.JSONField(
        blank=True,
        null=True,
        help_text="攻击过程步骤记录"
    )

    # 截图和证据文件
    screenshots = models.JSONField(
        blank=True,
        null=True,
        help_text="截图文件信息"
    )

    # 元数据
    class Meta:
        ordering = ['-detected_at']
        verbose_name = '漏洞'
        verbose_name_plural = '漏洞'
        indexes = [
            models.Index(fields=['vulnerability_id']),
            models.Index(fields=['task']),
            models.Index(fields=['type']),
            models.Index(fields=['risk_level']),
            models.Index(fields=['cvss_score']),
            models.Index(fields=['detected_at']),
        ]

    def save(self, *args, **kwargs):
        """保存时自动生成vulnerability_id"""
        if not self.vulnerability_id:
            self.vulnerability_id = f"vuln_{uuid.uuid4().hex[:8]}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.vulnerability_id} - {self.name}"

    def get_cvss_severity(self):
        """
        根据CVSS评分获取严重程度
        """
        score = self.cvss_score
        if score >= 9.0:
            return 'critical'
        elif score >= 7.0:
            return 'high'
        elif score >= 4.0:
            return 'medium'
        elif score >= 0.1:
            return 'low'
        else:
            return 'info'


class ScanResult(models.Model):
    """
    扫描结果模型
    存储扫描任务的详细结果和统计信息
    """
    task = models.OneToOneField(
        ScanTask,
        on_delete=models.CASCADE,
        related_name='result',
        help_text="关联的扫描任务"
    )

    # 技术栈识别结果
    technology_stack = models.JSONField(
        blank=True,
        null=True,
        help_text="识别出的技术栈信息"
    )

    # 扫描统计
    summary = models.JSONField(
        default=dict,
        help_text="扫描结果统计摘要"
    )

    # 完整报告数据
    report_data = models.JSONField(
        blank=True,
        null=True,
        help_text="完整的扫描报告数据"
    )

    # 生成时间
    generated_at = models.DateTimeField(
        default=timezone.now,
        help_text="报告生成时间"
    )

    # 元数据
    class Meta:
        verbose_name = '扫描结果'
        verbose_name_plural = '扫描结果'
        indexes = [
            models.Index(fields=['task']),
            models.Index(fields=['generated_at']),
        ]

    def __str__(self):
        return f"Result for {self.task.task_id}"


class ScanLog(models.Model):
    """
    扫描日志模型
    记录扫描过程中的详细日志信息
    """
    # 日志级别枚举
    LEVEL_CHOICES = [
        ('DEBUG', '调试'),
        ('INFO', '信息'),
        ('WARNING', '警告'),
        ('ERROR', '错误'),
        ('CRITICAL', '严重'),
    ]

    task = models.ForeignKey(
        ScanTask,
        on_delete=models.CASCADE,
        related_name='logs',
        help_text="关联的扫描任务"
    )

    level = models.CharField(
        max_length=10,
        choices=LEVEL_CHOICES,
        default='INFO',
        help_text="日志级别"
    )

    message = models.TextField(
        help_text="日志消息"
    )

    module = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="产生日志的模块"
    )

    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="日志时间戳"
    )

    # 额外数据
    extra_data = models.JSONField(
        blank=True,
        null=True,
        help_text="额外的日志数据"
    )

    # 元数据
    class Meta:
        ordering = ['-timestamp']
        verbose_name = '扫描日志'
        verbose_name_plural = '扫描日志'
        indexes = [
            models.Index(fields=['task']),
            models.Index(fields=['level']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['module']),
        ]

    def __str__(self):
        return f"[{self.level}] {self.task.task_id}: {self.message[:50]}"
