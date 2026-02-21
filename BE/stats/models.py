from django.db import models
from django.utils import timezone


class Statistics(models.Model):
    """
    系统统计信息模型
    存储系统的统计数据
    """
    # 扫描统计
    total_scans = models.IntegerField(
        default=0,
        help_text="总扫描次数"
    )

    vulnerabilities_found = models.IntegerField(
        default=0,
        help_text="发现的漏洞总数"
    )

    critical_vulnerabilities = models.IntegerField(
        default=0,
        help_text="危急漏洞数量"
    )

    active_tasks = models.IntegerField(
        default=0,
        help_text="活跃任务数量"
    )

    system_uptime_hours = models.FloatField(
        default=0.0,
        help_text="系统运行时间（小时）"
    )

    # 更新时间
    last_updated = models.DateTimeField(
        default=timezone.now,
        help_text="最后更新时间"
    )

    # 元数据
    class Meta:
        verbose_name = '系统统计'
        verbose_name_plural = '系统统计'

    def __str__(self):
        return f"系统统计 - 更新于 {self.last_updated}"
