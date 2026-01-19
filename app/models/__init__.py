"""
Aegis 数据模型包
---------------
统一导出所有数据库模型类。
"""
from .task import ScanTask, Vulnerability, ReportTask, ScanLog

# 设置模型间的关系
ScanTask.vulnerabilities = ScanTask.__mapper__.relationships["vulnerabilities"]
ScanTask.report_tasks = ScanTask.__mapper__.relationships["report_tasks"]
ScanTask.logs = ScanTask.__mapper__.relationships["logs"]

# 导出所有模型类
__all__ = [
    "ScanTask",
    "Vulnerability",
    "ReportTask",
    "ScanLog"
]