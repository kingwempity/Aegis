"""
Aegis 数据库模型
----------------
定义扫描任务、漏洞、报告任务和扫描日志的数据结构。
支持完整的漏洞检测生命周期管理。
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Text, DateTime, Enum, Integer, JSON, ForeignKey, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class ScanTask(Base):
    """扫描任务表 - 存储完整的扫描任务信息"""
    __tablename__ = "scan_tasks"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, comment="任务名称")
    target_url = Column(Text, nullable=False, comment="目标URL")

    # 任务状态
    status = Column(
        Enum("pending", "running", "completed", "failed", "stopped", "paused"),
        default="pending",
        comment="任务状态"
    )

    # 扫描配置
    scan_config = Column(JSON, comment="扫描配置参数")
    cookies = Column(Text, comment="登录Cookies")
    user_agent = Column(String(500), default="Aegis-Security-Scanner/1.0", comment="User-Agent")
    headers = Column(JSON, comment="自定义请求头")

    # 扫描进度
    progress = Column(Float, default=0.0, comment="扫描进度(0-100)")
    total_urls = Column(Integer, default=0, comment="发现的总URL数")
    scanned_urls = Column(Integer, default=0, comment="已扫描URL数")
    found_vulnerabilities = Column(Integer, default=0, comment="发现漏洞数")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), comment="创建时间")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="更新时间")
    started_at = Column(DateTime, nullable=True, comment="开始扫描时间")
    completed_at = Column(DateTime, nullable=True, comment="完成时间")

    # 错误信息
    error_message = Column(Text, comment="错误信息")

    # 关系
    vulnerabilities = relationship("Vulnerability", back_populates="task", cascade="all, delete-orphan")
    report_tasks = relationship("ReportTask", back_populates="task", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="task", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanTask(id={self.id}, name={self.name}, status={self.status}, progress={self.progress}%)>"


class Vulnerability(Base):
    """漏洞结果表 - 存储检测到的安全漏洞详情"""
    __tablename__ = "vulnerabilities"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False)

    # 漏洞信息
    vuln_type = Column(String(100), nullable=False, comment="漏洞类型")
    title = Column(String(500), nullable=False, comment="漏洞标题")
    severity = Column(
        Enum("info", "low", "medium", "high", "critical"),
        default="medium",
        comment="严重程度"
    )

    # 发现位置
    url = Column(Text, nullable=False, comment="漏洞URL")
    matched_at = Column(String(255), comment="匹配位置")

    # 攻击详情
    payload = Column(Text, comment="触发漏洞的Payload")
    plugin_id = Column(String(100), comment="检测插件ID")

    # 证据数据
    evidence = Column(JSON, comment="HTTP请求/响应证据")
    description = Column(Text, comment="漏洞描述")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), comment="发现时间")

    # 关系
    task = relationship("ScanTask", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type={self.vuln_type}, severity={self.severity})>"


class ReportTask(Base):
    """报告生成任务表 - 支持异步报告生成"""
    __tablename__ = "report_tasks"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False)

    # 报告配置
    report_type = Column(
        Enum("json", "html", "markdown", "pdf"),
        default="html",
        comment="报告格式"
    )
    report_title = Column(String(255), comment="报告标题")

    # 生成状态
    status = Column(
        Enum("pending", "processing", "completed", "failed"),
        default="pending",
        comment="生成状态"
    )

    # 文件信息
    file_path = Column(String(500), comment="报告文件路径")
    file_size = Column(Integer, comment="文件大小(bytes)")
    download_url = Column(String(500), comment="下载链接")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), comment="创建时间")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="更新时间")
    completed_at = Column(DateTime, nullable=True, comment="完成时间")

    # 错误信息
    error_message = Column(Text, comment="错误信息")

    # 关系
    task = relationship("ScanTask", back_populates="report_tasks")

    def __repr__(self):
        return f"<ReportTask(id={self.id}, type={self.report_type}, status={self.status})>"


class ScanLog(Base):
    """扫描日志表 - 记录扫描过程中的详细日志"""
    __tablename__ = "scan_logs"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False)

    # 日志信息
    level = Column(
        Enum("debug", "info", "warning", "error"),
        default="info",
        comment="日志级别"
    )
    message = Column(Text, nullable=False, comment="日志消息")

    # 上下文信息
    url = Column(String(500), comment="相关URL")
    plugin_id = Column(String(100), comment="相关插件ID")
    response_time = Column(Float, comment="响应时间(秒)")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), comment="记录时间")

    # 关系
    task = relationship("ScanTask", back_populates="logs")

    def __repr__(self):
        return f"<ScanLog(id={self.id}, level={self.level}, message={self.message[:50]}...)>"
