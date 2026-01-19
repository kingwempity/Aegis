"""
Aegis 数据库模型
----------------
定义扫描任务、漏洞、报告任务和扫描日志的数据结构。
支持完整的漏洞检测生命周期管理。

优化内容:
- 添加数据库索引以提升查询性能
- 使用更精确的字段类型和约束
- 添加模型实用方法
- 支持完整的OWASP漏洞分类
"""
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, DateTime, Enum, Integer, JSON, ForeignKey, Float, Index, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class ScanTask(Base):
    """扫描任务表 - 存储完整的扫描任务信息"""
    __tablename__ = "scan_tasks"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, index=True, comment="任务名称")
    target_url = Column(Text, nullable=False, comment="目标URL")

    # 任务状态
    status = Column(
        Enum("pending", "running", "completed", "failed", "stopped", "paused"),
        default="pending",
        index=True,
        comment="任务状态"
    )

    # 扫描配置
    scan_config = Column(JSON, comment="扫描配置参数")
    cookies = Column(Text, comment="登录Cookies")
    user_agent = Column(String(500), default="Aegis-Security-Scanner/1.0", comment="User-Agent")
    headers = Column(JSON, comment="自定义请求头")

    # 扫描控制参数
    max_qps = Column(Integer, default=5, comment="最大QPS限制")
    timeout = Column(Integer, default=30, comment="请求超时时间(秒)")
    max_retries = Column(Integer, default=3, comment="最大重试次数")
    follow_redirects = Column(Boolean, default=True, comment="是否跟随重定向")

    # 扫描进度
    progress = Column(Float, default=0.0, comment="扫描进度(0-100)")
    total_urls = Column(Integer, default=0, comment="发现的总URL数")
    scanned_urls = Column(Integer, default=0, comment="已扫描URL数")
    found_vulnerabilities = Column(Integer, default=0, comment="发现漏洞数")

    # 统计信息
    high_severity_count = Column(Integer, default=0, comment="高危漏洞数")
    medium_severity_count = Column(Integer, default=0, comment="中危漏洞数")
    low_severity_count = Column(Integer, default=0, comment="低危漏洞数")
    info_count = Column(Integer, default=0, comment="信息类漏洞数")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), index=True, comment="创建时间")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="更新时间")
    started_at = Column(DateTime, nullable=True, comment="开始扫描时间")
    completed_at = Column(DateTime, nullable=True, comment="完成时间")

    # 执行时间统计
    duration = Column(Integer, comment="扫描总耗时(秒)")

    # 错误信息
    error_message = Column(Text, comment="错误信息")

    # 关系
    vulnerabilities = relationship("Vulnerability", back_populates="task", cascade="all, delete-orphan")
    report_tasks = relationship("ReportTask", back_populates="task", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="task", cascade="all, delete-orphan")

    # 数据库索引
    __table_args__ = (
        Index('idx_scan_task_status_created', 'status', 'created_at'),
        Index('idx_scan_task_progress', 'progress'),
    )

    @property
    def is_completed(self) -> bool:
        """检查任务是否已完成"""
        return self.status in ['completed', 'failed', 'stopped']

    @property
    def is_running(self) -> bool:
        """检查任务是否正在运行"""
        return self.status == 'running'

    @property
    def duration_seconds(self) -> Optional[int]:
        """计算任务执行时长"""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at and self.is_running:
            return int((datetime.now() - self.started_at).total_seconds())
        return None

    @property
    def severity_stats(self) -> Dict[str, int]:
        """获取漏洞严重程度统计"""
        return {
            'critical': 0,  # 暂时不支持critical，等待后续扩展
            'high': self.high_severity_count,
            'medium': self.medium_severity_count,
            'low': self.low_severity_count,
            'info': self.info_count
        }

    def update_progress(self, scanned: int = None, total: int = None, progress: float = None):
        """更新扫描进度"""
        if scanned is not None:
            self.scanned_urls = scanned
        if total is not None:
            self.total_urls = total
        if progress is not None:
            self.progress = min(max(progress, 0.0), 100.0)
        else:
            # 自动计算进度
            if self.total_urls > 0:
                self.progress = min((self.scanned_urls / self.total_urls) * 100, 100.0)

    def add_vulnerability(self, severity: str):
        """增加漏洞计数"""
        self.found_vulnerabilities += 1
        if severity == 'high':
            self.high_severity_count += 1
        elif severity == 'medium':
            self.medium_severity_count += 1
        elif severity == 'low':
            self.low_severity_count += 1
        elif severity == 'info':
            self.info_count += 1

    def start_scan(self):
        """开始扫描"""
        self.status = 'running'
        self.started_at = datetime.now()
        self.progress = 0.0

    def complete_scan(self, error_message: str = None):
        """完成扫描"""
        self.completed_at = datetime.now()
        if error_message:
            self.status = 'failed'
            self.error_message = error_message
        else:
            self.status = 'completed'
        self.progress = 100.0
        self.duration = self.duration_seconds

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'name': self.name,
            'target_url': self.target_url,
            'status': self.status,
            'progress': self.progress,
            'total_urls': self.total_urls,
            'scanned_urls': self.scanned_urls,
            'found_vulnerabilities': self.found_vulnerabilities,
            'severity_stats': self.severity_stats,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.duration,
            'error_message': self.error_message
        }

    def __repr__(self):
        return f"<ScanTask(id={self.id}, name={self.name}, status={self.status}, progress={self.progress:.1f}%)>"


class Vulnerability(Base):
    """漏洞结果表 - 存储检测到的安全漏洞详情"""
    __tablename__ = "vulnerabilities"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)

    # 漏洞信息
    vuln_type = Column(String(100), nullable=False, index=True, comment="漏洞类型")
    title = Column(String(500), nullable=False, comment="漏洞标题")
    severity = Column(
        Enum("info", "low", "medium", "high", "critical"),
        default="medium",
        index=True,
        comment="严重程度"
    )

    # CWE信息 (扩展支持)
    cwe_id = Column(String(20), comment="CWE编号")
    cwe_name = Column(String(200), comment="CWE名称")

    # OWASP信息
    owasp_category = Column(String(100), comment="OWASP分类")

    # 发现位置
    url = Column(Text, nullable=False, comment="漏洞URL")
    matched_at = Column(String(255), comment="匹配位置")
    parameter = Column(String(255), comment="受影响的参数")
    method = Column(String(10), default="GET", comment="HTTP方法")

    # 攻击详情
    payload = Column(Text, comment="触发漏洞的Payload")
    plugin_id = Column(String(100), index=True, comment="检测插件ID")

    # 证据数据
    evidence = Column(JSON, comment="HTTP请求/响应证据")
    description = Column(Text, comment="漏洞描述")
    solution = Column(Text, comment="修复建议")
    references = Column(JSON, comment="参考链接")

    # 验证状态
    verified = Column(Boolean, default=True, comment="是否已验证")
    false_positive = Column(Boolean, default=False, comment="是否为误报")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), index=True, comment="发现时间")

    # 关系
    task = relationship("ScanTask", back_populates="vulnerabilities")

    # 数据库索引
    __table_args__ = (
        Index('idx_vuln_task_severity', 'task_id', 'severity'),
        Index('idx_vuln_type_severity', 'vuln_type', 'severity'),
        Index('idx_vuln_created_at', 'created_at'),
    )

    @property
    def severity_score(self) -> int:
        """获取严重程度分数"""
        scores = {
            'info': 1,
            'low': 2,
            'medium': 3,
            'high': 4,
            'critical': 5
        }
        return scores.get(self.severity, 1)

    @property
    def is_confirmed(self) -> bool:
        """检查漏洞是否已确认（非误报且已验证）"""
        return self.verified and not self.false_positive

    @property
    def evidence_summary(self) -> Dict[str, Any]:
        """获取证据摘要"""
        if not self.evidence:
            return {}

        evidence = self.evidence
        return {
            'request_method': evidence.get('method', self.method),
            'request_url': evidence.get('url', self.url),
            'response_status': evidence.get('status_code'),
            'response_length': len(evidence.get('response_body', '')),
            'matched_pattern': evidence.get('matched_pattern')
        }

    def mark_as_false_positive(self):
        """标记为误报"""
        self.false_positive = True
        self.verified = False

    def confirm_vulnerability(self):
        """确认漏洞有效性"""
        self.verified = True
        self.false_positive = False

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'task_id': self.task_id,
            'vuln_type': self.vuln_type,
            'title': self.title,
            'severity': self.severity,
            'severity_score': self.severity_score,
            'cwe_id': self.cwe_id,
            'cwe_name': self.cwe_name,
            'url': self.url,
            'parameter': self.parameter,
            'method': self.method,
            'payload': self.payload,
            'plugin_id': self.plugin_id,
            'evidence': self.evidence,
            'evidence_summary': self.evidence_summary,
            'description': self.description,
            'solution': self.solution,
            'references': self.references,
            'verified': self.verified,
            'false_positive': self.false_positive,
            'is_confirmed': self.is_confirmed,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type={self.vuln_type}, severity={self.severity}, confirmed={self.is_confirmed})>"


class ReportTask(Base):
    """报告生成任务表 - 支持异步报告生成"""
    __tablename__ = "report_tasks"

    # 基础信息
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)

    # 报告配置
    report_type = Column(
        Enum("json", "html", "markdown", "pdf"),
        default="html",
        comment="报告格式"
    )
    report_title = Column(String(255), comment="报告标题")
    include_evidence = Column(Boolean, default=True, comment="是否包含证据")
    include_logs = Column(Boolean, default=False, comment="是否包含扫描日志")

    # 生成状态
    status = Column(
        Enum("pending", "processing", "completed", "failed"),
        default="pending",
        index=True,
        comment="生成状态"
    )

    # 文件信息
    file_path = Column(String(500), comment="报告文件路径")
    file_name = Column(String(255), comment="报告文件名")
    file_size = Column(Integer, comment="文件大小(bytes)")
    download_url = Column(String(500), comment="下载链接")
    expires_at = Column(DateTime, comment="下载链接过期时间")

    # 生成统计
    total_vulnerabilities = Column(Integer, default=0, comment="包含的漏洞总数")
    generation_time = Column(Float, comment="生成耗时(秒)")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), index=True, comment="创建时间")
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), comment="更新时间")
    started_at = Column(DateTime, nullable=True, comment="开始生成时间")
    completed_at = Column(DateTime, nullable=True, comment="完成时间")

    # 错误信息
    error_message = Column(Text, comment="错误信息")

    # 关系
    task = relationship("ScanTask", back_populates="report_tasks")

    # 数据库索引
    __table_args__ = (
        Index('idx_report_task_status', 'task_id', 'status'),
        Index('idx_report_task_created', 'created_at'),
    )

    @property
    def is_completed(self) -> bool:
        """检查报告是否生成完成"""
        return self.status in ['completed', 'failed']

    @property
    def is_expired(self) -> bool:
        """检查下载链接是否过期"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

    @property
    def file_size_mb(self) -> float:
        """获取文件大小(MB)"""
        if self.file_size:
            return round(self.file_size / (1024 * 1024), 2)
        return 0.0

    def start_generation(self):
        """开始生成报告"""
        self.status = 'processing'
        self.started_at = datetime.now()

    def complete_generation(self, file_path: str = None, file_size: int = None, error_message: str = None):
        """完成报告生成"""
        self.completed_at = datetime.now()
        if error_message:
            self.status = 'failed'
            self.error_message = error_message
        else:
            self.status = 'completed'
            self.file_path = file_path
            self.file_size = file_size
            if self.started_at:
                self.generation_time = (self.completed_at - self.started_at).total_seconds()

        # 设置下载链接过期时间（7天后）
        from datetime import timedelta
        if self.status == 'completed':
            self.expires_at = self.completed_at + timedelta(days=7)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'task_id': self.task_id,
            'report_type': self.report_type,
            'report_title': self.report_title,
            'include_evidence': self.include_evidence,
            'include_logs': self.include_logs,
            'status': self.status,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_size_mb': self.file_size_mb,
            'download_url': self.download_url,
            'is_expired': self.is_expired,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'total_vulnerabilities': self.total_vulnerabilities,
            'generation_time': self.generation_time,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'error_message': self.error_message
        }

    def __repr__(self):
        return f"<ReportTask(id={self.id}, type={self.report_type}, status={self.status})>"


class ScanLog(Base):
    """扫描日志表 - 记录扫描过程中的详细日志"""
    __tablename__ = "scan_logs"

    # 使用自增ID以提升插入性能
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(36), ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)

    # 日志信息
    level = Column(
        Enum("debug", "info", "warning", "error"),
        default="info",
        index=True,
        comment="日志级别"
    )
    message = Column(Text, nullable=False, comment="日志消息")

    # 上下文信息
    url = Column(String(500), comment="相关URL")
    plugin_id = Column(String(100), index=True, comment="相关插件ID")
    vuln_type = Column(String(100), comment="相关漏洞类型")
    response_time = Column(Float, comment="响应时间(秒)")
    response_status = Column(Integer, comment="HTTP响应状态码")
    request_method = Column(String(10), comment="HTTP请求方法")

    # 性能指标
    bytes_sent = Column(Integer, comment="发送字节数")
    bytes_received = Column(Integer, comment="接收字节数")

    # 时间戳
    created_at = Column(DateTime, default=func.now(), index=True, comment="记录时间")

    # 关系
    task = relationship("ScanTask", back_populates="logs")

    # 数据库索引
    __table_args__ = (
        Index('idx_scan_log_task_level', 'task_id', 'level'),
        Index('idx_scan_log_created', 'created_at'),
        Index('idx_scan_log_plugin', 'plugin_id'),
    )

    @property
    def level_priority(self) -> int:
        """获取日志级别优先级"""
        priorities = {
            'debug': 1,
            'info': 2,
            'warning': 3,
            'error': 4
        }
        return priorities.get(self.level, 2)

    @property
    def is_error(self) -> bool:
        """检查是否为错误日志"""
        return self.level == 'error'

    @property
    def is_warning(self) -> bool:
        """检查是否为警告日志"""
        return self.level in ['warning', 'error']

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'id': self.id,
            'task_id': self.task_id,
            'level': self.level,
            'level_priority': self.level_priority,
            'message': self.message,
            'url': self.url,
            'plugin_id': self.plugin_id,
            'vuln_type': self.vuln_type,
            'response_time': self.response_time,
            'response_status': self.response_status,
            'request_method': self.request_method,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<ScanLog(id={self.id}, level={self.level}, message={self.message[:50]}...)>"