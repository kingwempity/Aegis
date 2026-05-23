"""
aegis.app.models.task
---------------------
定义扫描任务 (Task) 和 漏洞 (Vulnerability) 的数据库模型。

性能优化：
- 为常用查询字段添加索引，加速查询
- task_id, severity, url, status, target_url 等字段均已建立索引
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from app.database import Base

class ScanTask(Base):
    """
    扫描任务表模型。
    
    Attributes:
        id (int): 主键 ID
        target_url (str): 扫描目标 URL
        status (str): 任务状态 (PENDING, RUNNING, COMPLETED, FAILED)
        scan_strategy (str): 扫描策略模式
        created_at (datetime): 创建时间
        updated_at (datetime): 更新时间
    """
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    display_id = Column(Integer, nullable=False, unique=True, index=True)
    target_url = Column(String(255), nullable=False, index=True)
    status = Column(String(50), default="PENDING", index=True)
    scan_strategy = Column(String(50), default="default")
    target_paths = Column(JSON)
    target_vuln_types = Column(JSON)
    target_parameters = Column(JSON)
    progress = Column(Integer, default=0)
    current_stage = Column(String(255), nullable=True)
    vulnerabilities_found = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    __table_args__ = (
        Index('ix_scan_tasks_status_created', 'status', 'created_at'),
    )

    vulnerabilities = relationship("Vulnerability", back_populates="task", cascade="all, delete-orphan")
    execution_events = relationship(
        "ScanExecutionEvent",
        back_populates="task",
        cascade="all, delete-orphan",
        order_by="ScanExecutionEvent.seq",
    )

class Vulnerability(Base):
    """
    漏洞结果表模型。
    
    Attributes:
        id (int): 主键 ID
        task_id (int): 关联的任务 ID
        vuln_name (str): 漏洞名称
        severity (str): 风险等级 (High, Medium, Low, Info)
        url (str): 发现漏洞的URL
        payload (str): 攻击载荷
        evidence (json): 原始 HTTP 请求/响应报文证据
        attack_path (json): 攻击路径信息，包含请求详情和攻击链
        vuln_type (str): 漏洞类型（如 XSS、SQLi、LFI 等）
        parameter (str): 注入参数名
        method (str): HTTP 方法
        description (str): 漏洞描述
        remediation (str): 修复建议
        cvss_score (float): CVSS 评分
        detected_at (datetime): 检测时间
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"), index=True)
    vuln_name = Column(String(100), nullable=False)
    severity = Column(String(20), index=True)
    url = Column(String(500), index=True)
    payload = Column(Text)
    evidence = Column(JSON)
    attack_path = Column(JSON)
    vuln_type = Column(String(50))
    parameter = Column(String(100))
    method = Column(String(10))
    description = Column(Text)
    remediation = Column(Text)
    cvss_score = Column(Integer)
    detected_at = Column(DateTime, default=datetime.now)
    created_at = Column(DateTime, default=datetime.now, index=True)

    __table_args__ = (
        Index('ix_vulnerabilities_task_severity', 'task_id', 'severity'),
        Index('ix_vulnerabilities_severity_created', 'severity', 'created_at'),
    )

    task = relationship("ScanTask", back_populates="vulnerabilities")
