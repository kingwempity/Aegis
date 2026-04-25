"""
aegis.app.models.task
---------------------
定义扫描任务 (Task) 和 漏洞 (Vulnerability) 的数据库模型。

Author: Aegis Architect
Created: 2026-01-21
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database import Base  # <--- 关键修改：导入共享的 Base

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
    target_url = Column(String(255), nullable=False)
    status = Column(String(50), default="PENDING")
    scan_strategy = Column(String(50), default="default")
    target_paths = Column(JSON)
    target_vuln_types = Column(JSON)
    target_parameters = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    # 关联关系：一个任务包含多个漏洞
    vulnerabilities = relationship("Vulnerability", back_populates="task", cascade="all, delete-orphan")

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
    task_id = Column(Integer, ForeignKey("scan_tasks.id"))
    vuln_name = Column(String(100), nullable=False)
    severity = Column(String(20))
    url = Column(String(500))
    payload = Column(Text)
    evidence = Column(JSON)  # MySQL 8.0 原生 JSON 支持
    # 新增字段：攻击路径和详细漏洞信息
    attack_path = Column(JSON)  # 攻击路径信息（请求详情、攻击链步骤）
    vuln_type = Column(String(50))  # 漏洞类型
    parameter = Column(String(100))  # 注入参数名
    method = Column(String(10))  # HTTP 方法
    description = Column(Text)  # 漏洞描述
    remediation = Column(Text)  # 修复建议
    cvss_score = Column(Integer)  # CVSS 评分 (0-10)
    detected_at = Column(DateTime, default=datetime.now)  # 检测时间
    created_at = Column(DateTime, default=datetime.now)

    # 反向关联
    task = relationship("ScanTask", back_populates="vulnerabilities")
