"""
Aegis 数据库模型
----------------
定义扫描任务 (Task) 和 漏洞 (Vulnerability) 的数据结构。
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime

# 核心：必须从 app.database 导入统一的 Base
from app.database import Base

class ScanTask(Base):
    """扫描任务表"""
    __tablename__ = "scan_tasks"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(255), nullable=False)
    status = Column(String(50), default="PENDING")
    scan_strategy = Column(String(50), default="default")
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

    vulnerabilities = relationship("Vulnerability", back_populates="task")

class Vulnerability(Base):
    """漏洞结果表"""
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id"))
    vuln_name = Column(String(100), nullable=False)
    severity = Column(String(20))
    url = Column(String(500))
    payload = Column(Text)
    evidence = Column(JSON)
    created_at = Column(DateTime, default=datetime.now)

    task = relationship("ScanTask", back_populates="vulnerabilities")
