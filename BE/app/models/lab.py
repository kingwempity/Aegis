"""
app.models.lab
--------------
漏洞实验室数据模型。

Author: Aegis Architect
Created: 2026-03-01
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import String, Text, JSON, Integer, DateTime, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import BIGINT

from app.database import Base


class LabScenario(Base):
    """
    漏洞场景模型。
    
    存储漏洞复现场景的基本信息、攻击步骤演示、修复方案等。
    
    Attributes:
        id: 主键
        name: 场景名称
        vuln_type: 漏洞类型（SQLI, XSS, CMD_INJECTION等）
        difficulty: 难度等级（easy, medium, hard）
        description: 场景描述
        attack_steps: 攻击步骤（JSON格式）
        remediation: 修复方案（JSON格式）
        learning: 学习资料（JSON格式）
        is_active: 是否启用
        is_auto_generated: 是否自动生成
        source_scan_task_id: 来源扫描任务 ID
        created_at: 创建时间
        updated_at: 更新时间
    """
    __tablename__ = "lab_scenarios"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, comment="场景名称")
    vuln_type: Mapped[str] = mapped_column(String(50), nullable=False, comment="漏洞类型")
    difficulty: Mapped[str] = mapped_column(String(20), default="easy", comment="难度等级")
    description: Mapped[str] = mapped_column(Text, nullable=True, comment="场景描述")
    
    # 攻击步骤演示（JSON格式）
    # 格式: [{"step": 1, "title": "...", "description": "...", "request": {...}, "response": {...}, ...}]
    attack_steps: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON, nullable=True, comment="攻击步骤"
    )
    
    # 修复方案（JSON格式）
    # 格式: [{"title": "...", "code": "...", "description": "..."}]
    remediation: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(
        JSON, nullable=True, comment="修复方案"
    )
    
    # 学习资料（JSON格式）
    # 格式: {"principle": "...", "cwe": "...", "owasp": "...", "references": [...]}
    learning: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        JSON, nullable=True, comment="学习资料"
    )
    
    # 标签（用于筛选）
    tags: Mapped[Optional[List[str]]] = mapped_column(
        JSON, nullable=True, comment="标签"
    )
    
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, comment="是否启用")
    is_auto_generated: Mapped[bool] = mapped_column(
        Boolean, default=False, comment="是否自动生成"
    )
    source_scan_task_id: Mapped[Optional[int]] = mapped_column(
        Integer, nullable=True, comment="来源扫描任务 ID"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now, comment="创建时间"
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.now, onupdate=datetime.now, comment="更新时间"
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式。
        
        Returns:
            字典格式的场景数据
        """
        return {
            "id": self.id,
            "name": self.name,
            "vuln_type": self.vuln_type,
            "difficulty": self.difficulty,
            "description": self.description,
            "attack_steps": self.attack_steps or [],
            "remediation": self.remediation or [],
            "learning": self.learning or {},
            "tags": self.tags or [],
            "is_active": self.is_active,
            "is_auto_generated": self.is_auto_generated,
            "source_scan_task_id": self.source_scan_task_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# 漏洞类型枚举
VULN_TYPES = {
    "SQLI": "SQL注入 (SQL Injection)",
    "XSS_REFLECTED": "反射型XSS (Reflected XSS)",
    "XSS_STORED": "存储型XSS (Stored XSS)",
    "CMD_INJECTION": "命令注入 (Command Injection)",
    "LFI": "本地文件包含 (Local File Inclusion)",
    "RFI": "远程文件包含 (Remote File Inclusion)",
    "SSRF": "服务端请求伪造 (SSRF)",
    "XXE": "XML外部实体注入 (XXE)",
    "PATH_TRAVERSAL": "路径穿越 (Path Traversal)",
    "INFO_DISCLOSURE": "敏感信息泄露 (Information Disclosure)",
    "OPEN_REDIRECT": "开放重定向 (Open Redirect)",
    "CSRF": "跨站请求伪造 (CSRF)",
}

# 难度等级
DIFFICULTY_LEVELS = {
    "easy": "初级",
    "medium": "中级",
    "hard": "高级",
}