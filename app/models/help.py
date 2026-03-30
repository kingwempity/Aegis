"""
aegis.app.models.help
---------------------
帮助中心内容数据模型。

Author: Aegis Architect
Created: 2026-02-23
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from app.database import Base


class HelpContent(Base):
    """
    帮助内容表模型。
    
    Attributes:
        id (int): 主键 ID
        key (str): 内容唯一标识键（如 quick_start, scan_guide 等）
        title (str): 标题
        description (str): 简短描述
        content (str): 详细内容（支持 Markdown）
        icon (str): 图标名称
        icon_color (str): 图标颜色
        link (str): 跳转链接（可选）
        order (int): 排序顺序
        is_active (bool): 是否启用
        created_at (datetime): 创建时间
        updated_at (datetime): 更新时间
    """
    __tablename__ = "help_contents"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(100), nullable=False)
    description = Column(String(500), nullable=True)
    content = Column(Text, nullable=True)
    icon = Column(String(50), default="BookOpen")
    icon_color = Column(String(50), default="#ff6b00")
    link = Column(String(500), nullable=True)
    order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)