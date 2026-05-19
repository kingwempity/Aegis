"""
扫描执行事件模型 — 用于实时攻击执行界面回放与 WebSocket 推送。
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Index
from sqlalchemy.orm import relationship
from app.database import Base


class ScanExecutionEvent(Base):
    __tablename__ = "scan_execution_events"

    id = Column(Integer, primary_key=True, index=True)
    task_id = Column(Integer, ForeignKey("scan_tasks.id", ondelete="CASCADE"), nullable=False, index=True)
    seq = Column(Integer, nullable=False)
    event_type = Column(String(50), nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime, default=datetime.now)

    task = relationship("ScanTask", back_populates="execution_events")

    __table_args__ = (
        Index("ix_scan_execution_events_task_seq", "task_id", "seq", unique=True),
    )
