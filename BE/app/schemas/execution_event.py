from pydantic import BaseModel, Field
from typing import Any, Dict, List
from datetime import datetime


class ExecutionEventOut(BaseModel):
    id: int
    task_id: int
    seq: int
    event_type: str
    payload: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class ExecutionEventListOut(BaseModel):
    task_id: int
    events: List[ExecutionEventOut]
    next_after_seq: int
    has_more: bool
