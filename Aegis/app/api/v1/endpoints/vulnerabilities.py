from fastapi import APIRouter
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

router = APIRouter()

class Vulnerability(BaseModel):
    id: int
    title: str
    severity: str
    target_url: str
    description: Optional[str] = None
    created_at: datetime

@router.get("/", response_model=List[Vulnerability])
async def get_vulnerabilities(severity: Optional[str] = None):
    # Mock 数据
    vulns = [
        {"id": 1, "title": "PHP allow_url_fopen enabled", "severity": "high", "target_url": "192.168.10.156", "created_at": datetime.now()},
        {"id": 2, "title": "PHP allow_url_include enabled", "severity": "high", "target_url": "192.168.10.156", "created_at": datetime.now()},
        {"id": 3, "title": "X-Frame-Options Header Not Set", "severity": "low", "target_url": "192.168.10.156", "created_at": datetime.now()},
    ]
    if severity:
        return [v for v in vulns if v["severity"] == severity]
    return vulns
