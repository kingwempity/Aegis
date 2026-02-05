from fastapi import APIRouter
from typing import List
from pydantic import BaseModel

router = APIRouter()

class ScanProfile(BaseModel):
    id: int
    name: str
    description: str
    is_default: bool

@router.get("/", response_model=List[ScanProfile])
async def get_profiles():
    return [
        {"id": 1, "name": "Full Scan", "description": "Comprehensive scan including all modules", "is_default": True},
        {"id": 2, "name": "Quick Scan", "description": "Fast scan focusing on critical vulnerabilities", "is_default": False},
        {"id": 3, "name": "XSS Only", "description": "Targeted scan for Cross-Site Scripting", "is_default": False},
    ]
