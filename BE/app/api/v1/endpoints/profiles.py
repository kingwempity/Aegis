from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel

router = APIRouter()

class ScanProfile(BaseModel):
    id: int
    name: str
    description: str
    is_default: bool
    speed: Optional[str] = "standard"
    vulnerability_types: Optional[List[str]] = []

class ProfileCreate(BaseModel):
    name: str
    description: str
    speed: str = "standard"
    vulnerability_types: List[str] = []

# 模拟数据库
db_profiles = [
    {"id": 1, "name": "Full Scan", "description": "Comprehensive scan including all modules", "is_default": True, "speed": "standard", "vulnerability_types": ["SQLi", "XSS", "LFI", "RCE"]},
    {"id": 2, "name": "Quick Scan", "description": "Fast scan focusing on critical vulnerabilities", "is_default": False, "speed": "fast", "vulnerability_types": ["SQLi", "XSS"]},
    {"id": 3, "name": "XSS Only", "description": "Targeted scan for Cross-Site Scripting", "is_default": False, "speed": "standard", "vulnerability_types": ["XSS"]},
]

@router.get("", response_model=List[ScanProfile])
@router.get("/", response_model=List[ScanProfile])
async def get_profiles():
    return db_profiles

@router.post("/", response_model=ScanProfile)
async def create_profile(profile: ProfileCreate):
    new_id = max([p["id"] for p in db_profiles]) + 1 if db_profiles else 1
    new_profile = {
        "id": new_id,
        "name": profile.name,
        "description": profile.description,
        "is_default": False,
        "speed": profile.speed,
        "vulnerability_types": profile.vulnerability_types
    }
    db_profiles.append(new_profile)
    return new_profile
