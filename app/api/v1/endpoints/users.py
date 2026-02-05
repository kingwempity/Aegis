from fastapi import APIRouter
from typing import List
from pydantic import BaseModel

router = APIRouter()

class User(BaseModel):
    id: int
    username: str
    email: str
    role: str
    status: str

@router.get("/", response_model=List[User])
async def get_users():
    return [
        {"id": 1, "username": "admin", "email": "admin@aegis.io", "role": "Administrator", "status": "Active"},
        {"id": 2, "username": "security_auditor", "email": "auditor@aegis.io", "role": "Auditor", "status": "Active"},
    ]
