from fastapi import APIRouter, HTTPException
from typing import List, Optional
from pydantic import BaseModel

router = APIRouter()

class User(BaseModel):
    id: int
    username: str
    email: str
    role: str
    status: str

class UserCreate(BaseModel):
    username: str
    email: str
    role: str
    status: str = "Active"

# 模拟数据库存储
_mock_users = [
    {"id": 1, "username": "admin", "email": "admin@aegis.io", "role": "Administrator", "status": "Active"},
    {"id": 2, "username": "security_auditor", "email": "auditor@aegis.io", "role": "Auditor", "status": "Active"},
]

@router.get("/", response_model=List[User])
async def get_users():
    return _mock_users

@router.post("/", response_model=User)
async def create_user(user_in: UserCreate):
    # 检查用户名是否已存在
    if any(u["username"] == user_in.username for u in _mock_users):
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_user = {
        "id": len(_mock_users) + 1,
        "username": user_in.username,
        "email": user_in.email,
        "role": user_in.role,
        "status": user_in.status
    }
    _mock_users.append(new_user)
    return new_user
