from fastapi import APIRouter
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Dict, Optional

router = APIRouter()

class VulnStats(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class DashboardStats(BaseModel):
    running_scans: int
    pending_scans: int
    total_scans: int
    open_ports: int
    total_targets: int
    vulnerabilities: VulnStats

# 简单的内存缓存
_stats_cache: Optional[DashboardStats] = None
_last_cache_time: Optional[datetime] = None
CACHE_TTL = timedelta(seconds=10)  # 缓存 10 秒

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats():
    global _stats_cache, _last_cache_time
    
    now = datetime.now()
    if _stats_cache and _last_cache_time and (now - _last_cache_time) < CACHE_TTL:
        return _stats_cache

    # 模拟从数据库查询真实数据
    stats = DashboardStats(
        running_scans=0,
        pending_scans=0,
        total_scans=1,
        open_ports=10,
        total_targets=1,
        vulnerabilities=VulnStats(
            critical=0,
            high=8,
            medium=0,
            low=2
        )
    )
    
    _stats_cache = stats
    _last_cache_time = now
    return stats
