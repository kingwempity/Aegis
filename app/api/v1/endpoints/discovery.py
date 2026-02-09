from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from typing import List, Optional
from datetime import datetime
import asyncio

from app.services.network_scanner import NetworkScanner
from app.db.database import get_db
from sqlalchemy.orm import Session
from app.models.discovery import DiscoveryResult
from app.schemas.discovery import DiscoveryCreate, DiscoveryResponse, TargetCreate, TargetResponse

router = APIRouter()
scanner = NetworkScanner()

# 扫描状态存储（实际应用中可以使用 Redis）
scanning_status = {
    "is_scanning": False,
    "progress": 0,
    "message": "",
    "started_at": None,
    "completed_at": None
}

# 模拟目标存储（实际应用中应使用数据库模型）
_mock_targets = [
    {"id": 1, "url": "192.168.10.156", "description": "内网测试服务器", "status": "active", "created_at": datetime.now()}
]

@router.post("/scan/start")
async def start_network_scan(
    background_tasks: BackgroundTasks,
    network_range: str = "192.168.1.0/24",
    db: Session = Depends(get_db)
):
    """
    启动网络扫描任务。
    """
    global scanning_status
    
    if scanning_status["is_scanning"]:
        raise HTTPException(status_code=400, detail="扫描任务正在进行中")
    
    # 更新扫描状态
    scanning_status = {
        "is_scanning": True,
        "progress": 0,
        "message": "正在初始化扫描...",
        "started_at": datetime.now(),
        "completed_at": None
    }
    
    # 在后台启动扫描任务
    background_tasks.add_task(perform_network_scan, network_range, db)
    
    return {
        "status": "started",
        "message": f"开始扫描网络 {network_range}",
        "task_id": str(datetime.now().timestamp())
    }

async def perform_network_scan(network_range: str, db: Session):
    """
    执行网络扫描的异步函数。
    """
    global scanning_status
    
    try:
        # 清除旧的扫描结果
        db.query(DiscoveryResult).filter(
            DiscoveryResult.network_range == network_range
        ).delete()
        db.commit()
        
        scanning_status["message"] = f"正在扫描 {network_range}"
        scanning_status["progress"] = 10
        
        # 执行扫描
        results = await scanner.scan_network(network_range)
        
        scanning_status["progress"] = 60
        scanning_status["message"] = "正在保存结果..."
        
        # 保存结果到数据库
        for idx, result in enumerate(results):
            discovery = DiscoveryResult(
                ip_address=result["ip"],
                hostname=result.get("hostname", ""),
                mac_address=result.get("mac", ""),
                open_ports=",".join(map(str, result.get("ports", []))),
                os_info=result.get("os", "Unknown"),
                services=",".join(result.get("services", [])),
                network_range=network_range,
                status="active",
                last_seen=datetime.now()
            )
            db.add(discovery)
            
            # 更新进度
            progress = 60 + (30 * (idx + 1) / len(results))
            scanning_status["progress"] = min(90, progress)
        
        db.commit()
        
        scanning_status["progress"] = 100
        scanning_status["message"] = f"扫描完成，发现 {len(results)} 台设备"
        scanning_status["completed_at"] = datetime.now()
        
    except Exception as e:
        scanning_status["message"] = f"扫描失败: {str(e)}"
        scanning_status["progress"] = 0
        raise
    finally:
        scanning_status["is_scanning"] = False

@router.get("/scan/status")
async def get_scan_status():
    """
    获取当前网络扫描任务的状态。
    """
    return scanning_status

@router.post("/scan/stop")
async def stop_network_scan():
    """
    停止当前网络扫描任务。
    """
    global scanning_status
    
    if not scanning_status["is_scanning"]:
        raise HTTPException(status_code=400, detail="没有正在进行的扫描任务")
    
    scanning_status["is_scanning"] = False
    scanning_status["message"] = "扫描已停止"
    
    return {"status": "stopped", "message": "扫描任务已停止"}

@router.delete("/results")
async def clear_discovery_results(db: Session = Depends(get_db)):
    """
    清除所有网络发现扫描结果。
    """
    try:
        count = db.query(DiscoveryResult).count()
        db.query(DiscoveryResult).delete()
        db.commit()
        return {"deleted": count, "message": f"已清除 {count} 条记录"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/assets", response_model=List[DiscoveryResponse])
async def get_assets(db: Session = Depends(get_db)):
    """
    获取所有已发现的资产列表。
    """
    results = db.query(DiscoveryResult).all()
    return [
        DiscoveryResponse(
            id=r.id,
            ip_address=r.ip_address,
            hostname=r.hostname,
            mac_address=r.mac_address,
            open_ports=[int(p) for p in r.open_ports.split(",")] if r.open_ports else [],
            os_info=r.os_info,
            services=[s for s in r.services.split(",")] if r.services else [],
            network_range=r.network_range,
            status=r.status,
            last_seen=r.last_seen,
            created_at=r.created_at,
            updated_at=r.updated_at
        )
        for r in results
    ]

@router.get("/targets", response_model=List[TargetResponse])
async def get_targets():
    """
    获取目标列表（兼容旧接口）。
    """
    return _mock_targets

@router.post("/targets", response_model=TargetResponse)
async def create_target(target_in: TargetCreate):
    """
    添加新目标（兼容旧接口）。
    """
    new_target = {
        "id": len(_mock_targets) + 1,
        "url": target_in.url,
        "description": target_in.description,
        "status": "active",
        "created_at": datetime.now()
    }
    _mock_targets.append(new_target)
    return new_target
