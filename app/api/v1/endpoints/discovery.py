"""
aegis.app.api.v1.endpoints.discovery
------------------------------------
资产发现与目标管理 API。

Author: Aegis Architect
Created: 2026-01-21
"""

from fastapi import APIRouter, HTTPException, Depends, status
from typing import List, Optional
from datetime import datetime
import asyncio
import logging
import ipaddress
import os

from app.services.network_scanner import NetworkScanner
from app.db.database import get_db, SessionLocal
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.discovery import DiscoveryResult
from app.models.task import ScanTask, Vulnerability
from app.schemas.discovery import DiscoveryCreate, DiscoveryResponse, TargetCreate, TargetResponse

router = APIRouter()
scanner = NetworkScanner()

# 配置日志
logger = logging.getLogger(__name__)

# 扫描状态存储（实际应用中可以使用 Redis）
scanning_status = {
    "is_scanning": False,
    "progress": 0,
    "message": "",
    "started_at": None,
    "completed_at": None
}

# 云服务器/Docker 部署时可通过环境变量指定默认扫描网段；无法用 VPC 时用 172.17.0.0/24 可扫 Docker 内网
DISCOVERY_DEFAULT_NETWORK_RANGE = os.getenv("DISCOVERY_DEFAULT_NETWORK_RANGE", "172.17.0.0/24")

# 模拟目标存储（实际应用中应使用数据库模型）
_mock_targets = [
    {"id": 1, "url": "192.168.10.156", "description": "内网测试服务器", "status": "active", "created_at": datetime.now()}
]


@router.get("/suggested-range")
async def get_suggested_network_range():
    """
    返回建议的扫描网段。部署在 Docker 时默认 172.17.0.0/24（Docker 桥接网段），可发现本机网关及同主机容器；
    若能使用 VPC，可在环境变量中设置 DISCOVERY_DEFAULT_NETWORK_RANGE 为 VPC 网段。
    """
    return {"network_range": DISCOVERY_DEFAULT_NETWORK_RANGE}


@router.post("/scan/start", status_code=status.HTTP_202_ACCEPTED)
async def start_network_scan(
    network_range: str = "192.168.1.0/24",
    force: bool = False, # 新增 force 参数
):
    """
    启动网络扫描任务。
    如果 force 为 True，则强制启动新扫描，停止当前正在进行的扫描。
    """
    global scanning_status
    
    # 先做参数校验，提前返回明确错误
    try:
        ipaddress.ip_network(network_range, strict=False)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="无效的网段格式，请使用例如 192.168.1.0/24")

    if scanning_status["is_scanning"]:
        if force:
            logger.warning(f"强制停止当前扫描任务以启动新扫描: {network_range}")
            # 停止当前扫描（这里只是标记，实际的后台任务需要更复杂的取消机制）
            scanning_status["is_scanning"] = False
            scanning_status["message"] = "当前扫描被强制停止"
            # 给予一点时间让旧任务结束（如果可能）
            await asyncio.sleep(1)
        else:
            logger.info(f"扫描任务已在进行中，忽略重复启动请求: {network_range}")
            return {
                "status": "already_running",
                "message": f"扫描任务正在进行中: {network_range}",
                "task_id": str(scanning_status["started_at"].timestamp()) if scanning_status["started_at"] else "",
            }
    
    # 更新扫描状态
    scanning_status = {
        "is_scanning": True,
        "progress": 0,
        "message": "正在初始化扫描...",
        "started_at": datetime.now(),
        "completed_at": None
    }
    
    logger.info(f"开始后台网络扫描任务: {network_range}")
    # 异步启动扫描任务，避免阻塞请求处理线程
    asyncio.create_task(perform_network_scan(network_range))
    
    return {
        "status": "started",
        "message": f"开始扫描网络 {network_range}",
        "task_id": str(datetime.now().timestamp())
    }

async def perform_network_scan(network_range: str):
    """
    执行网络扫描的异步函数。
    """
    global scanning_status
    
    # 检查是否被强制停止
    if not scanning_status["is_scanning"]:
        logger.info(f"扫描任务 {network_range} 被取消或强制停止前启动。")
        return

    db = SessionLocal()
    try:
        logger.info(f"正在执行网络扫描: {network_range}")
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
            # 再次检查是否被强制停止
            if not scanning_status["is_scanning"]:
                logger.info(f"扫描任务 {network_range} 在保存结果时被取消或强制停止。")
                break

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
            progress = 60 + (30 * (idx + 1) / len(results)) if results else 90
            scanning_status["progress"] = min(90, progress)
        
        db.commit()
        
        scanning_status["progress"] = 100
        scanning_status["message"] = f"扫描完成，发现 {len(results)} 台设备"
        scanning_status["completed_at"] = datetime.now()
        logger.info(f"网络扫描任务 {network_range} 完成。")
        
    except Exception as e:
        logger.error(f"网络扫描任务 {network_range} 失败: {e}", exc_info=True)
        scanning_status["message"] = f"扫描失败: {str(e)}"
        scanning_status["progress"] = 0
        # 不再重新抛出异常，而是让后台任务安静失败，避免影响主线程
    finally:
        db.close()
        # 只有当扫描状态仍然是当前任务时才重置
        if scanning_status["is_scanning"] and scanning_status["started_at"] is not None:
            # 检查是否是当前任务，避免重置被强制停止的任务
            # 实际生产环境需要更复杂的任务ID管理
            pass # 暂时不在这里重置，由 start_network_scan 或 stop_network_scan 控制
        scanning_status["is_scanning"] = False # 确保最终状态被重置

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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="没有正在进行的扫描任务")
    
    scanning_status["is_scanning"] = False
    scanning_status["message"] = "扫描已停止"
    logger.info("网络扫描任务被手动停止。")
    
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
        logger.info(f"已清除 {count} 条发现结果。")
        return {"deleted": count, "message": f"已清除 {count} 条记录"}
    except Exception as e:
        db.rollback()
        logger.error(f"清除发现结果失败: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/assets", response_model=List[DiscoveryResponse])
async def get_assets(db: Session = Depends(get_db)):
    """
    获取所有已发现的资产列表。
    """
    try:
        results = db.query(DiscoveryResult).all()
        return [
            DiscoveryResponse(
                id=r.id,
                ip_address=r.ip_address,
                hostname=r.hostname,
                mac_address=r.mac_address,
                open_ports=[int(p) for p in r.open_ports.split(",") if p.strip()] if r.open_ports else [],
                os_info=r.os_info,
                services=[s.strip() for s in r.services.split(",") if s.strip()] if r.services else [],
                network_range=r.network_range,
                status=r.status,
                last_seen=r.last_seen,
                created_at=r.created_at,
                updated_at=r.updated_at
            )
            for r in results
        ]
    except Exception as e:
        logger.error(f"获取资产列表失败: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

@router.get("/targets", response_model=List[TargetResponse])
async def get_targets(db: Session = Depends(get_db)):
    """
    获取目标列表。
    
    从扫描任务中提取唯一的目标URL，并统计每个目标的漏洞数量。
    
    Args:
        db: 数据库会话
        
    Returns:
        目标列表，包含漏洞统计信息
    """
    logger.info("正在查询目标列表...")
    
    # 从扫描任务中获取唯一的目标URL
    targets_query = db.query(
        ScanTask.target_url,
        func.max(ScanTask.created_at).label('last_scanned'),
        func.count(ScanTask.id).label('scan_count')
    ).group_by(ScanTask.target_url).all()
    
    # 构建目标列表
    targets = []
    for idx, (url, last_scanned, scan_count) in enumerate(targets_query, 1):
        # 查询该目标的漏洞统计
        # 使用 URL 匹配或包含关系来关联漏洞
        vuln_query = db.query(Vulnerability).filter(
            Vulnerability.url.like(f"%{url}%")
        ).all()
        
        # 统计各级别漏洞数量
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for v in vuln_query:
            if v.severity:
                sev = v.severity.lower()
                if sev == "critical":
                    critical_count += 1
                elif sev == "high":
                    high_count += 1
                elif sev == "medium":
                    medium_count += 1
                elif sev in ["low", "info"]:
                    low_count += 1
        
        target = TargetResponse(
            id=idx,
            url=url,
            description=f"已扫描 {scan_count} 次",
            status="active",
            created_at=last_scanned or datetime.now(),
            last_scanned=last_scanned,
            critical_vulns=critical_count,
            high_vulns=high_count,
            low_vulns=low_count + medium_count  # 前端显示 low 包含 medium
        )
        targets.append(target)
    
    logger.info(f"返回 {len(targets)} 个目标")
    return targets

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
    logger.info(f"添加新目标: {new_target['url']}")
    return new_target


@router.delete("/targets/{target_id}")
async def delete_target(target_id: int):
    """删除指定目标。"""
    global _mock_targets
    for i, t in enumerate(_mock_targets):
        if t["id"] == target_id:
            _mock_targets = _mock_targets[:i] + _mock_targets[i + 1:]
            logger.info(f"已删除目标 id={target_id}")
            return {"message": "目标已删除"}
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="目标不存在")
