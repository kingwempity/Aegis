"""
app.api.v1.endpoints.lab
------------------------
漏洞实验室 API 端点。

Author: Aegis Architect
Created: 2026-03-01
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func
import asyncio
import logging

from app.database import get_db
from app.models.lab import LabScenario, VULN_TYPES, DIFFICULTY_LEVELS
from app.models.task import Vulnerability
from app.schemas.lab import (
    LabScenarioCreate,
    LabScenarioUpdate,
    LabScenarioResponse,
    LabScenarioListResponse,
    VulnTypeInfo,
    GenerateScenarioRequest,
    GenerateScenarioResponse,
    GeneratedScenarioResult,
)

logger = logging.getLogger(__name__)


def get_risk_level(severity_str: str) -> str:
    """
    将严重级别字符串转换为标准小写风险级别。
    """
    severity = severity_str.upper() if severity_str else ""
    if severity == "CRITICAL":
        return "critical"
    elif severity == "HIGH":
        return "high"
    elif severity == "MEDIUM":
        return "medium"
    elif severity == "LOW":
        return "low"
    else:
        return "info"

router = APIRouter(tags=["Vulnerability Lab"])


@router.get("/scenarios", response_model=LabScenarioListResponse)
async def get_scenarios(
    vuln_type: Optional[str] = Query(None, description="漏洞类型筛选"),
    difficulty: Optional[str] = Query(None, description="难度等级筛选"),
    search: Optional[str] = Query(None, description="搜索关键词"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页数量"),
    db: Session = Depends(get_db),
) -> LabScenarioListResponse:
    """
    获取漏洞场景列表。
    
    支持按漏洞类型、难度等级筛选，以及关键词搜索。
    
    Args:
        vuln_type: 漏洞类型筛选
        difficulty: 难度等级筛选
        search: 搜索关键词（匹配名称和描述）
        page: 页码
        page_size: 每页数量
        db: 数据库会话
        
    Returns:
        场景列表和总数
    """
    # 构建基础查询
    query = db.query(LabScenario).filter(LabScenario.is_active == True)
    
    # 漏洞类型筛选
    if vuln_type:
        query = query.filter(LabScenario.vuln_type == vuln_type)
    
    # 难度筛选
    if difficulty:
        query = query.filter(LabScenario.difficulty == difficulty)
    
    # 关键词搜索
    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (LabScenario.name.ilike(search_pattern)) |
            (LabScenario.description.ilike(search_pattern))
        )
    
    # 获取总数
    total = query.count()
    
    # 分页
    offset = (page - 1) * page_size
    scenarios = query.order_by(LabScenario.created_at.desc()).offset(offset).limit(page_size).all()
    
    return LabScenarioListResponse(
        items=[LabScenarioResponse.model_validate(s) for s in scenarios],
        total=total,
    )


@router.get("/scenarios/{scenario_id}", response_model=LabScenarioResponse)
async def get_scenario(
    scenario_id: int,
    db: Session = Depends(get_db),
) -> LabScenarioResponse:
    """
    获取单个漏洞场景详情。
    
    Args:
        scenario_id: 场景ID
        db: 数据库会话
        
    Returns:
        场景详情
        
    Raises:
        HTTPException: 场景不存在时抛出404
    """
    scenario = db.query(LabScenario).filter(LabScenario.id == scenario_id).first()
    
    if not scenario:
        raise HTTPException(status_code=404, detail="场景不存在")
    
    return LabScenarioResponse.model_validate(scenario)


@router.post("/scenarios", response_model=LabScenarioResponse)
async def create_scenario(
    scenario: LabScenarioCreate,
    db: Session = Depends(get_db),
) -> LabScenarioResponse:
    """
    创建新的漏洞场景。
    
    Args:
        scenario: 场景创建数据
        db: 数据库会话
        
    Returns:
        创建的场景
    """
    # 验证漏洞类型
    if scenario.vuln_type not in VULN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"无效的漏洞类型，可选值: {list(VULN_TYPES.keys())}"
        )
    
    # 验证难度等级
    if scenario.difficulty not in DIFFICULTY_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"无效的难度等级，可选值: {list(DIFFICULTY_LEVELS.keys())}"
        )
    
    # 创建场景
    db_scenario = LabScenario(
        name=scenario.name,
        vuln_type=scenario.vuln_type,
        difficulty=scenario.difficulty,
        description=scenario.description,
        attack_steps=scenario.attack_steps,
        remediation=scenario.remediation,
        learning=scenario.learning,
        tags=scenario.tags,
    )
    
    db.add(db_scenario)
    db.commit()
    db.refresh(db_scenario)
    
    return LabScenarioResponse.model_validate(db_scenario)


@router.put("/scenarios/{scenario_id}", response_model=LabScenarioResponse)
async def update_scenario(
    scenario_id: int,
    scenario: LabScenarioUpdate,
    db: Session = Depends(get_db),
) -> LabScenarioResponse:
    """
    更新漏洞场景。
    
    Args:
        scenario_id: 场景ID
        scenario: 更新数据
        db: 数据库会话
        
    Returns:
        更新后的场景
        
    Raises:
        HTTPException: 场景不存在时抛出404
    """
    db_scenario = db.query(LabScenario).filter(LabScenario.id == scenario_id).first()
    
    if not db_scenario:
        raise HTTPException(status_code=404, detail="场景不存在")
    
    # 更新字段
    update_data = scenario.model_dump(exclude_unset=True)
    
    # 验证漏洞类型
    if "vuln_type" in update_data and update_data["vuln_type"] not in VULN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"无效的漏洞类型，可选值: {list(VULN_TYPES.keys())}"
        )
    
    # 验证难度等级
    if "difficulty" in update_data and update_data["difficulty"] not in DIFFICULTY_LEVELS:
        raise HTTPException(
            status_code=400,
            detail=f"无效的难度等级，可选值: {list(DIFFICULTY_LEVELS.keys())}"
        )
    
    for key, value in update_data.items():
        setattr(db_scenario, key, value)
    
    db.commit()
    db.refresh(db_scenario)
    
    return LabScenarioResponse.model_validate(db_scenario)


@router.delete("/scenarios/{scenario_id}")
async def delete_scenario(
    scenario_id: int,
    db: Session = Depends(get_db),
) -> dict:
    """
    删除漏洞场景（软删除）。
    
    Args:
        scenario_id: 场景ID
        db: 数据库会话
        
    Returns:
        操作结果
        
    Raises:
        HTTPException: 场景不存在时抛出404
    """
    db_scenario = db.query(LabScenario).filter(LabScenario.id == scenario_id).first()
    
    if not db_scenario:
        raise HTTPException(status_code=404, detail="场景不存在")
    
    # 软删除
    db_scenario.is_active = False
    db.commit()
    
    return {"message": "场景已删除", "id": scenario_id}


@router.get("/vuln-types", response_model=List[VulnTypeInfo])
async def get_vuln_types(
    db: Session = Depends(get_db),
) -> List[VulnTypeInfo]:
    """
    获取所有漏洞类型及其场景数量。
    
    Args:
        db: 数据库会话
        
    Returns:
        漏洞类型列表
    """
    # 统计每种类型的场景数量
    type_counts = dict(
        db.query(
            LabScenario.vuln_type,
            func.count(LabScenario.id)
        )
        .filter(LabScenario.is_active == True)
        .group_by(LabScenario.vuln_type)
        .all()
    )
    
    # 构建返回结果
    result = []
    for code, name in VULN_TYPES.items():
        result.append(VulnTypeInfo(
            code=code,
            name=name,
            count=type_counts.get(code, 0),
        ))
    
    return result


@router.get("/difficulty-levels")
async def get_difficulty_levels() -> dict:
    """
    获取所有难度等级。
    
    Returns:
        难度等级字典
    """
    return DIFFICULTY_LEVELS


@router.post("/scenarios/generate-from-scan", response_model=GenerateScenarioResponse)
async def generate_scenarios_from_scan(
    request: GenerateScenarioRequest,
    db: Session = Depends(get_db),
) -> GenerateScenarioResponse:
    """
    从扫描结果手动生成 Vuln Lab 场景。
    
    通过 LLM 对指定扫描任务发现的漏洞进行总结，自动生成教学场景。
    
    Args:
        request: 生成请求，包含 scan_task_id、max_scenarios、min_severity
        db: 数据库会话
        
    Returns:
        生成结果，包含成功数量和结果列表
        
    Raises:
        HTTPException: 任务不存在或无漏洞时抛出404
    """
    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.task_id == request.scan_task_id)
        .all()
    )
    
    if not vulns:
        raise HTTPException(
            status_code=404,
            detail=f"任务 {request.scan_task_id} 未发现漏洞，无法生成场景"
        )
    
    from scanner.engine.lab_generator import LabScenarioGenerator, SEVERITY_ORDER
    
    generator = LabScenarioGenerator()
    min_severity_level = SEVERITY_ORDER.get(request.min_severity, 2)
    
    results: List[GeneratedScenarioResult] = []
    generated_count = 0
    
    with db.begin():
        for vuln in vulns:
            if generated_count >= request.max_scenarios:
                break
            
            vuln_severity = get_risk_level(getattr(vuln, 'severity', 'HIGH'))
            vuln_severity_level = SEVERITY_ORDER.get(vuln_severity, 4)
            
            if vuln_severity_level > min_severity_level:
                logger.info(f" 跳过场景生成: {vuln.url} (严重级别 {vuln_severity} 低于阈值 {request.min_severity})")
                results.append(GeneratedScenarioResult(
                    scenario_id=0,
                    name="已跳过",
                    vuln_type="unknown",
                    success=False,
                    error=f"严重级别 {vuln_severity} 低于阈值 {request.min_severity}"
                ))
                continue
            
            vuln_data = vuln.to_dict() if hasattr(vuln, 'to_dict') else vuln.__dict__
            
            try:
                scenario_data = await generator.generate_from_vuln(vuln_data, scan_task_id=request.scan_task_id)
                
                if scenario_data:
                    lab_scenario = LabScenario(
                        name=scenario_data["name"],
                        vuln_type=scenario_data["vuln_type"],
                        difficulty=scenario_data["difficulty"],
                        description=scenario_data.get("description", ""),
                        attack_steps=scenario_data.get("attack_steps", []),
                        remediation=scenario_data.get("remediation", []),
                        learning=scenario_data.get("learning", {}),
                        tags=scenario_data.get("tags", []),
                        is_active=False,
                        is_auto_generated=True,
                        source_scan_task_id=request.scan_task_id,
                    )
                    db.add(lab_scenario)
                    db.flush()
                    
                    generated_count += 1
                    results.append(GeneratedScenarioResult(
                        scenario_id=lab_scenario.id,
                        name=lab_scenario.name,
                        vuln_type=lab_scenario.vuln_type,
                        success=True,
                    ))
                    logger.info(f"手动生成 Vuln Lab 场景: {lab_scenario.name}")
                else:
                    results.append(GeneratedScenarioResult(
                        scenario_id=0,
                        name="生成失败",
                        vuln_type="unknown",
                        success=False,
                        error="LLM 返回空数据"
                    ))
            except Exception as e:
                logger.warning(f"手动生成场景失败: {e}")
                results.append(GeneratedScenarioResult(
                    scenario_id=0,
                    name="生成失败",
                    vuln_type="unknown",
                    success=False,
                    error=str(e)
                ))
    
    return GenerateScenarioResponse(
        scan_task_id=request.scan_task_id,
        generated_count=generated_count,
        total_vulns=len(vulns),
        results=results,
    )