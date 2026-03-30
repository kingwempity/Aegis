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

from app.database import get_db
from app.models.lab import LabScenario, VULN_TYPES, DIFFICULTY_LEVELS
from app.schemas.lab import (
    LabScenarioCreate,
    LabScenarioUpdate,
    LabScenarioResponse,
    LabScenarioListResponse,
    VulnTypeInfo,
)

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