"""
app.schemas.lab
---------------
漏洞实验室 Pydantic Schema。
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class AttackStepSchema(BaseModel):
    """
    攻击步骤 Schema。
    
    Attributes:
        step: 步骤序号
        title: 步骤标题
        description: 步骤描述
        request: HTTP请求详情
        response: HTTP响应详情
        payload: 使用的Payload
        payload_explanation: Payload解释
        result: 执行结果
    """
    step: int = Field(..., description="步骤序号")
    title: str = Field(..., description="步骤标题")
    description: Optional[str] = Field(None, description="步骤描述")
    request: Optional[Dict[str, Any]] = Field(None, description="HTTP请求详情")
    response: Optional[Dict[str, Any]] = Field(None, description="HTTP响应详情")
    payload: Optional[str] = Field(None, description="使用的Payload")
    payload_explanation: Optional[str] = Field(None, description="Payload解释")
    result: Optional[str] = Field(None, description="执行结果")


class RemediationSchema(BaseModel):
    """
    修复方案 Schema。
    
    Attributes:
        title: 方案标题
        description: 方案描述
        code: 示例代码
        language: 代码语言
    """
    title: str = Field(..., description="方案标题")
    description: Optional[str] = Field(None, description="方案描述")
    code: Optional[str] = Field(None, description="示例代码")
    language: Optional[str] = Field("python", description="代码语言")


class LearningSchema(BaseModel):
    """
    学习资料 Schema。
    
    Attributes:
        principle: 漏洞原理
        cwe: CWE编号
        owasp: OWASP分类
        impact: 影响范围
        references: 参考资料
    """
    principle: Optional[str] = Field(None, description="漏洞原理")
    cwe: Optional[str] = Field(None, description="CWE编号")
    owasp: Optional[str] = Field(None, description="OWASP分类")
    impact: Optional[str] = Field(None, description="影响范围")
    references: Optional[List[str]] = Field(None, description="参考资料")


class LabScenarioBase(BaseModel):
    """
    漏洞场景基础 Schema。
    """
    name: str = Field(..., description="场景名称", max_length=200)
    vuln_type: str = Field(..., description="漏洞类型", max_length=50)
    difficulty: str = Field("easy", description="难度等级")
    description: Optional[str] = Field(None, description="场景描述")
    tags: Optional[List[str]] = Field(None, description="标签")


class LabScenarioCreate(LabScenarioBase):
    """
    创建漏洞场景 Schema。
    """
    attack_steps: Optional[List[Dict[str, Any]]] = Field(None, description="攻击步骤")
    remediation: Optional[List[Dict[str, Any]]] = Field(None, description="修复方案")
    learning: Optional[Dict[str, Any]] = Field(None, description="学习资料")


class LabScenarioUpdate(BaseModel):
    """
    更新漏洞场景 Schema。
    """
    name: Optional[str] = Field(None, description="场景名称", max_length=200)
    vuln_type: Optional[str] = Field(None, description="漏洞类型", max_length=50)
    difficulty: Optional[str] = Field(None, description="难度等级")
    description: Optional[str] = Field(None, description="场景描述")
    attack_steps: Optional[List[Dict[str, Any]]] = Field(None, description="攻击步骤")
    remediation: Optional[List[Dict[str, Any]]] = Field(None, description="修复方案")
    learning: Optional[Dict[str, Any]] = Field(None, description="学习资料")
    tags: Optional[List[str]] = Field(None, description="标签")
    is_active: Optional[bool] = Field(None, description="是否启用")


class LabScenarioResponse(LabScenarioBase):
    """
    漏洞场景响应 Schema。
    """
    id: int = Field(..., description="场景ID")
    attack_steps: List[Dict[str, Any]] = Field(default_factory=list, description="攻击步骤")
    remediation: List[Dict[str, Any]] = Field(default_factory=list, description="修复方案")
    learning: Dict[str, Any] = Field(default_factory=dict, description="学习资料")
    is_active: bool = Field(True, description="是否启用")
    is_auto_generated: bool = Field(False, description="是否自动生成")
    source_scan_task_id: Optional[int] = Field(None, description="来源扫描任务ID")
    created_at: Optional[datetime] = Field(None, description="创建时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")

    class Config:
        from_attributes = True


class LabScenarioListResponse(BaseModel):
    """
    漏洞场景列表响应 Schema。
    """
    items: List[LabScenarioResponse] = Field(..., description="场景列表")
    total: int = Field(..., description="总数")


class VulnTypeInfo(BaseModel):
    """
    漏洞类型信息 Schema。
    """
    code: str = Field(..., description="类型代码")
    name: str = Field(..., description="类型名称")
    count: int = Field(0, description="该类型场景数量")


class GenerateScenarioRequest(BaseModel):
    """
    手动触发场景生成请求 Schema。
    """
    scan_task_id: int = Field(..., description="扫描任务ID")
    max_scenarios: int = Field(3, description="最多生成场景数", ge=1, le=10)
    min_severity: str = Field("medium", description="最低严重级别")


class GeneratedScenarioResult(BaseModel):
    """
    生成结果 Schema。
    """
    scenario_id: int = Field(..., description="场景ID")
    name: str = Field(..., description="场景名称")
    vuln_type: str = Field(..., description="漏洞类型")
    success: bool = Field(True, description="是否成功")
    error: Optional[str] = Field(None, description="错误信息")


class GenerateScenarioResponse(BaseModel):
    """
    场景生成响应 Schema。
    """
    scan_task_id: int = Field(..., description="扫描任务ID")
    generated_count: int = Field(..., description="成功生成数量")
    total_vulns: int = Field(..., description="扫描发现的漏洞总数")
    results: List[GeneratedScenarioResult] = Field(..., description="生成结果列表")