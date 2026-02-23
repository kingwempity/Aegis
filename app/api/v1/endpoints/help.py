"""
aegis.app.api.v1.endpoints.help
--------------------------------
帮助中心内容管理 API 端点。

Author: Aegis Architect
Created: 2026-02-23
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from datetime import datetime

from app.database import get_db
from app.models.help import HelpContent

router = APIRouter()


# ==================== Pydantic Schemas ====================

class HelpContentBase(BaseModel):
    """帮助内容基础模型。"""
    key: str = Field(..., description="内容唯一标识键", max_length=50)
    title: str = Field(..., description="标题", max_length=100)
    description: Optional[str] = Field(None, description="简短描述", max_length=500)
    content: Optional[str] = Field(None, description="详细内容（支持 Markdown）")
    icon: str = Field(default="BookOpen", description="图标名称", max_length=50)
    icon_color: str = Field(default="#ff6b00", description="图标颜色", max_length=50)
    link: Optional[str] = Field(None, description="跳转链接", max_length=500)
    order: int = Field(default=0, description="排序顺序")
    is_active: bool = Field(default=True, description="是否启用")


class HelpContentCreate(HelpContentBase):
    """创建帮助内容请求模型。"""
    pass


class HelpContentUpdate(BaseModel):
    """更新帮助内容请求模型。"""
    title: Optional[str] = Field(None, description="标题", max_length=100)
    description: Optional[str] = Field(None, description="简短描述", max_length=500)
    content: Optional[str] = Field(None, description="详细内容（支持 Markdown）")
    icon: Optional[str] = Field(None, description="图标名称", max_length=50)
    icon_color: Optional[str] = Field(None, description="图标颜色", max_length=50)
    link: Optional[str] = Field(None, description="跳转链接", max_length=500)
    order: Optional[int] = Field(None, description="排序顺序")
    is_active: Optional[bool] = Field(None, description="是否启用")


class HelpContentResponse(HelpContentBase):
    """帮助内容响应模型。"""
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ==================== API Endpoints ====================

@router.get("", response_model=List[HelpContentResponse])
async def get_help_contents(
    active_only: bool = Query(False, description="仅返回启用的内容"),
    db: Session = Depends(get_db)
) -> List[HelpContent]:
    """
    获取帮助内容列表。
    
    Args:
        active_only: 是否仅返回启用内容
        db: 数据库会话
        
    Returns:
        帮助内容列表，按 order 排序
    """
    query = db.query(HelpContent)
    if active_only:
        query = query.filter(HelpContent.is_active == True)
    return query.order_by(HelpContent.order).all()


@router.get("/key/{content_key}", response_model=HelpContentResponse)
async def get_help_content_by_key(
    content_key: str,
    db: Session = Depends(get_db)
) -> HelpContent:
    """
    根据 Key 获取帮助内容。
    
    Args:
        content_key: 内容唯一标识键
        db: 数据库会话
        
    Returns:
        帮助内容详情
        
    Raises:
        HTTPException: 内容不存在时返回 404
    """
    content = db.query(HelpContent).filter(HelpContent.key == content_key).first()
    if not content:
        raise HTTPException(status_code=404, detail="帮助内容不存在")
    return content


@router.get("/{content_id}", response_model=HelpContentResponse)
async def get_help_content(
    content_id: int,
    db: Session = Depends(get_db)
) -> HelpContent:
    """
    根据 ID 获取帮助内容。
    
    Args:
        content_id: 内容 ID
        db: 数据库会话
        
    Returns:
        帮助内容详情
        
    Raises:
        HTTPException: 内容不存在时返回 404
    """
    content = db.query(HelpContent).filter(HelpContent.id == content_id).first()
    if not content:
        raise HTTPException(status_code=404, detail="帮助内容不存在")
    return content


@router.post("", response_model=HelpContentResponse)
async def create_help_content(
    content_data: HelpContentCreate,
    db: Session = Depends(get_db)
) -> HelpContent:
    """
    创建帮助内容。
    
    Args:
        content_data: 创建请求数据
        db: 数据库会话
        
    Returns:
        创建的帮助内容
        
    Raises:
        HTTPException: Key 已存在时返回 400
    """
    # 检查 Key 是否已存在
    existing = db.query(HelpContent).filter(HelpContent.key == content_data.key).first()
    if existing:
        raise HTTPException(status_code=400, detail=f"Key '{content_data.key}' 已存在")
    
    content = HelpContent(**content_data.model_dump())
    db.add(content)
    db.commit()
    db.refresh(content)
    return content


@router.put("/{content_id}", response_model=HelpContentResponse)
async def update_help_content(
    content_id: int,
    content_data: HelpContentUpdate,
    db: Session = Depends(get_db)
) -> HelpContent:
    """
    更新帮助内容。
    
    Args:
        content_id: 内容 ID
        content_data: 更新请求数据
        db: 数据库会话
        
    Returns:
        更新后的帮助内容
        
    Raises:
        HTTPException: 内容不存在时返回 404
    """
    content = db.query(HelpContent).filter(HelpContent.id == content_id).first()
    if not content:
        raise HTTPException(status_code=404, detail="帮助内容不存在")
    
    # 仅更新提供的字段
    update_data = content_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(content, key, value)
    
    db.commit()
    db.refresh(content)
    return content


@router.delete("/{content_id}")
async def delete_help_content(
    content_id: int,
    db: Session = Depends(get_db)
) -> dict:
    """
    删除帮助内容。
    
    Args:
        content_id: 内容 ID
        db: 数据库会话
        
    Returns:
        删除结果
        
    Raises:
        HTTPException: 内容不存在时返回 404
    """
    content = db.query(HelpContent).filter(HelpContent.id == content_id).first()
    if not content:
        raise HTTPException(status_code=404, detail="帮助内容不存在")
    
    db.delete(content)
    db.commit()
    return {"status": "success", "message": f"帮助内容 '{content.title}' 已删除"}


@router.post("/init-default")
async def init_default_contents(db: Session = Depends(get_db)) -> dict:
    """
    初始化默认帮助内容。
    
    当数据库中没有帮助内容时，创建默认的四项内容：
    - 快速入门
    - 扫描指南
    - 报告解读
    - 联系支持
    
    Args:
        db: 数据库会话
        
    Returns:
        初始化结果
    """
    # 检查是否已有内容
    existing_count = db.query(HelpContent).count()
    if existing_count > 0:
        return {"status": "skipped", "message": f"已存在 {existing_count} 条帮助内容，跳过初始化"}
    
    # 默认帮助内容
    default_contents = [
        {
            "key": "quick_start",
            "title": "快速入门",
            "description": "了解如何创建第一个扫描任务，配置扫描目标。",
            "content": """## 快速入门指南

欢迎使用 Aegis 漏洞扫描系统！本指南将帮助您快速上手。

### 1. 添加扫描目标
- 进入「目标管理」页面
- 点击「添加目标」按钮
- 输入目标 URL 或 IP 地址

### 2. 创建扫描任务
- 点击右上角「新扫描」按钮
- 选择扫描目标和扫描策略
- 确认后开始扫描

### 3. 查看扫描结果
- 在「扫描任务」页面查看进度
- 扫描完成后查看漏洞详情
- 导出扫描报告

### 需要帮助？
如有疑问，请联系系统管理员。
""",
            "icon": "BookOpen",
            "icon_color": "#ff6b00",
            "link": None,
            "order": 1,
            "is_active": True
        },
        {
            "key": "scan_guide",
            "title": "扫描指南",
            "description": "学习不同扫描类型的配置方法和最佳实践。",
            "content": """## 扫描指南

### 扫描类型说明

#### 1. 快速扫描
- 适用于初步安全评估
- 扫描时间：5-10分钟
- 检测常见漏洞

#### 2. 标准扫描
- 全面安全检测
- 扫描时间：30-60分钟
- 检测中高危漏洞

#### 3. 深度扫描
- 最全面的安全检测
- 扫描时间：1-3小时
- 检测所有类型漏洞

### 最佳实践

1. **选择合适的扫描时间**：避开业务高峰期
2. **设置合理的并发数**：避免对目标造成过大压力
3. **定期扫描**：建议每周至少一次安全扫描
4. **及时修复**：发现高危漏洞应立即处理
""",
            "icon": "Shield",
            "icon_color": "#3b82f6",
            "link": None,
            "order": 2,
            "is_active": True
        },
        {
            "key": "report_guide",
            "title": "报告解读",
            "description": "理解漏洞扫描报告，分析安全风险等级。",
            "content": """## 报告解读指南

### 风险等级说明

| 等级 | 说明 | 建议处理时间 |
|------|------|-------------|
| 严重 | 可直接导致系统被入侵 | 立即处理 |
| 高危 | 存在被利用的风险 | 24小时内 |
| 中危 | 需要关注的安全问题 | 7天内 |
| 低危 | 建议优化的问题 | 30天内 |
| 信息 | 仅供参考的信息 | 可选处理 |

### 报告内容说明

#### 漏洞详情
- 漏洞名称和类型
- 受影响的 URL
- 漏洞证明（请求/响应）

#### 修复建议
- 漏洞成因分析
- 具体修复方案
- 相关安全参考

### 导出报告
支持导出 PDF、HTML、JSON 格式的报告。
""",
            "icon": "FileText",
            "icon_color": "#22c55e",
            "link": None,
            "order": 3,
            "is_active": True
        },
        {
            "key": "contact_support",
            "title": "联系支持",
            "description": "遇到问题？联系技术支持获取帮助。",
            "content": """## 联系技术支持

### 支持渠道

#### 在线支持
- 工作时间：周一至周五 9:00-18:00
- 响应时间：2小时内

#### 邮件支持
- 邮箱：support@aegis.local
- 响应时间：24小时内

### 常见问题

**Q: 扫描任务卡在「运行中」状态？**
A: 请检查网络连接，或联系管理员重启扫描服务。

**Q: 无法添加扫描目标？**
A: 请确认目标格式正确（URL 需包含协议头，如 https://）。

**Q: 如何获取更高权限？**
A: 请联系系统管理员申请相应权限。

### 问题反馈
如发现系统问题或有功能建议，欢迎反馈！
""",
            "icon": "MessageCircle",
            "icon_color": "#a855f7",
            "link": None,
            "order": 4,
            "is_active": True
        }
    ]
    
    # 批量插入
    for content_data in default_contents:
        content = HelpContent(**content_data)
        db.add(content)
    
    db.commit()
    
    return {"status": "success", "message": f"成功初始化 {len(default_contents)} 条默认帮助内容"}