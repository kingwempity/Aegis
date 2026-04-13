"""
scanner.engine
--------------
扫描引擎核心模块。

提供漏洞扫描、攻击脚本生成、攻击路径探索等核心功能。

模块组成：
- core: 核心扫描引擎
- attack: 攻击脚本生成与路径探索算法
- parser: YAML模板解析器
- template_generator: 模板化攻击脚本生成器（新增）
"""

from scanner.engine.core import (
    ScannerEngine,
    ScannerEngineBuilder,
    ScanResult,
    ScanStatistics,
    create_default_engine,
    create_aggressive_engine,
    create_stealthy_engine,
)

from scanner.engine.attack import (
    # 枚举类型
    PayloadType,
    EncodingType,
    
    # 数据实体
    PathCandidate,
    PayloadVariant,
    AttackContext,
    AttackPathNode,
    AttackPathResult,
    
    # 核心组件
    PayloadEncoder,
    PayloadMutator,
    ContextAwareEngine,
    AttackScriptGenerator,
    AttackPathExplorer,
    
    # 攻击路径搜索算法
    HeuristicEvaluator,
    MultiDimensionalHeuristic,
    CostCalculator,
    AttackPathSearchAlgorithm,
    AttackGraphBuilder,
    
    # 便捷函数
    create_default_generator,
    create_aggressive_generator,
    create_default_explorer,
    create_default_search_algorithm,
    create_attack_node,
)

from scanner.engine.parser import TemplateParser
from scanner.engine.rules import THINKPHP_EXCLUSIVE_SQLI_KEYWORDS

# 导入模板化攻击脚本生成器（新模块）
from scanner.engine.template_generator import (
    # 枚举类型
    AttackStrategy,
    PayloadCategory,
    EncodingMethod,
    VariableScope,
    
    # 数据实体
    Payload,
    AttackRequest,
    AttackScript,
    TemplateVariable,
    Template,
    
    # 核心组件
    VariableResolver,
    PayloadEncoder as TemplatePayloadEncoder,
    PayloadMutator as TemplatePayloadMutator,
    PayloadGenerator,
    TemplateRenderer,
    AttackScriptBuilder,
    TemplateManager,
    BatchScriptGenerator,
    
    # 便捷函数
    create_script_builder,
    generate_attack_scripts,
    load_and_generate,
)

__all__ = [
    # 核心扫描引擎
    "ScannerEngine",
    "ScannerEngineBuilder",
    "ScanResult",
    "ScanStatistics",
    "create_default_engine",
    "create_aggressive_engine",
    "create_stealthy_engine",
    
    # 枚举类型（attack模块）
    "PayloadType",
    "EncodingType",
    
    # 枚举类型（template_generator模块）
    "AttackStrategy",
    "PayloadCategory",
    "EncodingMethod",
    "VariableScope",
    
    # 数据实体（attack模块）
    "PathCandidate",
    "PayloadVariant",
    "AttackContext",
    "AttackPathNode",
    "AttackPathResult",
    
    # 数据实体（template_generator模块）
    "Payload",
    "AttackRequest",
    "AttackScript",
    "TemplateVariable",
    "Template",
    
    # 核心组件（attack模块）
    "PayloadEncoder",
    "PayloadMutator",
    "ContextAwareEngine",
    "AttackScriptGenerator",
    "AttackPathExplorer",
    
    # 核心组件（template_generator模块）
    "VariableResolver",
    "TemplatePayloadEncoder",
    "TemplatePayloadMutator",
    "PayloadGenerator",
    "TemplateRenderer",
    "AttackScriptBuilder",
    "TemplateManager",
    "BatchScriptGenerator",
    
    # 攻击路径搜索算法
    "HeuristicEvaluator",
    "MultiDimensionalHeuristic",
    "CostCalculator",
    "AttackPathSearchAlgorithm",
    "AttackGraphBuilder",
    
    # 便捷函数（attack模块）
    "create_default_generator",
    "create_aggressive_generator",
    "create_default_explorer",
    "create_default_search_algorithm",
    "create_attack_node",
    
    # 便捷函数（template_generator模块）
    "create_script_builder",
    "generate_attack_scripts",
    "load_and_generate",
    
    # 解析器
    "TemplateParser",
    
    # 规则常量
    "THINKPHP_EXCLUSIVE_SQLI_KEYWORDS",
]
