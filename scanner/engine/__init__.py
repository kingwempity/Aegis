"""
scanner.engine
--------------
扫描引擎核心模块。

提供漏洞扫描、攻击脚本生成、攻击路径探索等核心功能。

模块组成：
- core: 核心扫描引擎
- attack: 攻击脚本生成与路径探索算法
- parser: YAML模板解析器
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

__all__ = [
    # 核心扫描引擎
    "ScannerEngine",
    "ScannerEngineBuilder",
    "ScanResult",
    "ScanStatistics",
    "create_default_engine",
    "create_aggressive_engine",
    "create_stealthy_engine",
    
    # 枚举类型
    "PayloadType",
    "EncodingType",
    
    # 数据实体
    "PathCandidate",
    "PayloadVariant",
    "AttackContext",
    "AttackPathNode",
    "AttackPathResult",
    
    # 核心组件
    "PayloadEncoder",
    "PayloadMutator",
    "ContextAwareEngine",
    "AttackScriptGenerator",
    "AttackPathExplorer",
    
    # 攻击路径搜索算法
    "HeuristicEvaluator",
    "MultiDimensionalHeuristic",
    "CostCalculator",
    "AttackPathSearchAlgorithm",
    "AttackGraphBuilder",
    
    # 便捷函数
    "create_default_generator",
    "create_aggressive_generator",
    "create_default_explorer",
    "create_default_search_algorithm",
    "create_attack_node",
    
    # 解析器
    "TemplateParser",
]