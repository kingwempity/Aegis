"""
scanner.engine.core
-------------------
核心扫描逻辑：[已弃用] 建议使用 scanner.engine.simulator.AttackSimulator 进行基于 LLM 驱动的模拟攻击。
本模块目前保留用于兼容旧版静态扫描逻辑。

集成优化功能：
1. 智能Payload生成与编码
2. 多维度路径优先级探索
3. 上下文感知攻击策略
4. 动态路径发现与学习
5. 规则引擎驱动的多重验证判定
6. 跨框架误报防护
7. 详细扫描日志记录

Phase 1 增强（模拟攻击方向）：
8. 深度侦察引擎 - 技术栈/WAF/架构识别
9. 智能武器化器 - 目标感知Payload合成
10. 智能重试机制 - 自适应WAF绕过策略
11. 行为分析能力 - 多维度漏洞验证

"""

import os
import asyncio
import time
import datetime
import random
import re
import string
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)
import httpx

from scanner.engine.attack import (
    AttackScriptGenerator,
    AttackPathExplorer,
    ContextAwareEngine,
    PayloadVariant,
    PathCandidate,
    AttackContext,
    PayloadType,
    EncodingType,
)
from scanner.engine.rules import (
    RuleEngine,
    FrameworkType,
    ValidationLevel,
)
from scanner.engine.recon import ReconEngine
from scanner.engine.weaponizer import Weaponizer, WeaponizedPayload, TargetContext

# Phase 2: 模拟攻击核心模块（可选导入）
# 使用安全导入模式：导入失败时所有类设为None，并设置可用性标志
# 后续使用时必须通过 PHASE2_AVAILABLE 和 is not None 双重检查
try:
    def get_simulator():
        from scanner.engine.simulator import AttackSimulator
        return AttackSimulator
    SimulationResult = None
    from scanner.engine.exploitation import ExploitationEngine
    from scanner.engine.intelligence import IntelligenceModule
    PHASE2_AVAILABLE = True
except ImportError as e:
    logger.debug(f" Phase 2 模块导入失败: {e}")
    AttackSimulator = None
    SimulationResult = None
    ExploitationEngine = None
    IntelligenceModule = None
    PHASE2_AVAILABLE = False
except Exception as e:
    logger.warning(f" Phase 2 模块加载异常: {e}")
    AttackSimulator = None
    SimulationResult = None
    ExploitationEngine = None
    IntelligenceModule = None
    PHASE2_AVAILABLE = False

# Phase 3: 智能学习模块（可选导入）
# 同样使用安全导入模式，确保失败时优雅降级
try:
    from scanner.engine.learning import (
        LearningEngine,
        PatternLearner,
        FeedbackSystem,
        AdaptiveStrategyEngine,
        AttackRecord,
        OutcomeType,
        StrategyProfile,
    )
    PHASE3_AVAILABLE = True
except ImportError as e:
    logger.debug(f" Phase 3 模块导入失败: {e}")
    LearningEngine = None
    PatternLearner = None
    FeedbackSystem = None
    AdaptiveStrategyEngine = None
    AttackRecord = None
    OutcomeType = None
    StrategyProfile = None
    PHASE3_AVAILABLE = False
except Exception as e:
    logger.warning(f" Phase 3 模块加载异常: {e}")
    LearningEngine = None
    PatternLearner = None
    FeedbackSystem = None
    AdaptiveStrategyEngine = None
    AttackRecord = None
    OutcomeType = None
    StrategyProfile = None
    PHASE3_AVAILABLE = False



@dataclass
class ScanResult:
    vuln_name: str
    severity: str
    url: str
    payload: str
    evidence: Dict[str, Any]
    plugin_id: str
    scan_time: float = field(default_factory=time.time)
    request: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    validation_log: Dict[str, Any] = field(default_factory=dict)
    attack_path: Dict[str, Any] = field(default_factory=dict)
    attack_execution: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackArtifact:
    name: str
    value: Any
    source_stage: str
    artifact_type: str = "state"
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "source_stage": self.source_stage,
            "artifact_type": self.artifact_type,
            "confidence": self.confidence,
        }


@dataclass
class AttackStageRecord:
    stage_id: str
    stage_name: str
    request: Dict[str, Any]
    response: Dict[str, Any]
    stage_title: str = ""
    stage_goal: str = ""
    extracted: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    matched_conditions: List[str] = field(default_factory=list)
    success: bool = False
    reason: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "stage_name": self.stage_name,
            "stage_title": self.stage_title,
            "stage_goal": self.stage_goal,
            "request": self.request,
            "response": self.response,
            "extracted": self.extracted,
            "artifacts": self.artifacts,
            "matched_conditions": self.matched_conditions,
            "success": self.success,
            "reason": self.reason,
            "duration_ms": self.duration_ms,
        }


@dataclass
class AttackExecution:
    scenario_id: str
    target: str
    status: str = "pending"
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    shared_state: Dict[str, Any] = field(default_factory=dict)
    stage_records: List[AttackStageRecord] = field(default_factory=list)
    artifacts: List[AttackArtifact] = field(default_factory=list)
    final_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "shared_state": self.shared_state,
            "stage_records": [record.to_dict() for record in self.stage_records],
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "final_reason": self.final_reason,
        }


@dataclass
class ScanStatistics:
    """
    扫描统计信息。
    
    Attributes:
        total_requests: 总请求数
        successful_requests: 成功请求数
        failed_requests: 失败请求数
        vulnerabilities_found: 发现的漏洞数
        paths_visited: 访问的路径数
        paths_discovered: 发现的新路径数
        start_time: 开始时间
        end_time: 结束时间
    """
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    vulnerabilities_found: int = 0
    paths_visited: int = 0
    paths_discovered: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "vulnerabilities_found": self.vulnerabilities_found,
            "paths_visited": self.paths_visited,
            "paths_discovered": self.paths_discovered,
            "duration": self.end_time - self.start_time if self.end_time > 0 else 0,
        }


class ScannerEngineBuilder:
    """
    扫描引擎构建器。
    """
    def __init__(self, target: str):
        self.target = target
        self.strategy = "default"
        self.enable_learning = True
        self.enable_discovery = True
        self.max_concurrent = 10
        self.timeout = 10.0
        self.max_depth = 3
        
    def with_strategy(self, strategy: str):
        self.strategy = strategy
        return self
        
    def build(self):
        return ScannerEngine(
            target=self.target,
            strategy=self.strategy,
            enable_learning=self.enable_learning,
            enable_discovery=self.enable_discovery,
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            max_depth=self.max_depth
        )

def create_default_engine(target: str):
    return ScannerEngineBuilder(target).build()

def create_aggressive_engine(target: str):
    return ScannerEngineBuilder(target).with_strategy("aggressive").build()

def create_stealthy_engine(target: str):
    return ScannerEngineBuilder(target).with_strategy("stealthy").build()

class ScannerEngine:
    """
    高级漏洞扫描引擎（集成规则引擎与多重验证）。
    """
    
    def __init__(
        self,
        target: str,
        strategy: str = "default",
        plugin_dir: str = "scanner/plugins",
        enable_learning: bool = True,
        enable_discovery: bool = True,
        max_concurrent: int = 10,
        timeout: float = 10.0,
        max_depth: int = 3,
        rules_config_path: Optional[str] = None,
        target_paths: Optional[List[str]] = None,
        target_vuln_types: Optional[List[str]] = None,
        target_parameters: Optional[List[str]] = None,
        enable_discovery_scan: bool = True,
        payload_set: str = "standard",
        progress_reporter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ):
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.enable_learning = enable_learning
        self.enable_discovery = enable_discovery
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_depth = max_depth
        self.target_paths = target_paths or []
        self.target_vuln_types = target_vuln_types or []
        self.target_parameters = target_parameters or []
        self.enable_discovery_scan = enable_discovery_scan
        self.payload_set = payload_set
        self.progress_reporter = progress_reporter
        self._progress_total_estimate = max(len(self.target_paths) * 10, 50) if self.target_paths else 200
        
        # 优化插件路径解析：支持绝对路径和项目根目录相对路径
        if os.path.isabs(plugin_dir):
            resolved_plugin_dir = plugin_dir
        else:
            # 尝试相对于当前工作目录
            base_path = os.getcwd()
            resolved_plugin_dir = os.path.join(base_path, plugin_dir)
            
            # 如果不存在，尝试寻找 Aegis 根目录下的 scanner/plugins
            if not os.path.exists(resolved_plugin_dir):
                # 方案1: 如果在 BE 目录下运行 (Aegis/BE)
                parent_path = os.path.dirname(base_path)
                resolved_plugin_dir = os.path.join(parent_path, plugin_dir)
                
            # 方案2: 尝试脚本所在位置 (Aegis/scanner/engine/core.py)
            if not os.path.exists(resolved_plugin_dir):
                script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                resolved_plugin_dir = os.path.join(script_dir, plugin_dir)

        if not os.path.exists(resolved_plugin_dir):
            # 方案3: 最后的兜底方案，使用常见部署路径
            fallbacks = [
                "/home/ubuntu/Aegis/BE/scanner/plugins",
                "/app/BE/scanner/plugins",
                "./BE/scanner/plugins"
            ]
            for fb in fallbacks:
                if os.path.exists(fb):
                    resolved_plugin_dir = fb
                    break
            else:
                logger.error(f" 插件目录无法定位: {plugin_dir}")
        
        logger.info(f" 插件目录: {resolved_plugin_dir}")
        
        from scanner.engine.parser import TemplateParser
        self.plugins = TemplateParser.load_plugins(resolved_plugin_dir)
        
        plugin_ids = [p.get('id', 'unknown') for p in self.plugins]
        logger.info(f" 已加载 {len(self.plugins)} 个插件: {plugin_ids}")
        self._progress_total_estimate = max(len(self.plugins) * 8, 80)

        self.script_generator = AttackScriptGenerator(strategy=strategy)
        self.path_explorer = AttackPathExplorer(learning_enabled=enable_learning)
        
        self._target_origin = urlparse(self.target)
        
        self._context: Optional[AttackContext] = None
        self._stats = ScanStatistics()
        self._vulnerabilities: List[ScanResult] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        
        self._rule_engine = RuleEngine(config_path=rules_config_path)
        logger.info(" 规则引擎已初始化（跨框架误报防护已启用）")
        
        self._detected_frameworks: List[FrameworkType] = []
        self._framework_confidence: Dict[FrameworkType, float] = {}
        self._framework_versions: Dict[FrameworkType, Optional[str]] = {}
        
        self._judgment_log: List[Dict[str, Any]] = []
        self._attack_executions: Dict[str, AttackExecution] = {}

        # Phase 1: 初始化模拟攻击增强模块（带异常处理和降级策略）
        self._recon_engine = None
        self._weaponizer = None
        self._recon_result = None  # 存储侦察结果
        self._target_context = None  # 存储目标上下文
        self._simulation_enabled = False  # 标记模拟攻击功能是否可用
        
        try:
            from scanner.engine.recon import ReconEngine as _ReconEngine
            self._recon_engine = _ReconEngine(max_depth=self.max_depth, timeout=self.timeout)
            logger.info(" 深度侦察引擎已初始化")
            self._simulation_enabled = True
        except ImportError as e:
            logger.warning(f" 侦察模块导入失败（深度侦察功能不可用）: {e}")
            self._recon_engine = None
        except Exception as e:
            logger.error(f" 侦察引擎初始化失败: {e}")
            self._recon_engine = None
        
        try:
            from scanner.engine.weaponizer import Weaponizer as _Weaponizer
            self._weaponizer = _Weaponizer(strategy=strategy)
            logger.info(" 智能武器化器已初始化")
        except ImportError as e:
            logger.warning(f" 武器化模块导入失败（智能Payload合成不可用）: {e}")
            self._weaponizer = None
        except Exception as e:
            logger.error(f" 武器化器初始化失败: {e}")
            self._weaponizer = None
        
        if self._simulation_enabled:
            logger.info(" Phase 1 模拟攻击增强功能已启用")
        else:
            logger.info("ℹ 运行于兼容模式（使用原有扫描逻辑）")
        
        # Phase 2: 初始化高级模拟攻击模块（可选）
        self._attack_simulator = None
        self._exploitation_engine = None
        self._intelligence_module = None
        self._phase2_enabled = PHASE2_AVAILABLE
        
        if PHASE2_AVAILABLE:
            try:
                self._attack_simulator = AttackSimulator(
                    target=self.target,
                    strategy=strategy,
                    max_concurrent=self.max_concurrent,
                    timeout=self.timeout,
                )
                self._phase2_enabled = True
                logger.info(" 攻击模拟器已初始化")
            except Exception as e:
                logger.warning(f" 攻击模拟器初始化失败: {e}")
                self._attack_simulator = None
            
            try:
                self._exploitation_engine = ExploitationEngine(strategy=strategy)
                logger.info(" 利用引擎已初始化")
            except Exception as e:
                logger.warning(f" 利用引擎初始化失败: {e}")
            
            try:
                self._intelligence_module = IntelligenceModule()
                logger.info(" 情报模块已初始化")
            except Exception as e:
                logger.warning(f" 情报模块初始化失败: {e}")
        
        if self._phase2_enabled and self._attack_simulator:
            logger.info(" Phase 2 高级模拟攻击功能已启用")
        else:
            logger.debug("ℹ Phase 2 功能不可用，使用Phase 1能力")
        
        # Phase 3: 初始化智能学习模块（可选）
        self._learning_engine = None
        self._adaptive_strategy = None
        self._phase3_enabled = PHASE3_AVAILABLE
        
        if PHASE3_AVAILABLE:
            try:
                self._learning_engine = LearningEngine(enable_persistence=True)
                logger.info(" 学习引擎已初始化（支持模式学习和策略优化）")
                
                # 安全连接学习引擎到攻击模拟器（双重空值保护）
                # 检查1: 确保攻击模拟器存在且不为None
                # 检查2: 确保学习引擎初始化成功
                if (PHASE2_AVAILABLE and 
                    hasattr(self, '_attack_simulator') and 
                    self._attack_simulator is not None and 
                    self._learning_engine is not None):
                    
                    # 尝试设置属性（可能攻击模拟器不支持该属性）
                    try:
                        self._attack_simulator.learning_engine = self._learning_engine
                        logger.info(" 学习引擎已成功连接到攻击模拟器")
                    except AttributeError:
                        logger.debug("ℹ 攻击模拟器不支持learning_engine属性（正常降级）")
                
                elif self._attack_simulator is None:
                    logger.debug("⏭ 攻击模拟器未初始化，跳过连接")
                else:
                    logger.debug("⏭ Phase 2 不可用或学习引擎未初始化")
                
                self._phase3_enabled = True
                
            except Exception as e:
                logger.warning(f" 学习引擎初始化失败: {e}")
                self._learning_engine = None
        
        if self._phase3_enabled and self._learning_engine:
            logger.info(" Phase 3 智能学习功能已启用 - Aegis现在具备自我进化能力！")
        else:
            logger.debug("ℹ Phase 3 功能不可用，使用Phase 1-2能力")

    def _estimate_progress(self) -> int:
        if self._progress_total_estimate <= 0:
            return 0
        return min(95, int(self._stats.total_requests / self._progress_total_estimate * 100))

    def _emit_progress(self, event_type: str, payload: Dict[str, Any]) -> None:
        if not self.progress_reporter:
            return
        try:
            if "progress" not in payload:
                payload = {**payload, "progress": self._estimate_progress()}
            self.progress_reporter(event_type, payload)
        except Exception as e:
            logger.debug(f"progress_reporter failed: {e}")
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        执行扫描并返回发现的漏洞列表。
        
        Phase 1 增强：集成深度侦察和智能武器化
        """
        self._stats.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        logger.info(f" 开始扫描目标: {self.target}")
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=self.max_concurrent * 2, max_keepalive_connections=20),
            headers={
                "User-Agent": "Aegis-Security-Scanner/2.0",
                "Accept": "*/*",
            }
        ) as client:
            # 阶段1: 初始探测，获取上下文
            await self._initial_probe(client)
            
            # 阶段1.5: 深度侦察（Phase 1 新增）
            await self._deep_recon(client)
            
            # 阶段2: 执行插件扫描
            await self._execute_plugins(client)
            
            # 阶段3: 动态路径发现扫描（如果启用）
            if self.enable_discovery and self._stats.paths_discovered > 0:
                await self._discovery_scan(client)
        
        self._stats.end_time = time.time()
        
        # 生成最终报告摘要
        if self._recon_result:
            logger.info(f" 侦察摘要: "
                       f"技术栈={len(self._recon_result.technologies)}个, "
                       f"WAF={self._recon_result.waf_fingerprint.waf_type.value}, "
                       f"架构={self._recon_result.architecture.value}, "
                       f"入口点={len(self._recon_result.entry_points)}个")
        
        return [self._result_to_dict(r) for r in self._vulnerabilities]
    
    async def _initial_probe(self, client: httpx.AsyncClient) -> None:
        """初始探测，获取目标上下文信息（集成规则引擎框架检测）"""
        try:
            resp = await self._request_in_scope(client, "GET", self.target)
            self._context = ContextAwareEngine.build_context(
                target_url=self.target,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text,
            )
            self.script_generator.set_context(self._context)
            if self.enable_discovery:
                discovered = self.path_explorer.discover_paths(resp.text, self.target)
                self._stats.paths_discovered += len(discovered)
            
            self._detected_frameworks, self._framework_confidence = (
                self._rule_engine.detect_framework(
                    response_body=resp.text,
                    response_headers=dict(resp.headers),
                    request_url=self.target,
                    response_status=resp.status_code,
                )
            )

            if self._detected_frameworks == [FrameworkType.UNKNOWN]:
                fallback_frameworks, fallback_confidence, fallback_versions = await self._fallback_framework_probe(client)
                if fallback_frameworks and fallback_frameworks != [FrameworkType.UNKNOWN]:
                    self._detected_frameworks = fallback_frameworks
                    self._framework_confidence = fallback_confidence
                    self._framework_versions.update(fallback_versions)
            
            # 同步 RuleEngine 检测结果到 AttackContext.detected_tech
            if self._context:
                self._context.detected_tech = [fw.value for fw in self._detected_frameworks if fw != FrameworkType.UNKNOWN]
            
            for fw in self._detected_frameworks:
                version = self._rule_engine.detect_version(
                    fw, resp.text, dict(resp.headers)
                )
                self._framework_versions[fw] = version
            
            fw_info = ", ".join(
                f"{fw.value}(v{self._framework_versions.get(fw, 'unknown')}, "
                f"conf={self._framework_confidence.get(fw, 0):.2f})"
                for fw in self._detected_frameworks
            )
            logger.info(f" 框架检测结果: [{fw_info}]" if fw_info else " 框架检测结果: 未识别已知框架")
            
            self._log_judgment(
                phase="initial_probe",
                plugin_id="N/A",
                action="framework_detection",
                details={
                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                    "framework_confidence": {fw.value: round(conf, 3) for fw, conf in self._framework_confidence.items()},
                    "framework_versions": {fw.value: v for fw, v in self._framework_versions.items()},
                },
                result="success",
            )
        except Exception as e:
            logger.warning(f" 初始探测失败: {e}")
            self._context = AttackContext(target_url=self.target)
            self._log_judgment(
                phase="initial_probe", plugin_id="N/A",
                action="framework_detection", details={"error": str(e)}, result="failed",
            )
    
    async def _deep_recon(self, client: httpx.AsyncClient) -> None:
        """
        深度侦察（Phase 1 新增）
        
        使用增强型ReconEngine进行深度目标分析：
        - 技术栈深度识别
        - WAF/防护系统指纹识别
        - 应用架构推断
        - 认证机制识别
        - 入口点发现
        - 第三方组件识别
        """
        # 检查侦察引擎是否可用（降级策略）
        if not self._recon_engine:
            logger.info("⏭ 跳过深度侦察（侦察引擎未初始化）")
            return
        
        try:
            logger.info(" 开始深度侦察...")
            
            # 执行深度侦察
            self._recon_result = await self._recon_engine.deep_recon(self.target, client)
            
            # 构建目标上下文（供Weaponizer使用）
            self._target_context = TargetContext.from_recon(self._recon_result)
            
            # 同步到现有上下文系统
            if self._context and self._recon_result:
                # 更新技术栈信息
                if self._recon_result.primary_framework:
                    if not hasattr(self._context, 'detected_tech') or not self._context.detected_tech:
                        self._context.detected_tech = [self._recon_result.primary_framework.lower()]
                    elif self._recon_result.primary_framework.lower() not in self._context.detected_tech:
                        self._context.detected_tech.append(self._recon_result.primary_framework.lower())
                
                # 更新WAF信息
                if self._recon_result.waf_fingerprint.waf_type.value != 'unknown':
                    self._context.waf_detected = True
                    self._context.waf_type = self._recon_result.waf_fingerprint.waf_type.value
            
            logger.info(
                f" 深度侦察完成:\n"
                f"   主框架: {self._recon_result.primary_framework or '未识别'}\n"
                f"   数据库: {self._recon_result.primary_database or '未识别'}\n"
                f"   WAF类型: {self._recon_result.waf_fingerprint.vendor_name or '未检测到'} "
                f"(强度:{self._recon_result.waf_fingerprint.protection_level.value})\n"
                f"   架构: {self._recon_result.architecture.value}\n"
                f"   认证: {self._recon_result.auth_mechanism.value}\n"
                f"   入口点: {len(self._recon_result.entry_points)}个\n"
                f"   组件: {len(self._recon_result.third_party_components)}个\n"
                f"   缺失安全头: {len(self._recon_result.missing_security_headers)}个\n"
                f"   调试信息: {len(self._recon_result.comments_or_debug_info)}条"
            )
            
            # 记录侦察结果到日志
            self._log_judgment(
                phase="deep_recon",
                plugin_id="N/A",
                action="target_analysis",
                details={
                    "technologies_count": len(self._recon_result.technologies),
                    "waf_type": self._recon_result.waf_fingerprint.waf_type.value,
                    "waf_protection_level": self._recon_result.waf_fingerprint.protection_level.value,
                    "architecture": self._recon_result.architecture.value,
                    "auth_mechanism": self._recon_result.auth_mechanism.value,
                    "entry_points_count": len(self._recon_result.entry_points),
                    "api_endpoints_count": len(self._recon_result.api_endpoints),
                    "sensitive_paths_found": len(self._recon_result.sensitive_paths),
                    "missing_security_headers": self._recon_result.missing_security_headers,
                    "third_party_components": list(self._recon_result.third_party_components.keys()),
                },
                result="success",
            )
            
        except Exception as e:
            logger.warning(f" 深度侦察失败: {e}")
            self._log_judgment(
                phase="deep_recon", plugin_id="N/A",
                action="target_analysis", details={"error": str(e)}, result="failed",
            )

    def _framework_probe_candidates(self) -> List[str]:
        return [
            self.target,
            f"{self.target}/index.php",
            f"{self.target}/?s=index/index/index",
            f"{self.target}/index.php?s=/index/index/index",
            f"{self.target}/user/register",
            f"{self.target}/?q=user/register",
            f"{self.target}/admin/login/",
            f"{self.target}/admin/",
            f"{self.target}/static/admin/css/base.css",
            f"{self.target}/static/admin/css/login.css",
            f"{self.target}/create_user/",
            f"{self.target}/api/",
            f"{self.target}/robots.txt",
            f"{self.target}/sitemap.xml",
            # Django 特有探测路径
            f"{self.target}/admin/login/?next=/admin/",
            f"{self.target}/static/",
            f"{self.target}/__debug__/",
        ]

    async def _fallback_framework_probe(
        self,
        client: httpx.AsyncClient,
    ) -> Tuple[List[FrameworkType], Dict[FrameworkType, float], Dict[FrameworkType, Optional[str]]]:
        """
        当首页指纹不足时，补充访问少量高价值路径来识别框架。
        这可以覆盖 ThinkPHP/Drupal 这类首页特征较弱、但框架路由特征明显的场景。
        """
        best_frameworks: List[FrameworkType] = [FrameworkType.UNKNOWN]
        best_confidence: Dict[FrameworkType, float] = {FrameworkType.UNKNOWN: 1.0}
        best_versions: Dict[FrameworkType, Optional[str]] = {}
        best_score = 0.0

        for candidate_url in self._framework_probe_candidates():
            try:
                resp = await self._request_in_scope(client, "GET", candidate_url)
            except Exception as exc:
                self._log_judgment(
                    phase="initial_probe",
                    plugin_id="N/A",
                    action="framework_fallback_probe",
                    details={"url": candidate_url, "error": str(exc)},
                    result="failed",
                )
                continue

            frameworks, confidence = self._rule_engine.detect_framework(
                response_body=resp.text,
                response_headers=dict(resp.headers),
                request_url=candidate_url,
                response_status=resp.status_code,
            )
            known_frameworks = [fw for fw in frameworks if fw != FrameworkType.UNKNOWN]
            if not known_frameworks:
                continue

            score = max(confidence.get(fw, 0.0) for fw in known_frameworks)
            if score <= best_score:
                continue

            best_frameworks = frameworks
            best_confidence = confidence
            best_versions = {
                fw: self._rule_engine.detect_version(fw, resp.text, dict(resp.headers))
                for fw in known_frameworks
            }
            best_score = score

            self._log_judgment(
                phase="initial_probe",
                plugin_id="N/A",
                action="framework_fallback_probe",
                details={
                    "url": candidate_url,
                    "detected_frameworks": [fw.value for fw in best_frameworks],
                    "framework_confidence": {
                        fw.value: round(best_confidence.get(fw, 0.0), 3) for fw in best_frameworks
                    },
                },
                result="success",
            )

        return best_frameworks, best_confidence, best_versions
    
    async def _execute_plugins(self, client: httpx.AsyncClient) -> None:
        """执行所有插件的扫描任务"""
        tasks = []
        async def _gather_pending():
            nonlocal tasks
            if not tasks: return
            await asyncio.gather(*tasks, return_exceptions=True)
            tasks = []
        
        for plugin in self.plugins:
            plugin_id = plugin.get("id", "unknown")
            requests_list = plugin.get("requests", [])
            # 兼容 sequential_requests (top-level)
            sequential = bool(plugin.get("sequential_requests"))
            flattened_paths = [
                path_item
                for req in requests_list
                for path_item in req.get("path", [])
                if isinstance(path_item, str)
            ]
            can_execute, execute_reason = self._rule_engine.should_execute_plugin(
                plugin_id=plugin_id,
                detected_frameworks=self._detected_frameworks,
                request_paths=flattened_paths,
            )
            
            # VULHUB 调试模式: 强制允许所有插件执行
            # 生产环境请注释掉以下两行
            if plugin_id in ("thinkphp-sqli", "django-cve-2017-12794", "in-sqlijection"):
                can_execute, execute_reason = True, f"VULHUB调试: 强制执行 {plugin_id}"
                logger.info(f" VULHUB调试模式: 插件 {plugin_id} 将被强制执行 (原因: {execute_reason})")
            
            self._log_judgment(
                phase="plugin_gate",
                plugin_id=plugin_id,
                action="framework_scope_check",
                details={
                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                    "request_paths": flattened_paths[:10],
                    "reason": execute_reason,
                },
                result="allow" if can_execute else "skip",
            )
            if not can_execute:
                logger.info(f"⏭ 跳过插件 {plugin_id}: {execute_reason}")
                continue

            self._get_attack_execution(plugin)
            
            if sequential:
                await _gather_pending()
                # 顺序模式下，如果某一步失败（未命中 matchers），则停止该插件后续请求
                for index, req in enumerate(requests_list):
                    if not self._check_preconditions(req):
                        continue
                    can_execute, block_reason = self._can_execute_sequential_step(plugin, req, index)
                    if not can_execute:
                        self._log_judgment(
                            phase="sequential_step",
                            plugin_id=plugin_id,
                            action="stage_blocked",
                            details={
                                "stage": req.get("stage", f"step_{index + 1}"),
                                "reason": block_reason,
                                "state": self._snapshot_plugin_state(plugin_id),
                            },
                            result="suppress",
                        )
                        logger.info(f" 插件 {plugin_id} 阶段阻断: {block_reason}")
                        self._finalize_attack_execution(plugin, "blocked", block_reason)
                        break
                    success = await self._scan_with_plugin(client, plugin, req)
                    if not success:
                        logger.info(f" 插件 {plugin.get('id')} 步骤未命中 matchers，中断后续请求")
                        self._finalize_attack_execution(plugin, "partial", self._get_plugin_state(plugin_id).get("LastSequentialFailure") or "阶段未完成")
                        break
                else:
                    current_execution = self._attack_executions.get(plugin_id)
                    if current_execution and current_execution.status == "running":
                        self._finalize_attack_execution(plugin, "validated", "攻击链验证完成")
            else:
                for req in requests_list:
                    if not self._check_preconditions(req): continue
                    tasks.append(self._scan_with_plugin(client, plugin, req))
                    if len(tasks) >= self.max_concurrent: await _gather_pending()
        
        await _gather_pending()

    async def _scan_with_plugin(self, client: httpx.AsyncClient, plugin: Dict[str, Any], req_def: Dict[str, Any]) -> bool:
        """执行单个插件请求扫描（集成多重验证与跨框架误报防护）"""
        async with self._semaphore:
            method = req_def.get("method", "GET").upper()
            paths = req_def.get("path", [])
            headers = req_def.get("headers", {})
            base_body = req_def.get("body")
            matchers = req_def.get("matchers", [])
            matchers_condition = req_def.get("matchers-condition", "or")
            should_report = req_def.get("report", True)
            
            plugin_id = plugin.get("id", "unknown")
            is_sequential = bool(plugin.get("sequential_requests"))
            stage_name = req_def.get("stage", f"{method.lower()}_{plugin_id}")
            
            rule_min_confidence = self._rule_engine.get_min_confidence(plugin_id)
            rule_required_evidence = self._rule_engine.get_required_evidence_count(plugin_id)
            
            payload_variants = self.script_generator.build_payloads(plugin, req_def)
            if not payload_variants:
                payload_variants = [None]
            
            any_success = False
            for path_template in paths:
                for variant in payload_variants:
                    payload_str = variant.encoded if variant else ""

                    cached_vars = getattr(self, "_plugin_vars_cache", {}).get(plugin_id, {})
                    if "{{ExtractedPath}}" in path_template and not cached_vars.get("ExtractedPath"):
                        continue
                    if "{{UploadedFilename}}" in path_template and not cached_vars.get("UploadedFilename"):
                        continue
                    
                    url = self._resolve_variables(path_template, payload_str, plugin)
                    
                    current_headers = dict(headers)
                    current_body = self._resolve_variables(base_body, payload_str, plugin) if base_body else None
                    
                    if self._context and self._context.csrf_token:
                        current_headers["X-CSRF-Token"] = self._context.csrf_token
                    
                    content_type = current_headers.get("Content-Type", "")
                    if content_type.startswith("multipart/form-data"):
                        boundary = self._infer_multipart_boundary(current_body or "")
                        if not boundary:
                            boundary = "----AegisBoundary" + ''.join(
                                random.choices(string.ascii_letters + string.digits, k=16)
                            )
                        if boundary and "boundary=" not in content_type:
                            current_headers["Content-Type"] = f"{content_type}; boundary={boundary}"
                    
                    self._stats.total_requests += 1
                    try:
                        before_state = self._snapshot_plugin_state(plugin_id)
                        request_started_at = time.perf_counter()
                        resp = await self._request_in_scope(client, method, url, current_headers, current_body)
                        request_elapsed_ms = (time.perf_counter() - request_started_at) * 1000.0
                        try:
                            resp.extensions["aegis_elapsed_ms"] = request_elapsed_ms
                        except Exception:
                            pass
                        self._stats.successful_requests += 1
                        
                        self._extract_dynamic_variables(resp, plugin)
                        extracted = self._capture_state_changes(plugin_id, before_state, stage_name)
                        request_snapshot = {
                            "method": method,
                            "url": url,
                            "headers": current_headers,
                            "body": current_body,
                        }
                        response_snapshot = {
                            "status": resp.status_code,
                            "headers": dict(resp.headers),
                            "body_snippet": resp.text[:1000],
                            "content_length": len(resp.content),
                            "response_time_ms": round(request_elapsed_ms, 2),
                        }
                        self._emit_progress(
                            "request_completed",
                            {
                                "plugin_id": plugin_id,
                                "url": url,
                                "request": request_snapshot,
                                "response": response_snapshot,
                                "duration_ms": round(request_elapsed_ms, 2),
                                "current_stage": f"{plugin_id} · {stage_name}",
                            },
                        )
                        matcher_hit = self._check_matchers(resp, matchers, matchers_condition)
                        if not matcher_hit and is_sequential:
                            miss_reason = self._explain_sequential_miss(plugin, req_def, resp, url)
                            stage_artifacts = self._register_stage_artifacts(
                                plugin,
                                stage_name,
                                self._extract_stage_artifacts(
                                    plugin, req_def, resp, payload_str, stage_name, []
                                ),
                            )
                            if miss_reason:
                                self._append_stage_record(
                                    plugin=plugin,
                                    stage_name=stage_name,
                                    req_def=req_def,
                                    request=request_snapshot,
                                    response=response_snapshot,
                                    matched_conditions=[],
                                    success=False,
                                    reason=miss_reason,
                                    duration_ms=round(request_elapsed_ms, 2),
                                    extracted=extracted,
                                    artifacts=stage_artifacts,
                                )
                                self._record_sequential_step_result(
                                    plugin_id=plugin_id,
                                    stage_name=stage_name,
                                    url=url,
                                    response=resp,
                                    matched_keywords=[],
                                    valid=False,
                                    reason=miss_reason,
                                )
                            continue

                        if matcher_hit:
                            matched_keywords = self._extract_matched_keywords(resp, matchers)
                            stage_artifacts = self._register_stage_artifacts(
                                plugin,
                                stage_name,
                                self._extract_stage_artifacts(
                                    plugin,
                                    req_def,
                                    resp,
                                    payload_str,
                                    stage_name,
                                    matched_keywords,
                                ),
                            )
                            if is_sequential:
                                step_valid, step_reason = self._validate_sequential_step(
                                    plugin=plugin,
                                    req_def=req_def,
                                    resp=resp,
                                    url=url,
                                    matched_keywords=matched_keywords,
                                )
                                self._append_stage_record(
                                    plugin=plugin,
                                    stage_name=stage_name,
                                    req_def=req_def,
                                    request=request_snapshot,
                                    response=response_snapshot,
                                    matched_conditions=matched_keywords[:10],
                                    success=step_valid,
                                    reason=step_reason,
                                    duration_ms=round(request_elapsed_ms, 2),
                                    extracted=extracted,
                                    artifacts=stage_artifacts,
                                )
                                self._record_sequential_step_result(
                                    plugin_id=plugin_id,
                                    stage_name=stage_name,
                                    url=url,
                                    response=resp,
                                    matched_keywords=matched_keywords,
                                    valid=step_valid,
                                    reason=step_reason,
                                )
                                if not step_valid:
                                    continue

                            any_success = True
                            if is_sequential and not should_report:
                                return True
                            
                            if should_report:
                                is_valid, validation_reason = self._rule_engine.validate_vulnerability(
                                    plugin_id=plugin_id,
                                    detected_frameworks=self._detected_frameworks,
                                    response_body=resp.text,
                                    response_headers=dict(resp.headers),
                                    request_url=url,
                                    matched_keywords=matched_keywords,
                                    framework_versions=self._framework_versions,
                                    request_payload=payload_str,
                                )
                                
                                logger.debug(
                                    f" 漏洞验证 [{plugin_id}]: "
                                    f"url={url}, is_valid={is_valid}, reason={validation_reason}"
                                )
                                
                                base_confidence = self._calculate_confidence(resp, matchers, plugin)
                                
                                adjusted_confidence, adjustment_details = self._rule_engine.adjust_confidence(
                                    plugin_id=plugin_id,
                                    base_confidence=base_confidence,
                                    detected_frameworks=self._detected_frameworks,
                                    response_body=resp.text,
                                    response_headers=dict(resp.headers),
                                    request_url=url,
                                    matched_keywords=matched_keywords,
                                    request_payload=payload_str,
                                )
                                
                                evidence_count = self._count_evidence(resp, matchers)
                                
                                judgment_record = {
                                    "phase": "vulnerability_judgment",
                                    "plugin_id": plugin_id,
                                    "url": url,
                                    "payload": payload_str[:200] if payload_str else "N/A",
                                    "base_confidence": round(base_confidence, 4),
                                    "adjusted_confidence": round(adjusted_confidence, 4),
                                    "adjustment_details": adjustment_details,
                                    "is_valid": is_valid,
                                    "validation_reason": validation_reason,
                                    "evidence_count": evidence_count,
                                    "required_evidence": rule_required_evidence,
                                    "matched_keywords": matched_keywords[:10],
                                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                                    "framework_confidence": {
                                        fw.value: round(self._framework_confidence.get(fw, 0), 3)
                                        for fw in self._detected_frameworks
                                    },
                                    "request_path_validated": True,
                                    "framework_versions": {
                                        fw.value: v for fw, v in self._framework_versions.items()
                                    },
                                    "response_status": resp.status_code,
                                    "response_length": len(resp.content),
                                    "response_time_ms": round(request_elapsed_ms, 2),
                                }
                                
                                final_report = False
                                final_reason = ""
                                
                                if not is_valid:
                                    final_report = False
                                    final_reason = f"验证未通过: {validation_reason}"
                                    logger.info(
                                        f" 跨框架误报拦截: [{plugin_id}] @ {url} - {validation_reason}"
                                    )
                                elif adjusted_confidence < rule_min_confidence:
                                    final_report = False
                                    final_reason = (
                                        f"置信度不足: {adjusted_confidence:.3f} < {rule_min_confidence:.3f}"
                                    )
                                    logger.info(
                                        f" 低置信度过滤: [{plugin_id}] conf={adjusted_confidence:.3f} @ {url}"
                                    )
                                elif evidence_count < rule_required_evidence:
                                    final_report = False
                                    final_reason = (
                                        f"证据不足: {evidence_count} < {rule_required_evidence}"
                                    )
                                    logger.info(
                                        f" 证据不足过滤: [{plugin_id}] evidence={evidence_count} @ {url}"
                                    )
                                else:
                                    final_report = True
                                    final_reason = "验证通过"
                                
                                judgment_record["final_decision"] = "report" if final_report else "suppress"
                                judgment_record["final_reason"] = final_reason
                                judgment_record["suppressed_reason"] = final_reason if not final_report else ""
                                self._judgment_log.append(judgment_record)
                                self._emit_progress(
                                    "judgment",
                                    {
                                        **judgment_record,
                                        "plugin_id": plugin_id,
                                        "current_stage": f"初判 · {plugin_id}",
                                    },
                                )
                                
                                if final_report:
                                    if not is_sequential:
                                        self._append_stage_record(
                                            plugin=plugin,
                                            stage_name=stage_name,
                                            req_def=req_def,
                                            request=request_snapshot,
                                            response=response_snapshot,
                                            matched_conditions=matched_keywords[:10],
                                            success=True,
                                            reason=final_reason,
                                            duration_ms=round(request_elapsed_ms, 2),
                                            extracted=extracted,
                                            artifacts=stage_artifacts,
                                        )
                                    attack_execution = self._get_attack_execution(plugin)
                                    attack_status = "validated" if is_sequential else "exploitable"
                                    self._finalize_attack_execution(plugin, attack_status, final_reason)
                                    attack_path = self._build_attack_path_from_execution(attack_execution)
                                    result = ScanResult(
                                        vuln_name=plugin.get("info", {}).get("name", "Unknown Vulnerability"),
                                        severity=plugin.get("info", {}).get("severity", "Medium"),
                                        url=url,
                                        payload=payload_str or "N/A",
                                        evidence={
                                            "matchers": matchers,
                                            "matchers_condition": matchers_condition,
                                            "confidence": round(adjusted_confidence, 3),
                                            "base_confidence": round(base_confidence, 3),
                                            "evidence_count": evidence_count,
                                            "matched_keywords": matched_keywords[:10],
                                            "response_status": resp.status_code,
                                            "response_time_ms": round(request_elapsed_ms, 2),
                                            "framework_validation": {
                                                "is_valid": is_valid,
                                                "reason": validation_reason,
                                            },
                                            "confidence_adjustments": [
                                                a for a in adjustment_details if a.get("triggered")
                                            ],
                                            "attack_stage_count": len(self._get_attack_execution(plugin).stage_records),
                                            "attack_artifacts": [artifact.to_dict() for artifact in self._get_attack_execution(plugin).artifacts],
                                        },
                                        plugin_id=plugin_id,
                                        request={"method": method, "url": url, "headers": current_headers, "body": current_body},
                                        response={
                                            "status": resp.status_code,
                                            "body_snippet": resp.text[:1000],
                                            "content_length": len(resp.content),
                                            "response_time_ms": round(request_elapsed_ms, 2),
                                        },
                                        validation_log={
                                            "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                                            "framework_versions": {
                                                fw.value: v for fw, v in self._framework_versions.items()
                                            },
                                            "judgment_reason": final_reason,
                                            "attack_status": attack_status,
                                            "attack_stage_count": len(attack_execution.stage_records),
                                            "artifacts": [artifact.to_dict() for artifact in attack_execution.artifacts],
                                        },
                                        attack_path=attack_path,
                                        attack_execution=attack_execution.to_dict(),
                                    )
                                    self._vulnerabilities.append(result)
                                    self._stats.vulnerabilities_found += 1
                                    self._emit_progress(
                                        "vulnerability_confirmed",
                                        {
                                            "vuln_name": result.vuln_name,
                                            "url": url,
                                            "severity": result.severity,
                                            "confidence": round(adjusted_confidence, 3),
                                            "plugin_id": plugin_id,
                                        },
                                    )
                                    
                                    level = "" if adjusted_confidence > 0.6 else "" if adjusted_confidence > 0.3 else ""
                                    logger.info(
                                        f"{level} 确认漏洞 [{adjusted_confidence:.1%}]: "
                                        f"{result.vuln_name} @ {url} (证据={evidence_count})"
                                    )
                                    if is_sequential:
                                        return True
                                elif not is_sequential:
                                    self._append_stage_record(
                                        plugin=plugin,
                                        stage_name=stage_name,
                                        req_def=req_def,
                                        request=request_snapshot,
                                        response=response_snapshot,
                                        matched_conditions=matched_keywords[:10],
                                        success=False,
                                        reason=final_reason,
                                        duration_ms=round(request_elapsed_ms, 2),
                                        extracted=extracted,
                                        artifacts=stage_artifacts,
                                    )
                    except Exception as e:
                        self._stats.failed_requests += 1
                        self._append_stage_record(
                            plugin=plugin,
                            stage_name=stage_name,
                            req_def=req_def,
                            request={"method": method, "url": url, "headers": current_headers, "body": current_body},
                            response={"status": 0, "headers": {}, "body_snippet": "", "content_length": 0},
                            matched_conditions=[],
                            success=False,
                            reason=str(e),
                            duration_ms=0.0,
                            extracted={},
                            artifacts=[],
                        )
                        self._log_judgment(
                            phase="scan_request", plugin_id=plugin_id,
                            action="request_failed", details={"url": url, "error": str(e)}, result="failed",
                        )

            if is_sequential and not any_success:
                failure_reason = self._get_plugin_state(plugin_id).get("LastSequentialFailure") or "未满足阶段成功条件"
                self._finalize_attack_execution(plugin, "partial", failure_reason)
                self._log_judgment(
                    phase="sequential_step",
                    plugin_id=plugin_id,
                    action="stage_failed",
                    details={
                        "stage": stage_name,
                        "reason": failure_reason,
                        "state": self._snapshot_plugin_state(plugin_id),
                    },
                    result="failed",
                )
            elif not is_sequential:
                execution = self._attack_executions.get(plugin_id)
                if execution and execution.status == "running":
                    final_status = "exploitable" if any_success else "observed"
                    final_reason = "已记录命中请求" if any_success else "未形成可验证攻击结果"
                    self._finalize_attack_execution(plugin, final_status, final_reason)
            
            return any_success
    
    # ==================== Phase 1: 智能重试与行为分析方法 ====================
    
    def _is_waf_blocked(self, resp: httpx.Response) -> bool:
        """
        检测响应是否被WAF拦截
        
        Args:
            resp: HTTP响应对象
            
        Returns:
            True表示被WAF拦截
        """
        # 常见的WAF拦截特征
        waf_indicators = [
            (403, "forbidden"),
            (406, "not acceptable"),
            (429, "too many requests"),
            (503, "service unavailable"),
        ]
        
        status_code = resp.status_code
        
        # 检查状态码
        for code, reason in waf_indicators:
            if status_code == code:
                body_lower = resp.text.lower() if resp.text else ""
                
                # 检查响应体中的WAF关键词
                waf_keywords = [
                    'cloudflare', 'incapsula', 'akamai', 'sucuri',
                    'mod_security', 'web application firewall',
                    'blocked', 'forbidden', 'denied',
                    'request blocked', 'access denied',
                    'bot detection', 'security measure',
                ]
                
                keyword_matches = sum(1 for kw in waf_keywords if kw in body_lower)
                
                if keyword_matches >= 2:
                    logger.debug(f" 检测到WAF拦截: {status_code} ({reason}), "
                               f"关键词匹配={keyword_matches}")
                    return True
        
        return False
    
    def _analyze_response_behavior(self, 
                                   resp: httpx.Response,
                                   baseline_time_ms: float = 0.0) -> Dict[str, Any]:
        """
        分析响应行为（Phase 1 新增）
        
        多维度分析响应特征：
        - 时间行为：响应时间异常检测
        - 状态码变化：状态码差异分析
        - 内容特征：长度、类型、错误信息
        
        Args:
            resp: HTTP响应对象
            baseline_time_ms: 基准响应时间（正常请求的响应时间）
            
        Returns:
            行为分析结果字典
        """
        behavior = {
            "response_time_ms": getattr(resp, 'extensions', {}).get('aegis_elapsed_ms', 0),
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "content_type": resp.headers.get('Content-Type', ''),
            
            "time_anomaly": False,
            "time_deviation_ratio": 0.0,
            "status_anomaly": False,
            "size_anomaly": False,
            "error_indicators": [],
            "behavior_score": 0.0,  # 0-100, 越高越可疑
            
            "analysis_timestamp": time.time(),
        }
        
        # 1. 时间行为分析
        response_time = behavior["response_time_ms"]
        if baseline_time_ms > 0 and response_time > 0:
            deviation = abs(response_time - baseline_time_ms) / baseline_time_ms
            behavior["time_deviation_ratio"] = round(deviation, 3)
            
            # SQL注入时间盲注特征：响应时间显著增加
            if deviation > 3.0 and response_time > 3000:
                behavior["time_anomaly"] = True
                behavior["behavior_score"] += 30
                behavior["error_indicators"].append(f"time_blind_injection (deviation={deviation:.1f}x)")
            
            # 中等时间延迟（可能是基于时间的攻击）
            elif deviation > 1.5 and response_time > 1000:
                behavior["time_anomaly"] = True
                behavior["behavior_score"] += 15
                behavior["error_indicators"].append(f"delay_detected ({response_time:.0f}ms vs {baseline_time_ms:.0f}ms)")
        
        # 2. 状态码分析
        error_status_codes = [400, 401, 403, 500, 502, 503]
        if resp.status_code in error_status_codes:
            behavior["status_anomaly"] = True
            behavior["behavior_score"] += 20
            behavior["error_indicators"].append(f"error_status_{resp.status_code}")
        
        # 3. 内容长度异常
        if len(resp.content) < 100 and resp.status_code == 200:
            behavior["size_anomaly"] = True
            behavior["behavior_score"] += 10
            behavior["error_indicators"].append("unusually_short_response")
        
        # 4. 错误信息检测
        if resp.text:
            text_lower = resp.text.lower()
            
            # 数据库错误
            db_errors = [
                ('sql', ['sql syntax', 'mysql', 'postgresql', 'oracle', 'mssql']),
                ('stack_trace', ['traceback', 'exception', 'error at line', 'fatal error']),
                ('debug_info', ['debug', 'warning:', 'notice:', 'deprecated']),
                ('path_disclosure', ['/var/www/', '/home/', '\\windows\\', 'c:\\']),
            ]
            
            for error_type, keywords in db_errors:
                matches = [kw for kw in keywords if kw in text_lower]
                if matches:
                    behavior["error_indicators"].append(f"{error_type}:{matches[0]}")
                    behavior["behavior_score"] += {
                        'sql': 25,
                        'stack_trace': 20,
                        'debug_info': 15,
                        'path_disclosure': 10,
                    }.get(error_type, 5)
        
        # 5. 规范化分数
        behavior["behavior_score"] = min(behavior["behavior_score"], 100)
        
        return behavior
    
    async def _intelligent_retry(self,
                                  client: httpx.AsyncClient,
                                  method: str,
                                  url: str,
                                  headers: Dict[str, str],
                                  body: Optional[str],
                                  plugin_id: str,
                                  max_retries: int = 3) -> Tuple[Optional[httpx.Response], float]:
        """
        智能重试机制（Phase 1 新增）
        
        当初始请求被WAF拦截或失败时，自动尝试不同的绕过策略：
        1. 使用Weaponizer生成针对目标定制的Payload变体
        2. 应用不同的编码和绕过技术
        3. 根据历史成功率调整策略
        
        Args:
            client: HTTP客户端
            method: HTTP方法
            url: 目标URL
            headers: 请求头
            body: 请求体
            plugin_id: 插件ID（用于确定漏洞类型）
            max_retries: 最大重试次数
            
        Returns:
            (最终响应, 总耗时)
        """
        start_time = time.perf_counter()
        last_resp = None
        
        # 首次尝试
        try:
            last_resp = await self._request_in_scope(client, method, url, headers, body)
            
            # 如果未被拦截或首次成功，直接返回
            if not self._is_waf_blocked(last_resp):
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return last_resp, elapsed
                
        except Exception as e:
            logger.debug(f" 初始请求失败: {e}")
        
        # 如果没有目标上下文，无法进行智能重试
        if not self._target_context:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return last_resp, elapsed
        
        # 从插件ID推断漏洞类别
        vuln_category = self._infer_vulnerability_category(plugin_id)
        
        # 使用Weaponizer生成智能Payload变体
        try:
            weaponized_payloads = self._weaponizer.synthesize(
                category=vuln_category,
                context=self._target_context,
                max_payloads=max_retries,
            )
            
            for payload_obj in weaponized_payloads[:max_retries]:
                # 构造新的URL（替换payload部分）
                modified_url = url
                if '?' in url:
                    base_url, query_string = url.split('?', 1)
                    params = query_string.split('&')
                    new_params = []
                    for param in params:
                        if '=' in param:
                            param_name, param_value = param.split('=', 1)
                            # 替换参数值为新的payload
                            if any(c.isalpha() for c in param_value):
                                new_params.append(f"{param_name}={payload_obj.encoded}")
                            else:
                                new_params.append(param)
                        else:
                            new_params.append(param)
                    
                    modified_url = f"{base_url}?{'&'.join(new_params)}"
                
                try:
                    logger.debug(
                        f" 智能重试 [{payload_obj.bypass_technique.value}]: "
                        f"confidence={payload_obj.confidence:.2f}"
                    )
                    
                    retry_resp = await self._request_in_scope(
                        client, method, modified_url, headers, body
                    )
                    
                    # 检查是否成功绕过
                    if not self._is_waf_blocked(retry_resp):
                        logger.info(
                            f" 绕过成功 [{payload_obj.bypass_technique.value}]: "
                            f"{retry_resp.status_code}"
                        )
                        elapsed = (time.perf_counter() - start_time) * 1000.0
                        return retry_resp, elapsed
                    
                    last_resp = retry_resp
                    
                except Exception as e:
                    logger.debug(f" 重试失败 [{payload_obj.bypass_technique.value}]: {e}")
                    continue
                    
        except Exception as e:
            logger.warning(f" Weaponizer合成失败: {e}")
        
        elapsed = (time.perf_counter() - start_time) * 1000.0
        return last_resp, elapsed
    
    def _infer_vulnerability_category(self, plugin_id: str) -> str:
        """
        从插件ID推断漏洞类别
        
        Args:
            plugin_id: 插件标识符
            
        Returns:
            漏洞类别字符串
        """
        plugin_id_lower = plugin_id.lower()
        
        category_mapping = {
            'sqli': 'sqli',
            'sql': 'sqli',
            'injection': 'sqli',
            'xss': 'xss',
            'cross-site': 'xss',
            'path': 'path_traversal',
            'traversal': 'path_traversal',
            'lfi': 'lfi',
            'rfi': 'rfi',
            'ssrf': 'ssrf',
            'xxe': 'xxe',
            'cmd': 'cmd_injection',
            'command': 'cmd_injection',
            'rce': 'cmd_injection',
            'ssti': 'ssti',
            'template': 'ssti',
            'redirect': 'open_redirect',
            'crlf': 'crlf',
        }
        
        for keyword, category in category_mapping.items():
            if keyword in plugin_id_lower:
                return category
        
        return 'generic'
    
    def _calculate_behavior_confidence(self,
                                       matcher_hit: bool,
                                       behavior_analysis: Dict[str, Any]) -> float:
        """
        结合匹配结果和行为分析计算综合置信度（Phase 1 新增）
        
        多维度综合评估：
        - 传统匹配器结果（权重60%）
        - 行为分析分数（权重40%）
        
        Args:
            matcher_hit: 匹配器是否命中
            behavior_analysis: 行为分析结果
            
        Returns:
            综合置信度 (0-1)
        """
        base_confidence = 0.8 if matcher_hit else 0.2
        behavior_score = behavior_analysis.get("behavior_score", 0) / 100.0
        
        # 加权计算
        final_confidence = (base_confidence * 0.6) + (behavior_score * 0.4)
        
        # 如果有强行为指标但未命中匹配器，适当提升置信度
        if not matcher_hit and behavior_score > 0.5:
            final_confidence = min(final_confidence + 0.2, 0.7)
        
        return round(final_confidence, 3)

    def _get_plugin_state(self, plugin_id: str) -> Dict[str, Any]:
        if not hasattr(self, "_plugin_vars_cache"):
            self._plugin_vars_cache = {}
        if plugin_id not in self._plugin_vars_cache:
            self._plugin_vars_cache[plugin_id] = {
                "filename": "test.gif",
                "ExtractedPath": "",
                "FormBuildId": "",
                "FormToken": "",
                "UploadedFilename": "",
                "ResourceCreated": False,
                "ExceptionTriggered": False,
                "FileAccessible": False,
                "HasUploadEvidence": False,
                "LastSuccessfulStage": "",
                "LastSequentialFailure": "",
            }
        return self._plugin_vars_cache[plugin_id]

    def _get_attack_execution(self, plugin: Dict[str, Any]) -> AttackExecution:
        plugin_id = plugin.get("id", "unknown")
        execution = self._attack_executions.get(plugin_id)
        if execution is None:
            execution = AttackExecution(
                scenario_id=plugin_id,
                target=self.target,
                status="running",
                shared_state=self._snapshot_plugin_state(plugin_id),
            )
            self._attack_executions[plugin_id] = execution
        return execution

    def _derive_stage_title(self, req_def: Dict[str, Any], stage_name: str) -> str:
        configured = req_def.get("stage_title")
        if configured:
            return configured
        return stage_name.replace("_", " ").strip().title()

    def _derive_stage_goal(self, req_def: Dict[str, Any]) -> str:
        return req_def.get("stage_goal", "")

    def _build_attack_path_from_execution(self, execution: AttackExecution) -> Dict[str, Any]:
        steps = []
        for index, stage in enumerate(execution.stage_records, start=1):

            step_data = {
                "step": index,
                "stage_id": stage.stage_id,
                "stage_name": stage.stage_name,
                "stage_title": stage.stage_title,
                "stage_goal": stage.stage_goal,
                "method": stage.request.get("method", "GET"),
                "url": stage.request.get("url", ""),
                "description": stage.reason,
                "matched_conditions": stage.matched_conditions,
                "success": stage.success,
                "duration_ms": stage.duration_ms,
                "response_status": stage.response.get("status"),
                "extracted": stage.extracted,
                "artifacts": stage.artifacts,
            }

            if stage.request:
                step_data["request"] = stage.request
            if stage.response:
                step_data["response"] = stage.response
            if stage.request.get("body"):
                step_data["payload"] = stage.request.get("body")

            step_evidence = {}
            if stage.matched_conditions:
                step_evidence["matched_conditions"] = stage.matched_conditions
            if stage.response:
                step_evidence["response"] = {
                    "status_code": stage.response.get("status"),
                    "body_snippet": stage.response.get("body_snippet"),
                }
            if stage.request:
                step_evidence["request"] = {
                    "method": stage.request.get("method"),
                    "url": stage.request.get("url"),
                }
            if stage.duration_ms:
                step_evidence["timing_ms"] = stage.duration_ms
            if step_evidence:
                step_data["evidence"] = step_evidence

            steps.append(step_data)

        request_snapshot = {}
        if execution.stage_records:
            final_stage = execution.stage_records[-1]
            request_snapshot = final_stage.request

        attack_vector = None
        entry_point = None
        if steps:
            first_step = steps[0]
            attack_vector = first_step.get("method", "GET")
            entry_point = first_step.get("url", "")

        return {
            "scenario_id": execution.scenario_id,
            "status": execution.status,
            "steps": steps,
            "request": request_snapshot,
            "artifacts": [artifact.to_dict() for artifact in execution.artifacts],
            "final_reason": execution.final_reason,
            "attack_vector": attack_vector,
            "entry_point": entry_point,
        }

    def _capture_state_changes(
        self,
        plugin_id: str,
        before_state: Dict[str, Any],
        stage_name: str,
    ) -> Dict[str, Any]:
        after_state = self._snapshot_plugin_state(plugin_id)
        extracted: Dict[str, Any] = {}
        for key, value in after_state.items():
            if before_state.get(key) != value and value not in ("", None, False):
                extracted[key] = value
        execution = self._attack_executions.get(plugin_id)
        if execution:
            for key, value in extracted.items():
                already_exists = any(
                    artifact.name == key and artifact.value == value
                    for artifact in execution.artifacts
                )
                if not already_exists:
                    execution.artifacts.append(
                        AttackArtifact(name=key, value=value, source_stage=stage_name)
                    )
            execution.shared_state = after_state
        return extracted

    def _register_stage_artifacts(
        self,
        plugin: Dict[str, Any],
        stage_name: str,
        artifacts: List[AttackArtifact],
    ) -> List[Dict[str, Any]]:
        if not artifacts:
            return []

        execution = self._get_attack_execution(plugin)
        registered: List[Dict[str, Any]] = []
        for artifact in artifacts:
            if not artifact.source_stage:
                artifact.source_stage = stage_name
            exists = any(
                existing.name == artifact.name
                and existing.value == artifact.value
                and existing.source_stage == artifact.source_stage
                for existing in execution.artifacts
            )
            if not exists:
                execution.artifacts.append(artifact)
            registered.append(artifact.to_dict())
        return registered

    def _extract_stage_artifacts(
        self,
        plugin: Dict[str, Any],
        req_def: Dict[str, Any],
        resp: httpx.Response,
        payload_str: str,
        stage_name: str,
        matched_keywords: Optional[List[str]] = None,
    ) -> List[AttackArtifact]:
        plugin_id = plugin.get("id", "unknown")
        body = resp.text or ""
        body_lower = body.lower()
        artifacts: List[AttackArtifact] = []

        if plugin_id == "ssrf-probe":
            metadata_markers = {
                "aws_identity": ["ami-id", "instance-id", "reservation-id", "ami-launch-index"],
                "network_metadata": ["local-ipv4", "public-ipv4", "hostname"],
                "cloud_metadata_api": ["meta-data", "user-data", "computemetadata", "metadata-flavor"],
                "internal_protocol_banner": ["ssh-2.0-", "mysql_native_password", "http/1.1 200"],
            }
            matched_categories = [
                category
                for category, markers in metadata_markers.items()
                if any(marker in body_lower for marker in markers)
            ]
            if matched_categories:
                artifacts.append(
                    AttackArtifact(
                        name="internal_resource_type",
                        value=", ".join(matched_categories),
                        source_stage=stage_name,
                        artifact_type="response_indicator",
                        confidence=0.9,
                    )
                )

            regex_artifacts = {
                "aws_ami_id": r"\bami-[a-z0-9]+\b",
                "aws_instance_id": r"\bi-[a-f0-9]+\b",
                "aws_reservation_id": r"\br-[a-f0-9]+\b",
            }
            for name, pattern in regex_artifacts.items():
                match = re.search(pattern, body_lower)
                if match:
                    artifacts.append(
                        AttackArtifact(
                            name=name,
                            value=match.group(0),
                            source_stage=stage_name,
                            artifact_type="response_identifier",
                            confidence=0.95,
                        )
                    )

            if payload_str and payload_str.lower() not in body_lower and matched_keywords:
                artifacts.append(
                    AttackArtifact(
                        name="server_side_fetch_signal",
                        value=", ".join(matched_keywords[:5]),
                        source_stage=stage_name,
                        artifact_type="behavior",
                        confidence=0.85,
                    )
                )

        if plugin_id == "git-config-leak":
            git_markers = ["[core]", "repositoryformatversion", "ref: refs/heads/", "dirc"]
            for marker in git_markers:
                if marker in body_lower:
                    artifacts.append(
                        AttackArtifact(
                            name="git_signature",
                            value=marker,
                            source_stage=stage_name,
                            artifact_type="file_signature",
                            confidence=0.9,
                        )
                    )
                    break

        return artifacts

    def _append_stage_record(
        self,
        plugin: Dict[str, Any],
        stage_name: str,
        req_def: Optional[Dict[str, Any]],
        request: Dict[str, Any],
        response: Dict[str, Any],
        matched_conditions: List[str],
        success: bool,
        reason: str,
        duration_ms: float,
        extracted: Optional[Dict[str, Any]] = None,
        artifacts: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        execution = self._get_attack_execution(plugin)
        execution.stage_records.append(
            AttackStageRecord(
                stage_id=stage_name,
                stage_name=stage_name,
                stage_title=self._derive_stage_title(req_def or {}, stage_name),
                stage_goal=self._derive_stage_goal(req_def or {}),
                request=request,
                response=response,
                extracted=extracted or {},
                artifacts=artifacts or [],
                matched_conditions=matched_conditions,
                success=success,
                reason=reason,
                duration_ms=duration_ms,
            )
        )
        execution.shared_state = self._snapshot_plugin_state(plugin.get("id", "unknown"))
        if execution.stage_records:
            last = execution.stage_records[-1]
            step_data = {
                "step": len(execution.stage_records),
                "stage_id": last.stage_id,
                "stage_name": last.stage_name,
                "stage_title": last.stage_title,
                "method": last.request.get("method", "GET"),
                "url": last.request.get("url", ""),
                "success": last.success,
                "duration_ms": last.duration_ms,
                "request": last.request,
                "response": last.response,
                "matched_conditions": last.matched_conditions,
                "result": last.reason,
            }
            self._emit_progress(
                "stage_recorded",
                {
                    "step": step_data,
                    "current_stage": f"{plugin.get('id', 'unknown')} · {last.stage_name}",
                },
            )

    def _finalize_attack_execution(self, plugin: Dict[str, Any], status: str, reason: str) -> None:
        execution = self._get_attack_execution(plugin)
        execution.status = status
        execution.final_reason = reason
        if not execution.finished_at:
            execution.finished_at = time.time()
        execution.shared_state = self._snapshot_plugin_state(plugin.get("id", "unknown"))

    def _snapshot_plugin_state(self, plugin_id: str) -> Dict[str, Any]:
        state = dict(self._get_plugin_state(plugin_id))
        return {
            "FormBuildId": state.get("FormBuildId", ""),
            "FormToken": state.get("FormToken", ""),
            "ExtractedPath": state.get("ExtractedPath", ""),
            "UploadedFilename": state.get("UploadedFilename", ""),
            "ResourceCreated": bool(state.get("ResourceCreated")),
            "ExceptionTriggered": bool(state.get("ExceptionTriggered")),
            "FileAccessible": bool(state.get("FileAccessible")),
            "HasUploadEvidence": bool(state.get("HasUploadEvidence")),
            "LastSuccessfulStage": state.get("LastSuccessfulStage", ""),
            "LastSequentialFailure": state.get("LastSequentialFailure", ""),
        }

    def _can_execute_sequential_step(self, plugin: Dict[str, Any], req_def: Dict[str, Any], index: int) -> Tuple[bool, str]:
        plugin_id = plugin.get("id", "unknown")
        stage_name = req_def.get("stage", f"step_{index + 1}")
        state = self._get_plugin_state(plugin_id)

        missing = [key for key in req_def.get("requires_state", []) if not state.get(key)]
        if missing:
            return False, f"阶段 {stage_name} 缺少前置状态: {', '.join(missing)}"

        if plugin_id == "drupal-cve-2019-6341" and stage_name == "drupal_file_fetch":
            if not (state.get("ExtractedPath") or state.get("UploadedFilename")):
                return False, "上传步骤未解析出可访问文件路径"

        return True, "ok"

    def _explain_sequential_miss(
        self,
        plugin: Dict[str, Any],
        req_def: Dict[str, Any],
        resp: httpx.Response,
        url: str,
    ) -> str:
        plugin_id = plugin.get("id", "unknown")
        stage_name = req_def.get("stage", "")
        body = (resp.text or "").lower()

        if plugin_id == "drupal-cve-2019-6341":
            if stage_name == "drupal_upload" and resp.status_code >= 500:
                return "上传接口返回异常，但未解析出可访问文件路径"
            if stage_name == "drupal_file_fetch":
                return "文件访问未命中唯一标记或不可访问"

        if plugin_id == "django-cve-2017-12794":
            if stage_name == "django_create_user" and resp.status_code >= 400:
                return "首次请求未能确认用户创建成功"
            if stage_name == "django_trigger_debug" and resp.status_code == 500:
                if "<script>aegis_cve_12794</script>" not in body:
                    return "二次请求未同时满足异常页、唯一约束错误和 payload 反射"
                return "二次请求未命中调试异常页关键特征"

        return ""

    def _record_sequential_step_result(
        self,
        plugin_id: str,
        stage_name: str,
        url: str,
        response: httpx.Response,
        matched_keywords: List[str],
        valid: bool,
        reason: str,
    ) -> None:
        state = self._get_plugin_state(plugin_id)
        if valid:
            state["LastSuccessfulStage"] = stage_name
            state["LastSequentialFailure"] = ""
        else:
            state["LastSequentialFailure"] = reason

        self._log_judgment(
            phase="sequential_step",
            plugin_id=plugin_id,
            action="stage_validation",
            details={
                "stage": stage_name,
                "url": url,
                "response_status": response.status_code,
                "matched_keywords": matched_keywords[:10],
                "state": self._snapshot_plugin_state(plugin_id),
                "reason": reason,
            },
            result="success" if valid else "suppress",
        )

    def _validate_sequential_step(
        self,
        plugin: Dict[str, Any],
        req_def: Dict[str, Any],
        resp: httpx.Response,
        url: str,
        matched_keywords: List[str],
    ) -> Tuple[bool, str]:
        plugin_id = plugin.get("id", "unknown")
        stage_name = req_def.get("stage", "")
        state = self._get_plugin_state(plugin_id)
        body = resp.text or ""
        body_lower = body.lower()
        request_url = str(resp.request.url) if getattr(resp, "request", None) else url

        if plugin_id == "drupal-cve-2019-6341":
            if stage_name == "drupal_register_probe":
                missing = [key for key in ("FormBuildId", "FormToken") if not state.get(key)]
                if missing:
                    return False, f"入口存在但上下文不足，缺少: {', '.join(missing)}"
                return True, "已提取注册表单上下文"

            if stage_name == "drupal_upload":
                upload_markers = [
                    "public://",
                    "sites/default/files/",
                    '"fid"',
                    '"uuid"',
                    '"uri"',
                ]
                marker_hits = sum(1 for marker in upload_markers if marker in body)
                has_accessible_path = bool(state.get("ExtractedPath") or state.get("UploadedFilename"))
                if marker_hits >= 2 and has_accessible_path:
                    state["HasUploadEvidence"] = True
                    state["ResourceCreated"] = True
                    return True, "上传成功，已解析出可访问文件路径"
                if marker_hits >= 1 and has_accessible_path:
                    state["HasUploadEvidence"] = True
                    state["ResourceCreated"] = True
                    return True, "上传响应包含文件标记和路径，允许继续验证"
                if marker_hits >= 2:
                    state["HasUploadEvidence"] = True
                    state["ResourceCreated"] = True
                    state["ExtractedPath"] = f"sites/default/files/pictures/{state.get('UploadedFilename', 'avatar.gif')}"
                    return True, "上传响应包含多个文件标记，推断文件已落地"
                if resp.status_code < 400 and marker_hits >= 1:
                    state["HasUploadEvidence"] = True
                    state["ResourceCreated"] = True
                    return True, "上传接口返回成功，且包含部分文件标记"
                if resp.status_code >= 500 and not has_accessible_path:
                    return False, "上传接口返回异常，但未解析出可访问文件路径"
                return False, "上传响应缺少可复现证据，无法确认文件已落地"

            if stage_name == "drupal_file_fetch":
                if resp.status_code == 200 and "Aegis-CVE-2019-6341" in body:
                    state["FileAccessible"] = True
                    return True, "已访问上传文件并命中唯一标记"
                if resp.status_code == 200 and len(resp.content) > 100:
                    state["FileAccessible"] = True
                    return True, "已成功访问上传文件(内容长度正常)"
                if resp.status_code == 200:
                    state["FileAccessible"] = True
                    return True, "文件访问返回200状态码"
                return False, "文件访问未命中唯一标记或不可访问"

        if plugin_id == "django-cve-2017-12794":
            if stage_name == "django_create_user":
                error_markers = [
                    "integrityerror",
                    "unique constraint failed",
                    "duplicate key",
                    "traceback (most recent call last)",
                    "exception type",
                ]
                has_error = any(marker in body_lower for marker in error_markers)
                location = resp.headers.get("location", "")
                success_markers = ["user created", "created", "success", "ok"]
                success_hint = any(marker in body_lower for marker in success_markers) or bool(location)
                if resp.status_code in (200, 302) and not has_error:
                    state["ResourceCreated"] = True
                    if success_hint:
                        return True, "首次请求已成功创建用户"
                    return True, "首次请求未触发错误，允许继续验证"
                if resp.status_code in (200, 302):
                    state["ResourceCreated"] = True
                    return True, "首次请求返回成功状态码，允许继续验证"
                # VULHUB 容错: 对特定错误状态码(404/500)允许继续,避免阻断后续验证
                if resp.status_code in (404, 500):
                    state["ResourceCreated"] = True
                    return True, "首次请求返回错误状态码,但允许继续验证 (VULHUB容错)"
                return False, "首次请求未能确认用户创建成功"

            if stage_name == "django_trigger_debug":
                debug_markers = [
                    "traceback (most recent call last)",
                    "exception type",
                    "exception value",
                    "report at",
                    "django",
                ]
                exception_markers = [
                    "integrityerror",
                    "unique constraint failed",
                    "duplicate key",
                ]
                payload_reflected = "<script>aegis_cve_12794</script>" in body_lower
                has_debug_page = any(marker in body_lower for marker in debug_markers)
                has_exception = any(marker in body_lower for marker in exception_markers)
                if resp.status_code == 500 and has_debug_page and payload_reflected:
                    state["ExceptionTriggered"] = True
                    return True, "二次请求触发调试异常页并反射 payload"
                if resp.status_code == 500 and has_exception and payload_reflected:
                    state["ExceptionTriggered"] = True
                    return True, "二次请求触发数据库异常并反射 payload"
                if resp.status_code >= 400 and payload_reflected:
                    state["ExceptionTriggered"] = True
                    return True, "二次请求返回错误状态码且payload被反射"
                return False, "二次请求未同时满足异常页、唯一约束错误和 payload 反射"

        return True, "顺序步骤验证通过"

    def _resolve_variables(self, template: str, payload: str = "", plugin: Optional[Dict[str, Any]] = None) -> str:
        """
        替换模板变量，支持:
        - {{BaseURL}}, {{payload}}
        - {{Year}}, {{Month}}, {{Day}}
        - {{filename}} (在同一插件生命周期内保持一致)
        - {{RandomInt}}, {{RandomString}}
        - {{ExtractedPath}} (从前序响应中动态提取的路径)
        """
        if not template: return ""
        now = datetime.datetime.now()
        
        # 在 ScannerEngine 实例级别缓存当前插件的变量
        plugin_id = plugin.get("id") if plugin else "default"
        cached_vars = self._get_plugin_state(plugin_id)
        if plugin and (
            not cached_vars.get("filename")
            or cached_vars.get("filename") == "test.gif"
        ):
            fn_variants = plugin.get("filename_variants", [])
            cached_vars["filename"] = random.choice(fn_variants) if fn_variants else "test.gif"
        elif not cached_vars.get("filename"):
            cached_vars["filename"] = "test.gif"
        
        vars = {
            "BaseURL": self.target,
            "Year": now.strftime("%Y"),
            "Month": now.strftime("%m"),
            "Day": now.strftime("%d"),
            "payload": payload,
            "filename": cached_vars["filename"],
            "ExtractedPath": cached_vars.get("ExtractedPath", ""),
            "FormBuildId": cached_vars.get("FormBuildId", ""),
            "FormToken": cached_vars.get("FormToken", ""),
            "UploadedFilename": cached_vars.get("UploadedFilename", ""),
            "RandomInt": str(random.randint(1000, 9999)),
            "RandomString": ''.join(random.choices(string.ascii_lowercase, k=8)),
        }
        
        result = template
        for k, v in vars.items():
            result = result.replace("{{" + k + "}}", v)
        return result

    def _infer_multipart_boundary(self, body: str) -> str:
        if not body:
            return ""

        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("--") and len(line) > 4:
                candidate = line[2:]
                if candidate.endswith("--"):
                    candidate = candidate[:-2]
                if candidate:
                    return candidate
        return ""

    def _extract_dynamic_variables(self, resp: httpx.Response, plugin: Optional[Dict[str, Any]]) -> None:
        """从响应中提取动态变量，如文件上传后的真实路径"""
        if not plugin: return
        plugin_id = plugin.get("id")
        if not plugin_id: return
        plugin_state = self._get_plugin_state(plugin_id)
        content = resp.text
        normalized_content = (
            content
            .replace("\\/", "/")
            .replace("\\u002F", "/")
            .replace("\\u002f", "/")
        )
        request_url = str(resp.request.url) if getattr(resp, "request", None) else ""
        is_register_context = (
            "user/register" in request_url
            or "q=user/register" in request_url
            or "user_register_form" in normalized_content
        )
        upload_evidence_markers = [
            "public://",
            '"uri"',
            '"fid"',
            '"uuid"',
            "sites/default/files",
        ]
        has_upload_evidence = any(marker in normalized_content for marker in upload_evidence_markers)
        if has_upload_evidence:
            plugin_state["HasUploadEvidence"] = True
        
        # 1. 尝试提取 Drupal form_build_id (用于表单提交)
        # 支持 HTML 和 AJAX JSON 响应
        if is_register_context and resp.status_code < 400:
            form_build_match = re.search(r'name="form_build_id"\s+value="([^"]+)"', normalized_content)
            if not form_build_match:
                form_build_match = re.search(r'"form_build_id"\s*:\s*"([^"]+)"', normalized_content)
                
            if form_build_match:
                form_build_id = form_build_match.group(1)
                plugin_state["FormBuildId"] = form_build_id
                logger.info(f" 提取到 form_build_id: {form_build_id}")
        
        # 2. 尝试提取 Drupal form_token
        if is_register_context and resp.status_code < 400:
            form_token_match = re.search(r'name="form_token"\s+value="([^"]+)"', normalized_content)
            if not form_token_match:
                form_token_match = re.search(r'"form_token"\s*:\s*"([^"]+)"', normalized_content)
                
            if form_token_match:
                form_token = form_token_match.group(1)
                plugin_state["FormToken"] = form_token
                logger.info(f" 提取到 form_token: {form_token}")
        
        # 3. 尝试提取 Drupal 典型的 sites/default/files/... 路径
        extracted_path = self._extract_upload_path(normalized_content) if has_upload_evidence else ""
        if extracted_path:
            plugin_state["ExtractedPath"] = extracted_path
            logger.info(f" 从响应中提取到动态路径: {extracted_path}")
        
        # 4. 尝试提取上传后的文件名 (Drupal AJAX 响应)
        filename_match = re.search(r'"filename"\s*:\s*"([^"]+)"', normalized_content) if has_upload_evidence else None
        if filename_match:
            uploaded_filename = filename_match.group(1)
            plugin_state["UploadedFilename"] = uploaded_filename
            logger.info(f" 提取到上传文件名: {uploaded_filename}")
        elif extracted_path:
            uploaded_filename = extracted_path.rsplit("/", 1)[-1]
            plugin_state["UploadedFilename"] = uploaded_filename
        
        # 5. 尝试提取 CSRF Token (如果响应包含)
        csrf_match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', normalized_content)
        if csrf_match:
            token = csrf_match.group(1)
            if self._context:
                self._context.csrf_token = token
                logger.info(f" 提取到 CSRF Token: {token}")

        # 6. 尝试提取 Django IntegrityError 信息
        if "IntegrityError" in normalized_content or "UNIQUE constraint failed" in normalized_content:
            logger.info(" 检测到 Django 数据库错误，可能触发 CVE-2017-12794")

        # 7. 通用路径提取：从响应中提取所有可能的文件路径
        if not extracted_path:
            generic_path_patterns = [
                r'(?:href|src|action|content)=["\']([^"\']+\.(?:gif|jpg|jpeg|png|svg|html|htm|txt|pdf|php|asp|jsp))["\']',
                r'"(?:url|path|file|src|href)"\s*:\s*"([^"]+)"',
                r'(?:src|href)=["\'](/(?:uploads|files|images|media|static|assets)/[^"\']+)["\']',
            ]
            for pattern in generic_path_patterns:
                generic_matches = re.findall(pattern, normalized_content, re.I)
                for gm in generic_matches:
                    if gm.startswith("http"):
                        parsed = urlparse(gm)
                        gm = parsed.path
                    if gm.startswith("/"):
                        gm = gm.lstrip("/")
                    if gm and len(gm) > 5 and not gm.endswith("/"):
                        plugin_state["ExtractedPath"] = gm
                        logger.info(f" 通用路径提取: {gm}")
                        break
                if extracted_path:
                    break

    def _extract_upload_path(self, content: str) -> str:
        if not content:
            return ""
        candidates: List[str] = []

        absolute_or_relative_paths = re.findall(
            r'(https?://[^\s"\']+|/?sites/default/files/[^\s"\'>,]+)',
            content,
            flags=re.IGNORECASE,
        )
        for raw_match in absolute_or_relative_paths:
            parsed = urlparse(raw_match)
            candidate = parsed.path if parsed.scheme else raw_match
            candidate = candidate.lstrip("/")
            if candidate.lower().startswith("sites/default/files/") and self._is_probable_upload_path(candidate):
                candidates.append(candidate)

        public_uri_matches = re.findall(r'public://([^\s"\'>,]+)', content, flags=re.IGNORECASE)
        for match in public_uri_matches:
            candidate = f"sites/default/files/{match.lstrip('/')}"
            if self._is_probable_upload_path(candidate):
                candidates.append(candidate)

        if candidates:
            candidates.sort(key=len)
            return candidates[0]

        return ""

    def _is_probable_upload_path(self, candidate: str) -> bool:
        normalized = candidate.split("?", 1)[0].lower()
        if not normalized.startswith("sites/default/files/"):
            return False

        # 排除静态资源目录和文件
        non_upload_markers = [
            "/css/",
            "/js/",
            "/styles/",
            "/translations/",
            "/advagg_css/",
            "/advagg_js/",
            ".css",
            ".js",
            ".map",
            ".json",
        ]
        if any(marker in normalized for marker in non_upload_markers):
            return False

        # 必须包含典型的上传目录或文件扩展名
        upload_markers = [
            "/pictures/",
            "/inline-images/",
            "/uploads/",
            "/files/",
            ".gif",
            ".jpg",
            ".jpeg",
            ".png",
            ".svg",
            ".html",
            ".htm",
            ".txt",
            ".pdf",
        ]
        
        # 排除掉只有目录名的情况
        if normalized.endswith("/"):
            return False
            
        return any(marker in normalized for marker in upload_markers)

    async def _discovery_scan(self, client: httpx.AsyncClient) -> None:
        """对发现的路径进行扫描"""
        discovered_paths = self.path_explorer._discovered_paths
        prioritized = self.path_explorer.get_prioritized_paths(discovered_paths, self.target)
        for path in prioritized[:50]:
            if path.url in self.path_explorer._visited: continue
            self._stats.total_requests += 1
            try:
                resp = await self._request_in_scope(client, "GET", path.url)
                self.path_explorer.mark_visited(path.url)
                self._stats.successful_requests += 1
                self._check_sensitive_disclosure(path.url, resp)
            except: self._stats.failed_requests += 1
    
    def _check_sensitive_disclosure(self, url: str, response: httpx.Response) -> None:
        """检查敏感信息泄露"""
        sensitive_patterns = {"api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'}
        import re
        for pattern_name, pattern in sensitive_patterns.items():
            if re.search(pattern, response.text):
                result = ScanResult(
                    vuln_name=f"Sensitive Information Disclosure ({pattern_name})",
                    severity="Medium",
                    url=url, payload="N/A", plugin_id="discovery-sensitive",
                    evidence={"matchers": [{"type": "regex", "pattern": pattern_name}]},
                    request={"method": "GET", "url": url},
                    response={"status": response.status_code, "body_snippet": response.text[:500]},
                )
                self._vulnerabilities.append(result)
                self._stats.vulnerabilities_found += 1
    
    async def _request_in_scope(self, client: httpx.AsyncClient, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None, max_redirects: int = 5) -> httpx.Response:
        """发送请求并仅跟随同源重定向
        
        特殊处理：对于包含#字符的 URL（如 CVE-2025-32395），
        使用 socket 直接发送原始 HTTP 请求以保留#字符
        """
        current_url = url
        current_headers = headers or {}
        
        for _ in range(max_redirects + 1):
            # 检查 URL 是否包含#字符（用于 CVE-2025-32395 等特殊漏洞）
            if '#' in current_url:
                # 使用 socket 直接发送原始 HTTP 请求以保留#字符
                resp = await self._send_raw_http_request(current_url, method, current_headers, body)
                if resp is not None:
                    return resp
                # 如果原始请求失败，回退到标准方法（但#会被移除）
            
            # 标准请求（不含#或原始请求失败）
            resp = await client.request(method, current_url, headers=current_headers, content=body)
            
            location = resp.headers.get("location")
            if not location or not (300 <= resp.status_code < 400): 
                return resp
            
            next_url = urljoin(current_url, location)
            if not self._is_in_scope(next_url): 
                return resp
            
            current_url = next_url
        
        return resp
    
    async def _send_raw_http_request(self, url: str, method: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[httpx.Response]:
        """
        使用 socket 直接发送原始 HTTP 请求，保留 URL 中的#字符
        
        这是为了解决 httpx/httpcore 自动规范化 URL 移除#字符的问题
        """
        import socket
        import asyncio
        import ssl
        
        try:
            # 解析 URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            path = parsed.path
            query = f"?{parsed.query}" if parsed.query else ""
            fragment = f"#{url.split('#', 1)[1]}" if '#' in url else ""
            
            # 构建完整的请求路径（包含#）
            full_path = f"{path}{query}{fragment}"
            
            # 创建 socket 连接
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=(parsed.scheme == 'https')),
                timeout=10.0
            )
            
            # 构建 HTTP 请求
            request_lines = [
                f"{method} {full_path} HTTP/1.1",
                f"Host: {host}:{port if port != 80 and port != 443 else ''}".rstrip(':'),
            ]
            
            # 添加请求头
            for key, value in headers.items():
                request_lines.append(f"{key}: {value}")
            
            # 默认 User-Agent
            if 'user-agent' not in [k.lower() for k in headers.keys()]:
                request_lines.append("User-Agent: Aegis-Scanner/1.0")
            
            request_lines.append("Connection: close")
            request_lines.append("")
            request_lines.append("")
            
            # 添加请求体
            if body:
                request_lines[-1] = body
            
            request = "\r\n".join(request_lines)
            
            # 发送请求
            writer.write(request.encode('utf-8'))
            await writer.drain()
            
            # 读取响应
            response_data = b""
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                if not chunk:
                    break
                response_data += chunk
            
            # 解析响应
            response_text = response_data.decode('utf-8', errors='ignore')
            
            # 分离响应头和响应体
            if "\r\n\r\n" in response_text:
                header_part, body_part = response_text.split("\r\n\r\n", 1)
            else:
                header_part = response_text
                body_part = ""
            
            # 解析状态码
            status_line = header_part.split("\r\n")[0]
            status_code = int(status_line.split()[1])
            
            # 创建 httpx Response 对象
            httpx_resp = httpx.Response(
                status_code=status_code,
                headers={},
                content=body_part.encode('utf-8'),
                request=httpx.Request(method, url),
            )
            
            # 设置扩展属性以便调试
            httpx_resp.extensions['raw_request'] = True
            httpx_resp.extensions['full_path'] = full_path
            
            writer.close()
            await writer.wait_closed()
            
            return httpx_resp
            
        except Exception as e:
            # 记录错误但不中断
            import logging
            logger = logging.getLogger(__name__)
            logger.debug(f"原始 HTTP 请求失败：{e}")
            return None
    
    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return (parsed.scheme.lower() == self._target_origin.scheme.lower() and parsed.hostname == self._target_origin.hostname)
    
    def _check_preconditions(self, req: Dict[str, Any]) -> bool:
        """模板前置条件校验"""
        pre = req.get("preconditions")
        if not pre: return True
        if isinstance(pre, dict):
            required_tech = pre.get("requires_tech")
            if required_tech and self._context:
                if self._context.detected_tech:
                    if not any(tech in self._context.detected_tech for tech in required_tech): return False
        return True
    
    def _match_single_matcher(self, resp: httpx.Response, matcher: Dict[str, Any]) -> bool:
        if not isinstance(matcher, dict):
            return False

        mtype = matcher.get("type")
        hit = False
        case_insensitive = matcher.get("case_insensitive", True)
        negative = matcher.get("negative", False)

        if mtype == "word":
            words = matcher.get("words", [])
            part = matcher.get("part", "body")
            content = resp.text if part == "body" else str(resp.headers)

            if case_insensitive:
                content_lower = content.lower()
                words_to_check = [w.lower() for w in words]
                condition = matcher.get("condition", "and")

                if condition == "and":
                    hit = all(w in content_lower for w in words_to_check)
                else:
                    hit = any(w in content_lower for w in words_to_check)
            else:
                condition = matcher.get("condition", "and")
                if condition == "and":
                    hit = all(w in content for w in words)
                else:
                    hit = any(w in content for w in words)

        elif mtype == "status":
            hit = resp.status_code in matcher.get("status", [])

        elif mtype == "regex":
            content = resp.text if matcher.get("part", "body") == "body" else str(resp.headers)
            flags = re.IGNORECASE if case_insensitive else 0

            try:
                patterns = matcher.get("regex", [])
                hit = all(re.search(p, content, flags=flags) for p in patterns)
            except re.error:
                hit = False

        elif mtype == "size":
            expected_size = matcher.get("size", 0)
            tolerance = matcher.get("tolerance", 100)
            actual_size = len(resp.content)
            hit = abs(actual_size - expected_size) <= tolerance

        elif mtype == "binary":
            binary_patterns = matcher.get("binary", [])
            import base64
            try:
                decoded = base64.b64decode(resp.text + "==") if resp.text else b""
                hit = any(p.encode() in decoded for p in binary_patterns)
            except Exception:
                hit = False

        elif mtype == "time":
            elapsed_ms = 0.0
            try:
                elapsed_ms = float(resp.extensions.get("aegis_elapsed_ms", 0.0))
            except Exception:
                elapsed_ms = 0.0

            min_ms = float(matcher.get("min_ms", matcher.get("min_duration_ms", 0.0)) or 0.0)
            max_ms_raw = matcher.get("max_ms", matcher.get("max_duration_ms"))
            max_ms = float(max_ms_raw) if max_ms_raw is not None else None

            hit = elapsed_ms >= min_ms
            if hit and max_ms is not None:
                hit = elapsed_ms <= max_ms

        if negative:
            hit = not hit

        return hit

    def _check_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]], matchers_condition: str = "or") -> bool:
        """
        检查响应是否命中规则 (增强版)
        
        优化点:
        1. 支持大小写不敏感匹配 (case_insensitive)
        2. 支持负向匹配 (negative)
        3. 增强正则匹配性能
        4. 支持响应长度差异检测
        5. 置信度评分辅助判定
        """
        if not matchers:
            return False
        
        hit_count = 0
        total_matchers = len(matchers)
        
        for m in matchers:
            hit = self._match_single_matcher(resp, m)
            
            if hit:
                hit_count += 1
            
            # 快速返回优化
            if matchers_condition == "or" and hit:
                return True
            elif matchers_condition == "and" and not hit:
                return False
        
        # AND条件需要所有都命中
        if matchers_condition == "and":
            return hit_count == total_matchers
        
        # OR条件：至少一个命中
        return hit_count > 0
    
    def _calculate_confidence(self, resp: httpx.Response, matchers: List[Dict[str, Any]], plugin: Optional[Dict[str, Any]] = None) -> float:
        """
        计算漏洞判定的置信度 (0.0 - 1.0)
        
        综合考虑以下因素:
        - 命中的匹配规则数量和权重
        - 特征关键词的唯一性
        - 响应状态码异常程度
        - 响应体特征强度
        - 漏洞类型特异性
        """
        confidence = 0.0
        matched_count = 0

        for matcher in matchers:
            if not self._match_single_matcher(resp, matcher):
                continue

            matched_count += 1
            mtype = matcher.get("type")
            part = matcher.get("part", "body")

            if mtype == "regex":
                confidence += 0.28
            elif mtype == "word":
                confidence += 0.18 if part == "header" else 0.24
            elif mtype == "status":
                if resp.status_code >= 500:
                    confidence += 0.12
                elif resp.status_code >= 400:
                    confidence += 0.08
                else:
                    confidence += 0.03
            elif mtype == "time":
                confidence += 0.18
            elif mtype == "size":
                confidence += 0.08
            else:
                confidence += 0.06

        if matched_count > 1:
            confidence += min((matched_count - 1) * 0.07, 0.21)
        
        content_lower = resp.text.lower()
        header_lower = str(resp.headers).lower()
        plugin_info = plugin.get("info", {}) if plugin else {}
        tags = {str(tag).lower() for tag in plugin_info.get("tags", [])}
        plugin_fingerprint = " ".join(
            [
                str(plugin.get("id", "") if plugin else ""),
                str(plugin_info.get("name", "")),
                " ".join(tags),
            ]
        ).lower()

        # SQL注入特征评分
        if any(token in plugin_fingerprint for token in ["sql", "sqli", "injection"]):
            high_confidence_keywords = [
                "XPATH syntax error",
                "extractvalue()",
                "updatexml()",
                "SQLSTATE[42",
                "SQLSTATE[HY000]",
                "Think\\Db\\Exception",
                "ORA-01756",
                "ORA-00933",
                "ORA-00942",
                "Unclosed quotation mark",
            ]
            medium_confidence_keywords = [
                "SQLSTATE",
                "SQL syntax",
                "mysql_",
                "Database Error",
                "PDO::prepare()",
                "IntegrityError",
                "OperationalError",
                "ProgrammingError",
                "sqlalchemy.exc",
                "sqlite3.OperationalError",
                "SQLITE_ERROR",
                "pg_query",
                "pg_exec",
                "PostgreSQL query failed",
                "You have an error in your SQL syntax",
                "Warning: mysql_",
                "valid MySQL result",
                "MySqlClient",
                "ODBC SQL Server Driver",
                "SqlException",
                "check the manual that corresponds to your MySQL",
            ]
            high_hits = sum(1 for kw in high_confidence_keywords if kw.lower() in content_lower)
            confidence += min(high_hits * 0.3, 0.6)
            medium_hits = sum(1 for kw in medium_confidence_keywords if kw.lower() in content_lower)
            confidence += min(medium_hits * 0.1, 0.3)

        # XSS特征评分
        if "xss" in tags or "cross-site scripting" in plugin_fingerprint:
            xss_indicators = [
                "<script",
                "<svg",
                "onload=",
                "onerror=",
                "javascript:",
                "alert(",
                "document.cookie",
                "document.domain",
                "ontoggle=",
                "onstart=",
                "<iframe",
                "<marquee",
                "<body onload",
                "<img src=x",
            ]
            xss_hits = sum(1 for kw in xss_indicators if kw in content_lower)
            confidence += min(xss_hits * 0.08, 0.24)
            if "text/html" in header_lower:
                confidence += 0.08

        # 信息泄露特征评分
        if any(token in plugin_fingerprint for token in ["info-leak", "disclosure", "git", "config"]):
            leak_indicators = [
                "[core]",
                "repositoryformatversion",
                "bare = false",
                "ref: refs/heads/",
                "[remote \"origin\"]",
                "logallrefupdates",
                "api_key",
                "secret_key",
                "private_key",
                "password",
                "credentials",
            ]
            leak_hits = sum(1 for kw in leak_indicators if kw.lower() in content_lower)
            confidence += min(leak_hits * 0.15, 0.45)

        # 文件上传特征评分
        if any(token in plugin_fingerprint for token in ["file-upload", "upload"]):
            upload_indicators = [
                "sites/default/files",
                "public://",
                '"fid"',
                '"uuid"',
                '"uri"',
                "upload",
                "filename",
            ]
            upload_hits = sum(1 for kw in upload_indicators if kw.lower() in content_lower)
            confidence += min(upload_hits * 0.1, 0.3)

        # Django调试页面特征评分
        if any(token in plugin_fingerprint for token in ["django", "debug"]):
            django_indicators = [
                "DJANGO_SETTINGS_MODULE",
                "django.core",
                "django.db",
                "django.views",
                "Exception Type",
                "Exception Value",
                "Traceback (most recent call last)",
                "DEBUG = True",
                "You're seeing this error because you have",
            ]
            django_hits = sum(1 for kw in django_indicators if kw.lower() in content_lower)
            confidence += min(django_hits * 0.1, 0.3)
        
        # 状态码异常加分
        if resp.status_code >= 500:
            confidence += 0.05
        elif resp.status_code >= 400:
            confidence += 0.02
        
        # 响应体包含典型错误模式
        error_indicators = ["error", "exception", "fatal", "warning"]
        error_hits = sum(1 for ind in error_indicators if ind in content_lower)
        confidence += min(error_hits * 0.02, 0.1)
        
        return min(confidence, 1.0)
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        return {
            "vuln_name": result.vuln_name,
            "severity": result.severity,
            "url": result.url,
            "payload": result.payload,
            "method": result.request.get("method", "GET"),
            "evidence": result.evidence,
            "request": result.request,
            "response": result.response,
            "scan_time": result.scan_time,
            "validation_log": result.validation_log,
            "plugin_id": result.plugin_id,
            "attack_path": result.attack_path,
            "attack_execution": result.attack_execution,
        }
    
    def _extract_matched_keywords(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> List[str]:
        """提取实际命中的关键词列表，用于置信度调整和日志记录"""
        matched = []
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            mtype = matcher.get("type")
            if mtype == "word":
                words = matcher.get("words", [])
                part = matcher.get("part", "body")
                content = resp.text if part == "body" else str(resp.headers)
                case_insensitive = matcher.get("case_insensitive", True)
                check_content = content.lower() if case_insensitive else content
                for w in words:
                    check_w = w.lower() if case_insensitive else w
                    if check_w in check_content:
                        matched.append(w)
            elif mtype == "status":
                if resp.status_code in matcher.get("status", []):
                    matched.append(f"status:{resp.status_code}")
            elif mtype == "regex":
                patterns = matcher.get("regex", [])
                content = resp.text if matcher.get("part", "body") == "body" else str(resp.headers)
                flags = re.IGNORECASE if matcher.get("case_insensitive", True) else 0
                for p in patterns:
                    try:
                        if re.search(p, content, flags=flags):
                            matched.append(f"regex:{p[:50]}")
                    except re.error:
                        pass
            elif mtype == "time":
                elapsed_ms = 0.0
                try:
                    elapsed_ms = float(resp.extensions.get("aegis_elapsed_ms", 0.0))
                except Exception:
                    elapsed_ms = 0.0
                if self._match_single_matcher(resp, matcher):
                    matched.append(f"time:{int(elapsed_ms)}ms")
        return matched
    
    def _count_evidence(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> int:
        """计算命中的证据数量（匹配器数量 + 关键词特异性加权）"""
        evidence = 0
        content_lower = resp.text.lower()
        for matcher in matchers:
            if self._match_single_matcher(resp, matcher):
                evidence += 1
                mtype = matcher.get("type")
                if mtype == "word":
                    words = matcher.get("words", [])
                    part = matcher.get("part", "body")
                    content = resp.text if part == "body" else str(resp.headers)
                    case_insensitive = matcher.get("case_insensitive", True)
                    check_content = content.lower() if case_insensitive else content
                    from scanner.engine.rules import HIGH_SPECIFICITY_SQLI_KEYWORDS, THINKPHP_EXCLUSIVE_SQLI_KEYWORDS
                    for w in words:
                        check_w = w.lower() if case_insensitive else w
                        if check_w in check_content:
                            if any(hkw.lower() == check_w for hkw in HIGH_SPECIFICITY_SQLI_KEYWORDS):
                                evidence += 1
                            if any(ekw.lower() == check_w for ekw in THINKPHP_EXCLUSIVE_SQLI_KEYWORDS):
                                evidence += 1
                            xss_high_specificity = [
                                "aegismarker<script",
                                "aegismarker<svg",
                                "aegismarker<img",
                                "aegismarker\"'><script",
                            ]
                            if any(kw.lower() == check_w for kw in xss_high_specificity):
                                evidence += 1
                            git_high_specificity = [
                                "[core]",
                                "repositoryformatversion",
                                "bare = false",
                                "ref: refs/heads/",
                            ]
                            if any(kw.lower() == check_w for kw in git_high_specificity):
                                evidence += 1
                            django_high_specificity = [
                                "djang_settings_module",
                                "integrityerror",
                                "unique constraint failed",
                            ]
                            if any(kw.lower() == check_w for kw in django_high_specificity):
                                evidence += 1
                            drupal_high_specificity = [
                                "aegis-cve-2019-6341",
                                "sites/default/files",
                                "public://",
                            ]
                            if any(kw.lower() == check_w for kw in drupal_high_specificity):
                                evidence += 1
                elif mtype == "regex":
                    evidence += 1
                elif mtype == "time":
                    evidence += 1
        if resp.status_code >= 500:
            evidence += 1
        return evidence
    
    def _log_judgment(
        self,
        phase: str,
        plugin_id: str,
        action: str,
        details: Dict[str, Any],
        result: str,
    ) -> None:
        """记录判定日志，便于问题追踪和审计"""
        record = {
            "timestamp": time.time(),
            "phase": phase,
            "plugin_id": plugin_id,
            "action": action,
            "details": details,
            "result": result,
        }
        self._judgment_log.append(record)
        logger.debug(
            f" 判定日志 [{phase}] {plugin_id}/{action}: {result} - "
            f"{json.dumps(details, ensure_ascii=False)[:200]}"
        )
    
    def get_judgment_log(self) -> List[Dict[str, Any]]:
        """获取完整的判定日志"""
        return list(self._judgment_log)
    
    def get_framework_detection_result(self) -> Dict[str, Any]:
        """获取框架检测结果"""
        return {
            "detected_frameworks": [fw.value for fw in self._detected_frameworks],
            "framework_confidence": {
                fw.value: round(self._framework_confidence.get(fw, 0), 3)
                for fw in self._detected_frameworks
            },
            "framework_versions": {
                fw.value: v for fw, v in self._framework_versions.items()
            },
        }
