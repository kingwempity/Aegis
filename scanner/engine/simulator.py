"""
scanner.engine.simulator
-----------------------
模拟攻击核心引擎（Attack Simulation Engine）

这是Aegis从"静态扫描"到"真正模拟攻击"的核心转变点。

设计理念：
    真正的攻击者不会简单地发送Payload并检查响应，
    而是会：
    1. 系统性地侦察目标（Reconnaissance）
    2. 根据目标特征定制武器（Weaponization）
    3. 有策略地执行攻击（Exploitation）
    4. 根据反馈动态调整（Adaptation）

本模块实现完整的攻击生命周期管理：

核心组件：
    - AttackSimulator: 主控制器，协调整个攻击流程
    - AttackOrchestrator: 攻击编排器，管理多阶段攻击链
    - DecisionEngine: 决策引擎，基于AI的智能决策系统
    - AttackSession: 攻击会话，完整的状态管理
    - AttackChain: 攻击链，记录完整的攻击过程

使用示例:
    >>> simulator = AttackSimulator(target="http://example.com")
    >>> result = await simulator.run_simulation()
    >>> print(f"发现漏洞: {len(result.exploits)}")
    >>> for chain in result.attack_chain:
    ...     print(f"阶段: {chain.stage_name} - {'成功' if chain.success else '失败'}")
"""

import asyncio
import time
import uuid
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable, Set, Iterator
from enum import Enum, auto
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class AttackPhase(Enum):
    """攻击阶段枚举"""
    RECONNAISSANCE = auto()       # 侦察阶段
    WEAPONIZATION = auto()        # 武器化阶段
    EXPLOITATION = auto()         # 利用阶段
    POST_EXPLOITATION = auto()    # 后利用阶段
    IMPACT_ASSESSMENT = auto()    # 影响评估阶段


class DecisionType(Enum):
    """决策类型枚举"""
    CONTINUE = "continue"         # 继续执行
    BACKTRACK = "backtrack"       # 回退到上一步
    TERMINATE_SUCCESS = "terminate_success"  # 成功终止
    TERMINATE_FAILURE = "terminate_failure"  # 失败终止
    BRANCH_ALTERNATIVE = "branch_alternative"  # 尝试替代方案
    WAIT_AND_RETRY = "wait_and_retry"          # 等待后重试


class AttackStatus(Enum):
    """攻击状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    SUCCESS = "success"
    PARTIAL = "partial"           # 部分成功
    FAILED = "failed"
    BLOCKED = "blocked"           # 被WAF/防护阻止


@dataclass
class AttackStep:
    """
    单个攻击步骤
    
    代表攻击链中的一个原子操作，包含完整的上下文和结果信息。
    """
    step_id: str                  # 唯一标识符
    phase: AttackPhase            # 所属阶段
    stage_name: str               # 阶段名称
    stage_title: str              # 阶段标题
    stage_goal: str               # 阶段目标
    
    # 执行信息
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    payload: str = ""
    
    # 结果信息
    success: bool = False
    status_code: int = 0
    response_time_ms: float = 0.0
    response_size: int = 0
    
    # 证据信息
    evidence: Dict[str, Any] = field(default_factory=dict)
    matched_conditions: List[str] = field(default_factory=list)
    
    # 提取的信息
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    
    # 元数据
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    retry_count: int = 0
    bypass_technique_used: Optional[str] = None
    
    # 关联信息
    parent_step_id: Optional[str] = None
    child_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "phase": self.phase.name if isinstance(self.phase, AttackPhase) else self.phase,
            "stage_name": self.stage_name,
            "stage_title": self.stage_title,
            "stage_goal": self.stage_goal,
            "method": self.method,
            "url": self.url,
            "payload": self.payload[:200] if self.payload else "",
            "success": self.success,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "response_size": self.response_size,
            "evidence": self.evidence,
            "matched_conditions": self.matched_conditions[:10],
            "extracted_data": {k: str(v)[:100] for k, v in list(self.extracted_data.items())[:10]},
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "retry_count": self.retry_count,
            "bypass_technique_used": self.bypass_technique_used,
        }


@dataclass
class AttackChain:
    """
    攻击链
    
    完整记录一次攻击尝试的所有步骤，形成可追溯的攻击故事。
    """
    chain_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target_url: str = ""
    vulnerability_type: str = ""
    attack_vector: str = ""        # 攻击向量描述
    
    steps: List[AttackStep] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    
    # 统计信息
    total_steps: int = 0
    successful_steps: int = 0
    failed_steps: int = 0
    total_duration_ms: float = 0.0
    
    # 最终状态
    final_status: AttackStatus = AttackStatus.PENDING
    final_reason: str = ""
    
    # 时间线
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    
    def add_step(self, step: AttackStep) -> None:
        """添加攻击步骤"""
        self.steps.append(step)
        self.total_steps += 1
        
        if step.success:
            self.successful_steps += 1
        else:
            self.failed_steps += 1
        
        self.total_duration_ms += step.duration_ms
    
    def get_successful_steps(self) -> List[AttackStep]:
        return [s for s in self.steps if s.success]
    
    def get_failed_steps(self) -> List[AttackStep]:
        return [s for s in self.steps if not s.success]
    
    def get_timeline(self) -> List[Dict[str, Any]]:
        """生成时间线视图"""
        timeline = []
        for i, step in enumerate(self.steps):
            timeline.append({
                "step_number": i + 1,
                "timestamp": step.timestamp,
                "stage_name": step.stage_name,
                "success": step.success,
                "duration_ms": step.duration_ms,
                "method": step.method,
                "url": step.url[:100],
            })
        return timeline
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "target_url": self.target_url,
            "vulnerability_type": self.vulnerability_type,
            "attack_vector": self.attack_vector,
            "steps": [s.to_dict() for s in self.steps],
            "artifacts": self.artifacts,
            "statistics": {
                "total_steps": self.total_steps,
                "successful_steps": self.successful_steps,
                "failed_steps": self.failed_steps,
                "success_rate": f"{(self.successful_steps / max(self.total_steps, 1)) * 100:.1f}%",
                "total_duration_ms": round(self.total_duration_ms, 2),
                "average_step_duration_ms": round(
                    self.total_duration_ms / max(self.total_steps, 1), 2
                ),
            },
            "final_status": self.final_status.value,
            "final_reason": self.final_reason,
            "timeline": self.get_timeline(),
            "started_at": self.started_at,
            "finished_at": self.finished_at or time.time(),
            "duration_seconds": (self.finished_at or time.time()) - self.started_at,
        }
    
    def to_report_format(self) -> Dict[str, Any]:
        """转换为报告格式（与现有API兼容）"""
        return {
            "status": self.final_status.value.lower(),
            "final_reason": self.final_reason,
            "attack_vector": self.attack_vector,
            "entry_point": self.steps[0].url if self.steps else "",
            "steps": [
                {
                    "step": i + 1,
                    "stage_id": s.step_id,
                    "stage_name": s.stage_name,
                    "stage_title": s.stage_title,
                    "stage_goal": s.stage_goal,
                    "method": s.method,
                    "url": s.url,
                    "description": s.stage_goal,
                    "matched_conditions": s.matched_conditions,
                    "artifacts": [a for a in self.artifacts if a.get("source_stage") == s.stage_name],
                    "extracted": s.extracted_data,
                    "success": s.success,
                    "duration_ms": s.duration_ms,
                    "status": "validated" if s.success else "failed",
                    "evidence": {
                        "request": {
                            "method": s.method,
                            "url": s.url,
                            "headers": s.headers,
                            "body": s.body,
                        },
                        "response": {
                            "status_code": s.status_code,
                            "body_snippet": s.evidence.get("response_body", "")[:500],
                        },
                        "matched_patterns": s.matched_conditions,
                        "timing_ms": s.duration_ms,
                    },
                    "payload": s.payload,
                    "result": "success" if s.success else "failure",
                    "timestamp": s.timestamp,
                }
                for i, s in enumerate(self.steps)
            ],
            "artifacts": self.artifacts,
        }


@dataclass
class AttackSession:
    """
    攻击会话
    
    管理完整的攻击状态，包括：
    - 会话认证信息（Cookie/Token）
    - 动态提取的状态变量
    - CSRF Token等安全令牌
    - 完整的历史快照
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    
    # 认证状态
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    csrf_tokens: Dict[str, str] = field(default_factory=dict)
    
    # 动态状态变量（从响应中提取）
    state_variables: Dict[str, Any] = field(default_factory=dict)
    
    # 会话历史
    request_history: List[Dict[str, Any]] = field(default_factory=list)
    snapshots: List[Dict[str, Any]] = field(default_factory=list)
    
    # 会话元数据
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    is_active: bool = True
    
    # 统计
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    
    def update_cookies(self, cookies: Dict[str, str]) -> None:
        """更新Cookie"""
        self.cookies.update(cookies)
        self.last_activity = time.time()
    
    def set_csrf_token(self, token_name: str, token_value: str) -> None:
        """设置CSRF Token"""
        self.csrf_tokens[token_name] = token_value
        self.last_activity = time.time()
    
    def get_csrf_token(self, token_name: str = "default") -> Optional[str]:
        """获取CSRF Token"""
        return self.csrf_tokens.get(token_name)
    
    def set_state_variable(self, name: str, value: Any) -> None:
        """设置状态变量"""
        self.state_variables[name] = value
        self.logger.debug(f"状态更新: {name} = {str(value)[:50]}")
    
    def get_state_variable(self, name: str, default: Any = None) -> Any:
        """获取状态变量"""
        return self.state_variables.get(name, default)
    
    def record_request(self, method: str, url: str, 
                       status_code: int, duration_ms: float) -> None:
        """记录请求"""
        self.request_history.append({
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "status_code": status_code,
            "duration_ms": duration_ms,
        })
        self.total_requests += 1
        if status_code < 400:
            self.successful_requests += 1
        else:
            self.failed_requests += 1
        self.last_activity = time.time()
    
    def create_snapshot(self) -> Dict[str, Any]:
        """创建当前状态快照"""
        snapshot = {
            "snapshot_id": str(uuid.uuid4())[:8],
            "timestamp": time.time(),
            "cookies": dict(self.cookies),
            "csrf_tokens": dict(self.csrf_tokens),
            "state_variables": {k: str(v)[:100] for k, v in self.state_variables.items()},
            "request_count": self.total_requests,
        }
        self.snapshots.append(snapshot)
        return snapshot
    
    def restore_snapshot(self, snapshot: Dict[str, Any]) -> bool:
        """恢复到指定快照"""
        try:
            self.cookies = snapshot.get("cookies", {})
            self.csrf_tokens = snapshot.get("csrf_tokens", {})
            self.state_variables.update(snapshot.get("state_variables", {}))
            logger.info(f"✅ 已恢复到快照 {snapshot['snapshot_id']}")
            return True
        except Exception as e:
            logger.error(f"❌ 快照恢复失败: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "cookies_count": len(self.cookies),
            "csrf_tokens_count": len(self.csrf_tokens),
            "state_variables": list(self.state_variables.keys()),
            "request_statistics": {
                "total": self.total_requests,
                "successful": self.successful_requests,
                "failed": self.failed_requests,
                "success_rate": f"{(self.successful_requests / max(self.total_requests, 1)) * 100:.1f}%",
            },
            "snapshots_count": len(self.snapshots),
            "is_active": self.is_active,
            "session_duration_seconds": time.time() - self.created_at,
        }


@dataclass
class SimulationResult:
    """
    模拟攻击结果
    
    包含完整的攻击信息和统计。
    """
    simulation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_url: str = ""
    strategy_used: str = ""
    
    # 各阶段结果
    recon_result: Optional[Dict[str, Any]] = None
    weaponization_summary: Dict[str, Any] = field(default_factory=dict)
    exploits: List[Dict[str, Any]] = field(default_factory=list)
    impact_assessment: Dict[str, Any] = field(default_factory=dict)
    
    # 攻击链
    attack_chains: List[AttackChain] = field(default_factory=list)
    
    # 统计
    total_attacks_attempted: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities_confirmed: int = 0
    
    # 时间
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    
    @property
    def duration_seconds(self) -> float:
        return (self.finished_at or time.time()) - self.started_at
    
    @property
    def success_rate(self) -> float:
        if self.total_attacks_attempted == 0:
            return 0.0
        return self.vulnerabilities_confirmed / self.total_attacks_attempted
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "target_url": self.target_url,
            "strategy_used": self.strategy_used,
            "recon_result": self.recon_result,
            "weaponization_summary": self.weaponization_summary,
            "exploits": self.exploits,
            "impact_assessment": self.impact_assessment,
            "attack_chains": [chain.to_dict() for chain in self.attack_chains],
            "statistics": {
                "total_attacks_attempted": self.total_attacks_attempted,
                "vulnerabilities_found": self.vulnerabilities_found,
                "vulnerabilities_confirmed": self.vulnerabilities_confirmed,
                "success_rate": f"{self.success_rate:.1%}",
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "started_at": self.started_at,
            "finished_at": self.finished_at or time.time(),
        }


class DecisionEngine:
    """
    决策引擎
    
    基于多维度分析进行智能决策，决定攻击流程的下一步行动。
    
    决策依据：
    1. 当前步骤的成功/失败状态
    2. 响应行为分析（时间、大小、错误信息）
    3. 历史模式匹配
    4. WAF/防护检测信号
    5. 攻击进度评估
    """
    
    def __init__(self, aggressiveness: float = 0.7):
        """
        初始化决策引擎
        
        Args:
            aggressiveness: 激进程度 (0.0-1.0)，越高越激进
        """
        self.aggressiveness = aggressiveness
        self._decision_history: List[Dict[str, Any]] = []
        
        # 决策权重配置
        self.weights = {
            "matcher_hit": 0.30,
            "behavior_score": 0.25,
            "time_anomaly": 0.15,
            "error_indicators": 0.15,
            "historical_pattern": 0.15,
        }
    
    def evaluate(self, 
                 current_step: AttackStep,
                 attack_context: Dict[str, Any]) -> Tuple[DecisionType, str, float]:
        """
        评估当前步骤并做出决策
        
        Args:
            current_step: 当前执行的攻击步骤
            attack_context: 攻击上下文（包含目标信息、历史数据等）
            
        Returns:
            (决策类型, 决策原因, 置信度)
        """
        confidence = 0.0
        reasons = []
        
        # 1. 匹配器命中检查
        matcher_score = self._evaluate_matcher(current_step)
        confidence += matcher_score * self.weights["matcher_hit"]
        if current_step.matched_conditions:
            reasons.append(f"匹配器命中({len(current_step.matched_conditions)}个)")
        
        # 2. 行为分析评分
        behavior_score = self._evaluate_behavior(current_step)
        confidence += behavior_score * self.weights["behavior_score"]
        if behavior_score > 0.6:
            reasons.append(f"行为异常(score={behavior_score:.2f})")
        
        # 3. 时间异常检测
        time_score = self._evaluate_time_anomaly(current_step, attack_context)
        confidence += time_score * self.weights["time_anomaly"]
        if time_score > 0.7:
            reasons.append(f"时间异常(deviation={current_step.response_time_ms}ms)")
        
        # 4. 错误指标分析
        error_score = self._evaluate_errors(current_step)
        confidence += error_score * self.weights["error_indicators"]
        if error_score > 0.5:
            reasons.append(f"错误指示器触发")
        
        # 5. 综合决策
        decision, reason = self._make_decision(confidence, current_step, attack_context)
        reason_detail = "; ".join(reasons) if reasons else reason
        
        # 记录决策历史
        self._decision_history.append({
            "timestamp": time.time(),
            "step_id": current_step.step_id,
            "decision": decision.value,
            "confidence": confidence,
            "reason": reason_detail,
        })
        
        return decision, reason_detail, confidence
    
    def _evaluate_matcher(self, step: AttackStep) -> float:
        """评估匹配器命中情况"""
        if not step.matched_conditions:
            return 0.0
        
        base_score = min(len(step.matched_conditions) / 3.0, 1.0)
        
        if step.success:
            return base_score * 1.0
        else:
            return base_score * 0.6
    
    def _evaluate_behavior(self, step: AttackStep) -> float:
        """评估行为异常"""
        behavior = step.evidence.get("behavior_analysis", {})
        if not behavior:
            return 0.0
        
        score = behavior.get("behavior_score", 0) / 100.0
        
        # 加权关键指标
        if behavior.get("time_anomaly"):
            score *= 1.2
        if behavior.get("error_indicators"):
            score *= 1.1
        
        return min(score, 1.0)
    
    def _evaluate_time_anomaly(self, step: AttackStep, context: Dict[str, Any]) -> float:
        """评估时间异常"""
        baseline = context.get("baseline_response_time", 500)  # 默认500ms基准
        
        if step.response_time_ms <= 0 or baseline <= 0:
            return 0.0
        
        deviation = abs(step.response_time_ms - baseline) / baseline
        
        if deviation > 5.0 and step.response_time_ms > 3000:
            return 0.9  # 高度可疑的时间盲注
        elif deviation > 2.0:
            return 0.6
        elif deviation > 1.0:
            return 0.3
        else:
            return 0.0
    
    def _evaluate_errors(self, step: AttackStep) -> float:
        """评估错误指标"""
        errors = step.evidence.get("error_indicators", [])
        if not errors:
            return 0.0
        
        high_risk_errors = ['sql', 'stack_trace', 'path_disclosure']
        error_weight = sum(1.0 for e in errors if any(h in e for h in high_risk_errors))
        
        return min(error_weight / len(high_risk_errors), 1.0)
    
    def _make_decision(self, confidence: float, 
                       step: AttackStep,
                       context: Dict[str, Any]) -> Tuple[DecisionType, str]:
        """做出最终决策"""
        
        # 如果已经成功且置信度高
        if step.success and confidence > 0.7:
            return DecisionType.TERMINATE_SUCCESS, "漏洞已确认，高置信度"
        
        # 如果成功但置信度中等
        if step.success and confidence > 0.4:
            return DecisionType.CONTINUE, "初步确认，继续收集证据"
        
        # 如果被WAF拦截
        if step.status_code in [403, 406, 429, 503]:
            waf_keywords = ['blocked', 'forbidden', 'cloudflare', 'waf']
            body_lower = step.evidence.get("response_body", "").lower()
            
            if any(kw in body_lower for kw in waf_keywords):
                if step.retry_count < 3:
                    return DecisionType.BRANCH_ALTERNATIVE, "检测到WAF，尝试替代方案"
                else:
                    return DecisionType.TERMINATE_FAILURE, "多次绕过WAF失败"
        
        # 如果有强行为指标但未命中匹配器
        if not step.success and confidence > 0.5:
            if step.retry_count < 2:
                return DecisionType.WAIT_AND_RETRY, "行为异常但未匹配，重试"
            else:
                return DecisionType.BACKTRACK, "多次重试无效，回退"
        
        # 如果完全无反应
        if not step.matched_conditions and confidence < 0.2:
            if step.retry_count == 0:
                return DecisionType.CONTINUE, "首次尝试，继续探测"
            else:
                return DecisionType.TERMINATE_FAILURE, "无明显响应，终止"
        
        # 默认决策
        if confidence > self.aggressiveness:
            return DecisionType.CONTINUE, f"置信度{confidence:.2f}超过阈值{self.aggressiveness}"
        else:
            return DecisionType.TERMINATE_FAILURE, f"置信度不足({confidence:.2f})"
    
    def get_decision_statistics(self) -> Dict[str, Any]:
        """获取决策统计"""
        if not self._decision_history:
            return {"total_decisions": 0}
        
        decisions = [d["decision"] for d in self._decision_history]
        
        return {
            "total_decisions": len(decisions),
            "decision_distribution": {
                d.value: decisions.count(d.value) for d in DecisionType
            },
            "average_confidence": sum(d["confidence"] for d in self._decision_history) / len(decisions),
        }


class AttackOrchestrator:
    """
    攻击编排器
    
    协调多阶段攻击的执行顺序和依赖关系。
    
    功能：
    1. 构建攻击图（DAG）
    2. 拓扑排序确定执行顺序
    3. 并发控制
    4. 错误处理和回滚
    5. 进度跟踪
    """
    
    def __init__(self, max_concurrent: int = 5):
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._execution_log: List[Dict[str, Any]] = []
    
    async def execute_attack_chain(self,
                                   chain: AttackChain,
                                   session: AttackSession,
                                   executor: Callable,
                                   decision_engine: DecisionEngine) -> AttackStatus:
        """
        执行攻击链
        
        Args:
            chain: 攻击链对象
            session: 攻击会话
            executor: 实际执行请求的函数
            decision_engine: 决策引擎
            
        Returns:
            最终攻击状态
        """
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        chain.status = AttackStatus.RUNNING
        
        for step in chain.steps:
            async with self._semaphore:
                # 检查前置条件
                if not self._check_preconditions(step, session):
                    step.success = False
                    step.status_code = 0
                    step.final_reason = "前置条件未满足"
                    continue
                
                # 执行步骤
                start_time = time.perf_counter()
                
                try:
                    result = await executor(step, session)
                    
                    step.duration_ms = (time.perf_counter() - start_time) * 1000
                    
                    # 更新步骤结果
                    self._update_step_from_result(step, result)
                    
                    # 记录到会话
                    session.record_request(
                        step.method, step.url,
                        step.status_code, step.duration_ms
                    )
                    
                    # 使用决策引擎评估
                    decision, reason, confidence = decision_engine.evaluate(
                        step, {"baseline_response_time": 500}
                    )
                    
                    self._log_execution(step, decision, reason, confidence)
                    
                    # 根据决策采取行动
                    if decision == DecisionType.TERMINATE_SUCCESS:
                        chain.final_status = AttackStatus.SUCCESS
                        chain.final_reason = reason
                        break
                    elif decision == DecisionType.TERMINATE_FAILURE:
                        if not step.success:
                            chain.final_status = AttackStatus.FAILED
                            chain.final_reason = reason
                            continue
                    elif decision == DecisionType.BACKTRACK:
                        snapshot = session.create_snapshot()
                        logger.info(f"🔄 回退到快照 {snapshot['snapshot_id']}")
                        
                except Exception as e:
                    step.success = False
                    step.duration_ms = (time.perf_counter() - start_time) * 1000
                    step.final_reason = f"执行异常: {str(e)}"
                    logger.error(f"❌ 步骤执行失败 [{step.stage_name}]: {e}")
        
        # 设置最终状态
        chain.finished_at = time.time()
        
        if chain.final_status == AttackStatus.RUNNING:
            successful = sum(1 for s in chain.steps if s.success)
            if successful > 0:
                chain.final_status = AttackStatus.PARTIAL
                chain.final_reason = f"部分成功({successful}/{len(chain.steps)}步骤)"
            else:
                chain.final_status = AttackStatus.FAILED
                chain.final_reason = "所有步骤均未成功"
        
        return chain.final_status
    
    def _check_preconditions(self, step: AttackStep, session: AttackSession) -> bool:
        """检查步骤的前置条件是否满足"""
        # 这里可以添加复杂的前置条件逻辑
        # 例如：某些步骤需要在特定状态变量存在时才能执行
        return True
    
    def _update_step_from_result(self, step: AttackStep, result: Dict[str, Any]) -> None:
        """从执行结果更新步骤信息"""
        step.success = result.get("success", False)
        step.status_code = result.get("status_code", 0)
        step.response_time_ms = result.get("response_time_ms", 0)
        step.response_size = result.get("response_size", 0)
        step.evidence = result.get("evidence", {})
        step.matched_conditions = result.get("matched_conditions", [])
        step.extracted_data = result.get("extracted_data", {})
    
    def _log_execution(self, step: AttackStep, 
                      decision: DecisionType,
                      reason: str, confidence: float) -> None:
        """记录执行日志"""
        log_entry = {
            "timestamp": time.time(),
            "step_id": step.step_id,
            "stage_name": step.stage_name,
            "success": step.success,
            "decision": decision.value,
            "confidence": confidence,
            "reason": reason,
        }
        self._execution_log.append(log_entry)


class AttackSimulator:
    """
    模拟攻击主控制器
    
    这是整个模拟攻击系统的入口点和协调中心。
    
    职责：
    1. 初始化所有子系统（侦察、武器化、利用）
    2. 协调攻击生命周期的各个阶段
    3. 管理攻击会话和状态
    4. 收集和整合结果
    5. 提供统一的接口给ScannerEngine使用
    """
    
    def __init__(self, 
                 target: str,
                 strategy: str = "intelligent",
                 max_concurrent: int = 5,
                 timeout: float = 10.0):
        """
        初始化模拟攻击器
        
        Args:
            target: 目标URL
            strategy: 攻击策略 (aggressive/intelligent/stealthy)
            max_concurrent: 最大并发数
            timeout: 请求超时时间
        """
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        
        # 子系统初始化（延迟初始化，避免导入问题）
        self._recon_engine = None
        self._weaponizer = None
        self._orchestrator = AttackOrchestrator(max_concurrent=max_concurrent)
        self._decision_engine = DecisionEngine(
            aggressiveness=0.8 if strategy == "aggressive" else 0.7
        )
        
        # 会话管理
        self.session: Optional[AttackSession] = None
        self.current_chain: Optional[AttackChain] = None
        
        # 结果存储
        self.result: Optional[SimulationResult] = None
        
        # 统计
        self._simulations_run = 0
        self._vulnerabilities_discovered = 0
        
        logger.info(f"🎯 AttackSimulator 已初始化 (target={target}, strategy={strategy})")
    
    async def run_simulation(self, client: httpx.AsyncClient) -> SimulationResult:
        """
        执行完整的模拟攻击
        
        这是主方法，协调整个攻击流程：
        1. 侦察阶段
        2. 武器化阶段
        3. 利用阶段
        4. 影响评估
        
        Args:
            client: HTTP客户端实例
            
        Returns:
            完整的模拟攻击结果
        """
        self.result = SimulationResult(target_url=self.target, strategy_used=self.strategy)
        self.session = AttackSession(target_url=self.target)
        
        logger.info("="*60)
        logger.info(f"🚀 开始模拟攻击: {self.target}")
        logger.info(f"⚙️ 策略: {self.strategy}")
        logger.info("="*60)
        
        try:
            # 阶段1：侦察
            recon_start = time.time()
            recon_result = await self._recon_phase(client)
            recon_duration = time.time() - recon_start
            
            self.result.recon_result = recon_result
            logger.info(f"\n✅ 侦察完成 ({recon_duration:.2f}s)")
            
            # 阶段2：武器化
            weapon_start = time.time()
            weapons = await self._weaponize_phase(recon_result)
            weapon_duration = time.time() - weapon_start
            
            self.result.weaponization_summary = {
                "payloads_generated": len(weapons),
                "duration_seconds": round(weapon_duration, 2),
                "categories": list(set(w.get("category") for w in weapons)),
            }
            logger.info(f"✅ 武器化完成 ({weapon_duration:.2f}s): {len(weapons)} 个Payload")
            
            # 阶段3：利用
            exploit_start = time.time()
            exploit_results = await self._exploit_phase(client, weapons)
            exploit_duration = time.time() - exploit_start
            
            self.result.exploits = exploit_results
            self.result.vulnerabilities_found = len(exploit_results)
            self.result.vulnerabilities_confirmed = sum(
                1 for e in exploit_results if e.get("confirmed")
            )
            logger.info(f"✅ 利用完成 ({exploit_duration:.2f}s): "
                       f"{self.result.vulnerabilities_confirmed} 个确认漏洞")
            
            # 阶段4：影响评估
            impact = await self._assess_impact(exploit_results)
            self.result.impact_assessment = impact
            
            # 最终汇总
            self.result.finished_at = time.time()
            self.result.total_attacks_attempted = len(weapons)
            self.result.attack_chains = (
                [self.current_chain] if self.current_chain else []
            )
            
            self._simulations_run += 1
            self._vulnerabilities_discovered += self.result.vulnerabilities_confirmed
            
            logger.info("\n" + "="*60)
            logger.info(f"🎉 模拟攻击完成!")
            logger.info(f"📊 发现漏洞: {self.result.vulnerabilities_found}")
            logger.info(f"✅ 确认漏洞: {self.result.vulnerabilities_confirmed}")
            logger.info(f"⏱️ 总耗时: {self.result.duration_seconds:.2f}s")
            logger.info("="*60 + "\n")
            
            return self.result
            
        except Exception as e:
            logger.error(f"❌ 模拟攻击异常终止: {e}", exc_info=True)
            self.result.finished_at = time.time()
            self.result.impact_assessment = {"error": str(e)}
            return self.result
    
    async def _recon_phase(self, client: httpx.AsyncClient) -> Dict[str, Any]:
        """
        侦察阶段
        
        使用深度侦察引擎收集目标信息。
        """
        logger.info("\n📡 [阶段1/4] 侦察阶段")
        
        try:
            from scanner.engine.recon import ReconEngine
            
            if not self._recon_engine:
                self._recon_engine = ReconEngine(max_depth=3, timeout=self.timeout)
            
            recon_result = await self._recon_engine.deep_recon(self.target, client)
            
            # 存储关键信息到会话
            if self.session and recon_result:
                self.session.set_state_variable("primary_framework", recon_result.primary_framework or "")
                self.session.set_state_variable("primary_database", recon_result.primary_database or "")
                self.session.set_state_variable("waf_type", recon_result.waf_fingerprint.waf_type.value)
                self.session.set_state_variable("architecture", recon_result.architecture.value)
            
            return recon_result.to_dict() if hasattr(recon_result, 'to_dict') else {}
            
        except Exception as e:
            logger.warning(f"⚠️ 深度侦察失败，使用基础信息: {e}")
            return {
                "target_url": self.target,
                "error": str(e),
                "fallback_mode": True,
            }
    
    async def _weaponize_phase(self, recon_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        武器化阶段
        
        根据侦察结果生成针对性的攻击载荷。
        """
        logger.info("\n⚔️ [阶段2/4] 武器化阶段")
        
        payloads = []
        
        try:
            from scanner.engine.weaponizer import Weaponizer, TargetContext
            
            if not self._weaponizer:
                self._weaponizer = Weaponizer(strategy=self.strategy)
            
            # 构建目标上下文
            context = TargetContext()
            context.primary_framework = recon_info.get("primary_framework", "")
            context.primary_database = recon_info.get("primary_database", "")
            context.waf_type = recon_info.get("waf_fingerprint", {}).get("waf_type", "unknown")
            context.protection_level = recon_info.get("waf_fingerprint", {}).get("protection_level", 0)
            context.architecture = recon_info.get("architecture", "unknown")
            
            # 为每种漏洞类型生成Payload
            categories = ["sqli", "xss", "path_traversal", "cmd_injection"]
            
            for category in categories:
                try:
                    category_payloads = self._weaponizer.synthesize(
                        category=category,
                        context=context,
                        max_payloads=5,
                    )
                    
                    for p in category_payloads:
                        payloads.append(p.to_dict())
                        
                except Exception as e:
                    logger.debug(f"⚠️ Payload生成失败 ({category}): {e}")
            
        except Exception as e:
            logger.warning(f"⚠️ 武器化模块不可用: {e}")
            # 返回基础Payload列表作为降级方案
            payloads = [
                {"category": "generic", "encoded": "test{{RandomInt}}", "confidence": 0.3}
            ]
        
        return payloads
    
    async def _exploit_phase(self, 
                              client: httpx.AsyncClient,
                              weapons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        利用阶段
        
        执行实际的攻击尝试。
        """
        logger.info(f"\n💥 [阶段3/4] 利用阶段 ({len(weapons)} 个Payload)")
        
        exploits = []
        
        # 创建攻击链
        self.current_chain = AttackChain(
            target_url=self.target,
            attack_vector=f"Aegis-Simulated-Attack-{self.strategy}",
        )
        
        for weapon in weapons:
            try:
                payload_str = weapon.get("encoded", "")
                category = weapon.get("category", "generic")
                
                # 构造攻击步骤
                step = AttackStep(
                    step_id=str(uuid.uuid4())[:8],
                    phase=AttackPhase.EXPLOITATION,
                    stage_name=f"{category}_test",
                    stage_title=f"{category.upper()} 测试",
                    stage_goal=f"测试是否存在{category}漏洞",
                    method="GET",
                    url=self.target,
                    payload=payload_str,
                    bypass_technique_used=weapon.get("bypass_technique"),
                )
                
                # 发送请求
                start_time = time.perf_counter()
                
                # 将payload注入到URL
                test_url = f"{self.target}?test_param={payload_str}" if payload_str else self.target
                
                resp = await client.get(test_url, follow_redirects=True)
                
                elapsed = (time.perf_counter() - start_time) * 1000
                
                # 更新步骤
                step.status_code = resp.status_code
                step.response_time_ms = elapsed
                step.response_size = len(resp.content)
                step.duration_ms = elapsed
                step.evidence = {
                    "response_body": resp.text[:500],
                    "response_headers": dict(resp.headers),
                }
                
                # 简单验证（这里应该调用更复杂的验证逻辑）
                step.success = self._quick_validate(resp, category)
                
                if step.success:
                    step.matched_conditions = [f"{category}_indicator_detected"]
                
                # 添加到攻击链
                self.current_chain.add_step(step)
                
                # 记录到会话
                if self.session:
                    self.session.record_request(
                        step.method, step.url,
                        step.status_code, step.duration_ms
                    )
                
                # 如果成功，记录为发现的漏洞
                if step.success:
                    exploits.append({
                        "category": category,
                        "payload": payload_str,
                        "url": test_url,
                        "confirmed": True,
                        "evidence": step.evidence,
                        "confidence": weapon.get("confidence", 0.5),
                        "chain_id": self.current_chain.chain_id,
                    })
                    
            except Exception as e:
                logger.debug(f"⚠️ Payload执行失败: {e}")
        
        # 设置攻击链最终状态
        if self.current_chain:
            self.current_chain.finished_at = time.time()
            if any(e.get("confirmed") for e in exploits):
                self.current_chain.final_status = AttackStatus.SUCCESS
                self.current_chain.final_reason = f"发现 {len(exploits)} 个漏洞"
            else:
                self.current_chain.final_status = AttackStatus.FAILED
                self.current_chain.final_reason = "未发现可验证的漏洞"
        
        return exploits
    
    async def _assess_impact(self, exploits: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        影响评估阶段
        
        评估发现漏洞的实际危害性。
        """
        logger.info(f"\n📊 [阶段4/4] 影响评估")
        
        if not exploits:
            return {
                "risk_level": "low",
                "message": "未发现漏洞",
                "recommendations": [
                    "继续保持安全最佳实践",
                    "定期进行安全扫描",
                ],
            }
        
        # 评估风险等级
        confirmed_exploits = [e for e in exploits if e.get("confirmed")]
        
        risk_factors = {
            "critical": ["cmd_injection", "rce"],
            "high": ["sqli", "ssrf", "xxe"],
            "medium": ["xss", "path_traversal", "lfi"],
            "low": ["open_redirect", "crlf", "information_disclosure"],
        }
        
        risk_level = "info"
        for level, categories in risk_factors.items():
            if any(e.get("category") in categories for e in confirmed_exploits):
                risk_level = level
                break
        
        assessment = {
            "risk_level": risk_level,
            "vulnerabilities_count": len(confirmed_exploits),
            "categories_affected": list(set(e.get("category") for e in confirmed_exploits)),
            "potential_impact": self._describe_impact(risk_level),
            "remediation_priority": self._get_priority(risk_level),
            "recommendations": self._generate_recommendations(confirmed_exploits),
        }
        
        logger.info(f"  ⚠️ 风险等级: {risk_level.upper()}")
        logger.info(f"  📝 建议: {assessment['recommendations'][0]}")
        
        return assessment
    
    def _quick_validate(self, resp: httpx.Response, category: str) -> bool:
        """快速验证响应是否表明漏洞存在"""
        text = resp.text.lower() if resp.text else ""
        
        indicators = {
            "sqli": ["sql syntax", "mysql_fetch", "postgresql", "ora-", "microsoft ole db"],
            "xss": ["<script>alert", "<svg onload", "<img src=x onerror"],
            "path_traversal": ["root:", "etc/passwd", "boot.ini", "windows\\system32"],
            "cmd_injection": ["uid=", "gid=", "root:/root", "system32"],
        }
        
        category_indicators = indicators.get(category, [])
        return any(ind in text for ind in category_indicators)
    
    def _describe_impact(self, risk_level: str) -> str:
        descriptions = {
            "critical": "可能导致远程代码执行或系统完全接管",
            "high": "可能导致敏感数据泄露或权限提升",
            "medium": "可能导致有限的数据泄露或用户会话劫持",
            "low": "可能泄露少量信息或造成轻微干扰",
            "info": "信息性发现，不构成直接威胁",
        }
        return descriptions.get(risk_level, "未知影响")
    
    def _get_priority(self, risk_level: str) -> str:
        priorities = {
            "critical": "立即修复 (P0)",
            "high": "24小时内修复 (P1)",
            "medium": "一周内修复 (P2)",
            "low": "下个周期修复 (P3)",
            "info": "建议修复 (P4)",
        }
        return priorities.get(risk_level, "待定")
    
    def _generate_recommendations(self, exploits: List[Dict[str, Any]]) -> List[str]:
        recommendations = [
            "对所有用户输入进行严格的验证和过滤",
            "使用参数化查询防止SQL注入",
            "实施Content Security Policy防止XSS",
            "定期更新依赖库和安全补丁",
            "部署Web Application Firewall (WAF)",
        ]
        
        # 根据具体漏洞添加针对性建议
        categories = set(e.get("category") for e in exploits)
        
        if "sqli" in categories:
            recommendations.insert(0, "使用ORM框架或参数化查询替代字符串拼接SQL")
        
        if "xss" in categories:
            recommendations.insert(0, "对输出内容进行HTML编码，使用安全的模板引擎")
        
        if "cmd_injection" in categories:
            recommendations.insert(0, "避免在应用中直接执行系统命令，使用白名单机制")
        
        return recommendations[:6]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取模拟器统计信息"""
        return {
            "simulations_run": self._simulations_run,
            "vulnerabilities_discovered": self._vulnerabilities_discovered,
            "current_session": self.session.to_dict() if self.session else None,
            "decision_engine_stats": self._decision_engine.get_decision_statistics(),
        }


def create_simulator(target: str, 
                     strategy: str = "intelligent",
                     **kwargs) -> AttackSimulator:
    """创建AttackSimulator实例的便捷函数"""
    return AttackSimulator(target=target, strategy=strategy, **kwargs)
