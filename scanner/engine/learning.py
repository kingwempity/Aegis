"""
scanner.engine.learning
-------------------
学习模块（Learning Module）

为Aegis提供自我进化和自适应学习能力：

核心能力：
1. 模式学习（Pattern Learning）
   - 从成功案例中学习有效模式
   - 从失败案例中识别失败原因
   - 构建目标特征-策略映射知识库

2. 反馈系统（Feedback System）
   - 收集攻击结果反馈
   - 评估策略有效性
   - 动态调整权重和参数

3. 策略优化（Strategy Optimization）
   - 基于强化学习的策略选择
   - 多臂老虎机算法优化
   - 在线学习和离线学习结合

4. 自适应引擎（Adaptive Engine）
   - 根据目标特征自动调整策略
   - 实时性能监控和调优
   - A/B测试不同攻击方法

设计原则：
    - 数据驱动：所有决策基于历史数据统计
    - 渐进式改进：持续优化而非一次性完美
    - 可解释性：能够解释为什么选择某个策略
    - 安全边界：避免过度激进导致的风险

使用示例:
    >>> learner = LearningEngine()
    >>> learner.record_success(target_info, payload, result)
    >>> learner.record_failure(target_info, payload, error_type)
    >>> strategy = learner.suggest_strategy(new_target)
    >>> print(f"推荐策略: {strategy['name']}, 置信度: {strategy['confidence']}")
"""

from __future__ import annotations

import time
import json
import hashlib
import random
import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set, Iterator
from enum import Enum, auto
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pickle
import os

logger = logging.getLogger(__name__)


class OutcomeType(Enum):
    """结果类型枚举"""
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"
    ERROR = "error"


class FailureReason(Enum):
    """失败原因分类"""
    WAF_BLOCKED = "waf_blocked"
    NO_MATCH = "no_match"
    ENCODING_ERROR = "encoding_error"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    VALIDATION_FAILED = "validation_failed"
    UNKNOWN = "unknown"


@dataclass
class AttackRecord:
    """
    攻击记录
    
    单次攻击尝试的完整记录，用于学习分析。
    """
    record_id: str = field(default_factory=lambda: f"rec_{int(time.time() % 10000)}")
    
    # 目标信息
    target_url: str = ""
    target_hash: str = ""  # 用于快速查找相似目标
    
    # 攻击信息
    vulnerability_type: str = ""
    payload_category: str = ""
    payload_used: str = ""
    bypass_technique: str = ""
    
    # 执行结果
    outcome: OutcomeType = OutcomeType.FAILURE
    success: bool = False
    
    # 详细结果
    status_code: int = 0
    response_time_ms: float = 0.0
    confidence_score: float = 0.0
    
    # 失败原因（如果失败）
    failure_reason: Optional[FailureReason] = None
    failure_details: str = ""
    
    # 特征向量（用于机器学习）
    features: Dict[str, float] = field(default_factory=dict)
    
    # 元数据
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    attempt_number: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "target_url": self.target_url,
            "vulnerability_type": self.vulnerability_type,
            "payload_category": self.payload_category,
            "bypass_technique": self.bypass_technique,
            "outcome": self.outcome.value,
            "success": self.success,
            "status_code": self.status_code,
            "response_time_ms": round(self.response_time_ms, 2),
            "confidence_score": round(self.confidence_score, 3),
            "failure_reason": self.failure_reason.value if self.failure_reason else None,
            "timestamp": self.timestamp,
        }
    
    def compute_target_hash(self) -> str:
        """计算目标特征哈希（用于相似性匹配）"""
        features_str = "|".join([
            self.target_url,
            self.vulnerability_type,
            str(self.status_code) if self.status_code else "",
        ])
        return hashlib.md5(features_str.encode()).hexdigest()[:12]


@dataclass
class StrategyProfile:
    """
    策略配置文件
    
    定义一种攻击策略的详细配置。
    """
    name: str
    description: str = ""
    
    # 参数配置
    aggressiveness: float = 0.7      # 激进程度 (0-1)
    max_retries: int = 3              # 最大重试次数
    timeout_per_request: float = 10.0  # 单次请求超时
    
    # Payload选择偏好
    preferred_payload_types: List[str] = field(default_factory=list)
    encoding_priority: Dict[str, float] = field(default_factory=dict)
    
    # 统计信息
    total_uses: int = 0
    successful_uses: int = 0
    average_confidence: float = 0.0
    last_used: Optional[float] = None
    
    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.5  # 默认值
        return self.successful_uses / self.total_uses
    
    def update_statistics(self, success: bool, confidence: float) -> None:
        """更新统计数据"""
        self.total_uses += 1
        self.last_used = time.time()
        
        if success:
            self.successful_uses += 1
        
        # 移动平均置信度
        alpha = 0.3  # 学习率
        self.average_confidence = (
            alpha * confidence + (1 - alpha) * self.average_confidence
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "aggressiveness": self.aggressiveness,
            "success_rate": f"{self.success_rate:.1%}",
            "average_confidence": round(self.average_confidence, 3),
            "total_uses": self.total_uses,
            "preferred_payload_types": self.preferred_payload_types[:5],
        }


class PatternLearner:
    """
    模式学习器
    
    从历史攻击记录中学习有效模式和失败模式，
    为未来的攻击决策提供依据。
    """
    
    def __init__(self, max_patterns: int = 1000):
        self.max_patterns = max_patterns
        
        # 存储所有攻击记录
        self.records: List[AttackRecord] = []
        
        # 成功模式库
        self.success_patterns: Dict[str, List[AttackRecord]] = defaultdict(list)
        
        # 失败模式库
        self.failure_patterns: Dict[str, List[AttackRecord]] = defaultdict(list)
        
        # 特征重要性评分
        feature_importance: Dict[str, float] = {}
        
        # 统计信息
        self.total_records = 0
        self.success_count = 0
        self.failure_count = 0
    
    def record_attack(self, record: AttackRecord) -> None:
        """记录一次攻击尝试"""
        record.target_hash = record.compute_target_hash()
        self.records.append(record)
        self.total_records += 1
        
        if record.success:
            self.success_count += 1
            key = self._generate_pattern_key(record, is_success=True)
            self.success_patterns[key].append(record)
            
            # 更新特征重要性
            self._update_feature_importance(record.features, positive=True)
        else:
            self.failure_count += 1
            key = self._generate_pattern_key(record, is_success=False)
            if record.failure_reason:
                key = f"{key}_{record.failure_reason.value}"
            self.failure_patterns[key].append(record)
            
            # 更新特征重要性（反向）
            self._update_feature_importance(record.features, positive=False)
        
        # 限制存储大小
        if len(self.records) > self.max_patterns * 10:
            self.records = self.records[-self.max_patterns * 5:]
    
    def _generate_pattern_key(self, record: AttackRecord, 
                               is_success: bool) -> str:
        """生成模式键（用于分组）"""
        parts = [
            record.vulnerability_type or "unknown",
            record.payload_category or "generic",
            record.bypass_technique or "none",
            "status_" + str(record.status_code // 100) + "xx" if record.status_code else "unknown",
        ]
        
        if is_success:
            return "_".join(parts)
        else:
            return "_".join([p for p in parts])
    
    def _update_feature_importance(self, features: Dict[str, float], 
                                     positive: bool = True) -> None:
        """更新特征重要性"""
        direction = 1 if positive else -1
        
        for feature_name, value in features.items():
            if feature_name not in self.feature_importance:
                self.feature_importance[feature_name] = 0.5  # 初始值
            
            # 使用对数几率更新
            current = self.feature_importance[feature_name]
            delta = direction * 0.1 * value
            
            new_value = max(0.01, min(0.99, current + delta))
            self.feature_importance[feature_name] = new_value
    
    def get_successful_patterns(self, 
                                  vulnerability_type: Optional[str] = None,
                                  limit: int = 20) -> List[Dict[str, Any]]:
        """获取成功模式"""
        patterns = []
        
        for pattern_key, records in self.success_patterns.items():
            if vulnerability_type and vulnerability_type not in pattern_key:
                continue
            
            if not records:
                continue
            
            # 计算模式的综合得分
            recent_records = records[-10:]  # 最近10次
            success_rate = sum(1 for r in recent_records if r.success) / len(recent_records)
            avg_confidence = sum(r.confidence_score for r in recent_records) / len(recent_records)
            avg_time = sum(r.response_time_ms for r in recent_records) / len(recent_records)
            
            # 提取典型payload
            sample_payloads = list(set(r.payload_used for r in records[-5:] if r.payload_used))
            
            patterns.append({
                "pattern_id": pattern_key[:30],
                "vulnerability_type": vulnerability_type or "mixed",
                "sample_count": len(records),
                "recent_success_rate": round(success_rate, 3),
                "average_confidence": round(avg_confidence, 3),
                "average_response_time_ms": round(avg_time, 2),
                "effective_payloads": sample_payloads[:5],
                "last_success_time": max(r.timestamp for r in records),
            })
        
        # 按成功率排序
        patterns.sort(key=lambda x: x["recent_success_rate"], reverse=True)
        
        return patterns[:limit]
    
    def get_failure_analysis(self, 
                              vulnerability_type: Optional[str] = None,
                              limit: int = 15) -> List[Dict[str, Any]]:
        """获取失败模式分析"""
        analysis = []
        
        for pattern_key, records in self.failure_patterns.items():
            if vulnerability_type and vulnerability_type not in pattern_key:
                continue
            
            if not records:
                continue
            
            # 分析失败原因分布
            reason_counts = Counter(
                r.failure_reason.value for r in records 
                if r.failure_reason
            )
            
            most_common_reason = reason_counts.most_common(1)[0][0] if reason_counts else "unknown"
            
            # 计算失败率
            recent_records = records[-10:]
            failure_rate = sum(1 for r in recent_records if not r.success) / len(recent_records)
            
            analysis.append({
                "pattern_id": pattern_key[:30],
                "failure_count": len(records),
                "recent_failure_rate": round(failure_rate, 3),
                "primary_failure_reason": most_common_reason,
                "suggested_avoidance": self._get_avoidance_suggestion(most_common_reason),
            })
        
        # 按失败频率排序
        analysis.sort(key=lambda x: x["failure_count"], reverse=True)
        
        return analysis[:limit]
    
    def _get_avoidance_suggestion(self, failure_reason: str) -> str:
        """根据失败原因给出规避建议"""
        suggestions = {
            FailureReason.WAF_BLOCKED.value: "使用更高级的编码绕过技术或更换IP",
            FailureReason.NO_MATCH.value: "尝试不同的Payload变体或检查输入点",
            FailureReason.ENCODING_ERROR.value: "检查Payload编码方式是否与目标兼容",
            FailureReason.TIMEOUT.value: "增加超时时间或使用异步验证",
            FailureReason.NETWORK_ERROR.value: "检查网络连接和DNS解析",
            FailureReason.VALIDATION_FAILED.value: "收集更多证据以确认漏洞存在",
        }
        return suggestions.get(failure_reason, "需要进一步分析")
    
    def find_similar_targets(self, 
                             target_features: Dict[str, Any],
                             limit: int = 10) -> List[Dict[str, Any]]:
        """查找历史上相似的目标及其最佳策略"""
        similar = []
        
        for record in self.records[-500:]:  # 最近500条记录
            if not record.success:
                continue
            
            # 简单的特征匹配（实际应用可使用更复杂的ML算法）
            match_score = 0.0
            
            if record.vulnerability_type == target_features.get("vuln_type"):
                match_score += 0.4
            if record.bypass_technique == target_features.get("bypass"):
                match_score += 0.3
            if abs(record.status_code - target_features.get("status_code", 0)) < 100:
                match_score += 0.2
            if record.target_hash == target_features.get("target_hash", ""):
                match_score += 0.1
            
            if match_score > 0.5:
                similar.append({
                    "target_url": record.target_url,
                    "similarity": round(match_score, 3),
                    "successful_payload": record.payload_used[:80],
                    "bypass_technique": record.bypass_technique,
                    "confidence_achieved": record.confidence_score,
                    "response_time": record.response_time_ms,
                })
        
        similar.sort(key=lambda x: x["similarity"], reverse=True)
        
        return similar[:limit]
    
    def get_feature_importance(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """获取最重要的特征"""
        sorted_features = sorted(
            self.feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:top_n]
        
        return [
            {"feature": name, "importance": round(score, 4)}
            for name, score in sorted_features
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取学习器统计"""
        overall_success_rate = (
            self.success_count / max(self.total_records, 1)
        )
        
        return {
            "total_records": self.total_records,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "overall_success_rate": f"{overall_success_rate:.1%}",
            "patterns_learned": len(self.success_patterns) + len(self.failure_patterns),
            "features_tracked": len(self.feature_importance),
            "knowledge_base_size": len(self.records),
        }
    
    def export_knowledge(self, filepath: str) -> bool:
        """导出知识库到文件"""
        try:
            knowledge = {
                "export_timestamp": datetime.now().isoformat(),
                "statistics": self.get_statistics(),
                "successful_patterns": [
                    {"key": k, "count": len(v)} 
                    for k, v in list(self.success_patterns.items())[:50]
                ],
                "failure_patterns": [
                    {"key": k, "count": len(v)}
                    for k, v in list(self.failure_patterns.items())[:50]
                ],
                "feature_importance": self.get_feature_importance(30),
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(knowledge, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ 知识库已导出到 {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ 导出知识库失败: {e}")
            return False


class FeedbackSystem:
    """
    反馈系统
    
    收集和分析攻击结果的反馈，用于优化后续决策。
    
    功能：
    1. 结果收集和分类
    2. 策略效果评估
    3. 异常检测
    4. 趋势分析
    """
    
    def __init__(self):
        self.feedback_history: List[Dict[str, Any]] = []
        self.strategy_performance: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "attempts": 0,
            "successes": 0,
            "failures": 0,
            "avg_confidence": 0.0,
            "avg_time": 0.0,
            "last_result": None,
        })
        
        # 性能基线
        self.performance_baseline = {
            "overall_success_rate": 0.3,
            "avg_confidence": 0.5,
            "avg_response_time_ms": 500.0,
        }
        
        # 趋势数据
        self.recent_trends: List[Dict[str, Any]] = []
        
        logger.info("📊 反馈系统已初始化")
    
    def record_feedback(self, 
                        strategy_name: str,
                        outcome: OutcomeType,
                        confidence: float = 0.0,
                        response_time_ms: float = 0.0,
                        details: Optional[Dict[str, Any]] = None) -> None:
        """
        记录一条反馈
        """
        feedback_entry = {
            "timestamp": time.time(),
            "strategy": strategy_name,
            "outcome": outcome.value,
            "confidence": confidence,
            "response_time_ms": response_time_ms,
            "details": details or {},
        }
        
        self.feedback_history.append(feedback_entry)
        
        # 更新策略统计
        stats = self.strategy_performance[strategy_name]
        stats["attempts"] += 1
        stats["last_result"] = outcome.value
        stats["last_timestamp"] = time.time()
        
        if outcome == OutcomeType.SUCCESS:
            stats["successes"] += 1
            alpha = 0.3
            stats["avg_confidence"] = (
                alpha * confidence + (1 - alpha) * stats["avg_confidence"]
            )
        elif outcome == OutcomeType.BLOCKED:
            stats["failures"] += 1
        else:
            stats["failures"] += 1
        
        # 更新平均时间
        if response_time_ms > 0:
            alpha = 0.2
            stats["avg_time"] = (
                alpha * response_time_ms + (1 - alpha) * stats["avg_time"]
            )
        
        # 保留最近的历史
        if len(self.feedback_history) > 5000:
            self.feedback_history = self.feedback_history[-3000:]
    
    def evaluate_strategy(self, strategy_name: str) -> Dict[str, Any]:
        """
        评估特定策略的性能
        """
        stats = self.strategy_performance.get(strategy_name, {})
        
        if not stats or stats["attempts"] == 0:
            return {
                "strategy": strategy_name,
                "status": "insufficient_data",
                "recommendation": "需要更多数据才能评估",
                "confidence": 0.0,
            }
        
        success_rate = stats["successes"] / stats["attempts"]
        
        # 与基线比较
        baseline_success = self.performance_baseline["overall_success_rate"]
        improvement = success_rate - baseline_success
        
        # 评估状态
        if success_rate >= 0.8 and stats["attempts"] >= 10:
            status = "excellent"
            recommendation = "继续使用此策略"
        elif success_rate >= 0.6:
            status = "good"
            recommendation = "此策略表现良好"
        elif success_rate >= 0.4:
            status = "acceptable"
            recommendation = "可以继续使用，但考虑优化"
        elif success_rate >= 0.2:
            status = "poor"
            recommendation = "建议降低使用优先级或修改参数"
        else:
            status = "bad"
            recommendation = "建议停用此策略或大幅修改"
        
        return {
            "strategy": strategy_name,
            "status": status,
            "success_rate": f"{success_rate:.1%}",
            "total_attempts": stats["attempts"],
            "average_confidence": round(stats["avg_confidence"], 3),
            "average_response_time_ms": round(stats["avg_time"], 2),
            "improvement_over_baseline": f"{improvement:+.1%}" if improvement != 0 else "baseline",
            "recommendation": recommendation,
            "data_confidence": min(stats["attempts"] / 20.0, 1.0),  # 数据可信度
        }
    
    def detect_anomalies(self) -> List[Dict[str, Any]]:
        """
        检测异常的反馈模式
        """
        anomalies = []
        
        if len(self.feedback_history) < 20:
            return anomalies
        
        # 计算最近的趋势
        recent = self.feedback_history[-50:]
        
        # 1. 成功率突然下降
        if len(recent) >= 20:
            older = recent[:-10]
            newer = recent[-10:]
            
            older_success = sum(1 for f in older if f["outcome"] == "success") / len(older)
            newer_success = sum(1 for f in newer if f["outcome"] == "success") / len(newer)
            
            drop = older_success - newer_success
            if drop > 0.3:
                anomalies.append({
                    "type": "success_rate_drop",
                    "severity": "high" if drop > 0.5 else "medium",
                    "description": f"成功率下降了{drop:.1%}，可能遇到更强的防护",
                    "drop_percentage": f"{drop:.1%}",
                })
        
        # 2. 响应时间突然增加
        times = [f.get("response_time_ms", 0) for f in recent if f.get("response_time_ms", 0) > 0]
        if times:
            avg_time = sum(times) / len(times)
            slow_requests = [t for t in times if t > avg_time * 3]
            
            if len(slow_requests) > len(times) * 0.3:
                anomalies.append({
                    "type": "response_time_spike",
                    "severity": "medium",
                    "description": f"{len(slow_requests)}个请求响应时间超过平均值3倍",
                    "average_time_ms": round(avg_time, 2),
                })
        
        # 3. 大量被拦截
        blocked = sum(1 for f in recent if f["outcome"] == "blocked")
        if blocked > len(recent) * 0.7:
            anomalies.append({
                "type": "high_block_rate",
                "severity": "high",
                "description": f"{blocked}/{len(recent)}个请求被拦截({blocked/len(recent):.0%})",
                "block_rate": f"{blocked/len(recent):.0%}",
            })
        
        return anomalies
    
    def get_trend_analysis(self, window_hours: float = 24.0) -> Dict[str, Any]:
        """
        趋势分析
        """
        cutoff_time = time.time() - (window_hours * 3600)
        recent_feedback = [
            f for f in self.feedback_history 
            if f.get("timestamp", 0) > cutoff_time
        ]
        
        if not recent_feedback:
            return {"message": "没有足够的数据进行趋势分析"}
        
        # 计算时间窗口内的趋势
        hours = [(f["timestamp"] - cutoff_time) / 3600 for f in recent_feedback]
        
        # 按小时分桶
        hourly_buckets = defaultdict(list)
        for f, h in zip(recent_feedback, hours):
            bucket = int(h)
            hourly_buckets[bucket].append(f)
        
        trends = []
        for hour in sorted(hourly_buckets.keys()):
            bucket_data = hourly_buckets[hour]
            success_rate = sum(1 for f in bucket_data if f["outcome"] == "success") / len(bucket_data)
            avg_confidence = sum(f.get("confidence", 0) for f in bucket_data) / len(bucket_data)
            
            trends.append({
                "hour_offset": hour,
                "requests": len(bucket_data),
                "success_rate": round(success_rate, 3),
                "avg_confidence": round(avg_confidence, 3),
            })
        
        # 整体趋势方向
        if len(trends) >= 2:
            first_half = trends[:len(trends)//2]
            second_half = trends[len(trends)//2:]
            
            first_avg = sum(t["success_rate"] for t in first_half) / len(first_half)
            second_avg = sum(t["success_rate"] for t in second_half) / len(second_half)
            
            trend_direction = "improving" if second_avg > first_avg else "declining" if second_avg < first_avg else "stable"
        else:
            trend_direction = "insufficient_data"
        
        return {
            "window_hours": window_hours,
            "total_requests_in_window": len(recent_feedback),
            "overall_success_rate": sum(1 for f in recent_feedback if f["outcome"] == "success") / len(recent_feedback),
            "hourly_trends": trends[-12:],  # 最近12个小时
            "trend_direction": trend_direction,
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取反馈系统统计"""
        total = len(self.feedback_history)
        successes = sum(1 for f in self.feedback_history if f.get("outcome") == "success")
        
        return {
            "total_feedback_records": total,
            "successful_attacks": successes,
            "overall_success_rate": f"{successes/max(total, 1):.1%}",
            "strategies_evaluated": len(self.strategy_performance),
            "anomalies_detected": len(self.detect_anomalies()),
        }


class MultiArmedBandit:
    """
    多臂老虎机算法（Multi-Armed Bandit）
    
    用于在多个策略之间进行最优选择，平衡探索（Exploration）和利用（Exploitation）。
    
    实现UCB1（Upper Confidence Bound）算法。
    """
    
    def __init__(self, exploration_factor: float = 2.0):
        """
        初始化多臂老虎机
        
        Args:
            exploration_factor: 探索因子（控制探索vs利用的平衡），默认2.0（UCB1标准值）
        """
        self.exploration_factor = exploration_factor
        self.arms: Dict[str, Dict[str, float]] = {}  # arm -> {rewards, counts, ucb}
        self.total_pulls = 0
        
        logger.info(f"🎰 多臂老虎机初始化 (exploration={exploration_factor})")
    
    def add_arm(self, arm_name: str, initial_value: float = 0.0) -> None:
        """添加一个策略选项（arm）"""
        self.arms[arm_name] = {
            "reward": initial_value,
            "pulls": 0,
            "ucb": initial_value,
        }
    
    def select_arm(self) -> str:
        """
        选择一个arm（策略）进行尝试
        
        UCB算法：选择具有最高上置信界的arm
        """
        if not self.arms:
            return "default"
        
        # 如果有未尝试过的arm，优先尝试
        untried = [name for name, data in self.arms.items() if data["pulls"] == 0]
        if untried:
            return random.choice(untried)
        
        # 计算每个arm的UCB值
        best_arm = "default"
        best_ucb = -float('inf')
        
        for arm_name, data in self.arms.items():
            if data["pulls"] == 0:
                ucb = float('inf')
            else:
                bonus = math.sqrt(
                    self.exploration_factor * math.log(self.total_pulls + 1) / data["pulls"]
                )
                ucb = data["reward"] + data["ucb"] + bonus
            
            if ucb > best_ucb:
                best_ucb = ucb
                best_arm = arm_name
        
        return best_arm
    
    def update_reward(self, arm_name: str, reward: float) -> None:
        """
        更新arm的奖励值
        
        Args:
            arm_name: 策略名称
            reward: 奖励值（通常在0-1之间）
        """
        if arm_name not in self.arms:
            self.add_arm(arm_name)
        
        data = self.arms[arm_name]
        data["pulls"] += 1
        self.total_pulls += 1
        
        # 更新平均奖励（增量更新）
        n = data["pulls"]
        old_mean = data["reward"]
        data["reward"] = old_mean + (reward - old_mean) / n
    
    def get_arm_statistics(self, arm_name: Optional[str] = None) -> Any:
        """获取arm的统计信息"""
        if arm_name:
            if arm_name in self.arms:
                return self.arms[arm_name]
            return None
        
        return {
            name: {
                "average_reward": round(data["reward"], 4),
                "pulls": data["pulls"],
                "ucb_score": round(data["ucb"] + math.sqrt(
                    self.exploration_factor * math.log(max(self.total_pulls, 1)) / max(data["pulls"], 1)
                ), 4) if data["pulls"] > 0 else float('inf'),
            }
            for name, data in self.arms.items()
        }
    
    def get_best_arm(self) -> Optional[Tuple[str, float]]:
        """获取目前表现最好的arm"""
        if not self.arms:
            return None
        
        best_arm = max(self.arms.items(), key=lambda x: x[1]["reward"])
        return (best_arm[0], best_arm[1]["reward"])
    
    def reset_statistics(self) -> None:
        """重置统计（保留arm定义）"""
        for arm in self.arms.values():
            arm["reward"] = 0.0
            arm["pulls"] = 0
            arm["ucb"] = 0.0
        self.total_pulls = 0


class AdaptiveStrategyEngine:
    """
    自适应策略引擎
    
    结合模式学习、反馈系统和多臂老虎机，
    提供智能的策略选择和自适应能力。
    """
    
    def __init__(self):
        self.pattern_learner = PatternLearner()
        self.feedback_system = FeedbackSystem()
        self.bandit = MultiArmedBandit(exploration_factor=2.0)
        
        # 预定义策略
        self.strategies: Dict[str, StrategyProfile] = {}
        self._initialize_default_strategies()
        
        # 当前活跃策略
        self.current_strategy: Optional[str] = None
        
        # 自适应状态
        self.adaptation_count = 0
        self.last_adaptation: Optional[float] = None
        
        logger.info("🧠 自适应策略引擎已初始化")
    
    def _initialize_default_strategies(self) -> None:
        """初始化默认策略"""
        default_strategies = [
            StrategyProfile(
                name="conservative",
                description="保守策略：低激进度，高安全性",
                aggressiveness=0.3,
                max_retries=2,
                encoding_priority={"url_encoding": 0.9, "case_manipulation": 0.7},
            ),
            StrategyProfile(
                name="balanced",
                description="平衡策略：中等激进度和安全性",
                aggressiveness=0.6,
                max_retries=3,
                encoding_priority={"url_encoding": 0.8, "unicode_encoding": 0.7, "comment_insertion": 0.6},
            ),
            StrategyProfile(
                name="aggressive",
                description="激进策略：高激进度，快速但风险大",
                aggressiveness=0.9,
                max_retries=5,
                encoding_priority={"double_url_encoding": 0.9, "null_byte_injection": 0.8, "multiple_encoding": 0.7},
            ),
            StrategyProfile(
                name="stealthy",
                description="隐秘策略：低检测率，慢速但隐蔽",
                aggressiveness=0.4,
                max_retries=2,
                encoding_priority={"case_manipulation": 0.9, "whitespace_substitution": 0.8},
            ),
        ]
        
        for strategy in default_strategies:
            self.strategies[strategy.name] = strategy
            self.bandit.add_arm(strategy.name)
    
    async def suggest_strategy(self, 
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """
        根据上下文建议最优策略
        
        Args:
            context: 目标上下文信息
            
        Returns:
            推荐策略及理由
        """
        # 1. 检查是否有相似目标的成功经验
        similar_targets = self.pattern_learner.find_similar_targets(context, limit=5)
        
        # 2. 基于多臂老虎机的初始选择
        bandit_choice = self.bandit.select_arm()
        
        # 3. 如果有相似目标经验，结合经验调整
        if similar_targets and random.random() < 0.7:  # 70%概率使用经验
            best_match = similar_targets[0]
            suggested_strategy = self._infer_strategy_from_similarity(best_match)
            
            if suggested_strategy and suggested_strategy in self.strategies:
                final_strategy = suggested_strategy
                selection_method = "experience_based"
            else:
                final_strategy = bandit_choice
                selection_method = "bandit_fallback"
        else:
            final_strategy = bandit_choice
            selection_method = "pure_exploration"
        
        # 4. 获取策略详情
        strategy_profile = self.strategies.get(final_strategy)
        
        if not strategy_profile:
            final_strategy = "balanced"
            strategy_profile = self.strategies["balanced"]
        
        self.current_strategy = final_strategy
        
        # 5. 构造返回结果
        result = {
            "recommended_strategy": final_strategy,
            "strategy_details": strategy_profile.to_dict(),
            "selection_method": selection_method,
            "confidence": self._calculate_recommendation_confidence(
                final_strategy, similar_targets, context
            ),
            "reasoning": self._generate_recommendation_reasoning(
                final_strategy, selection_method, similar_targets, context
            ),
            "similar_cases": similar_targets[:3] if similar_targets else [],
            "adaptation_info": {
                "total_adaptations": self.adaptation_count,
                "last_adaptation": self.last_adaptation,
            },
        }
        
        return result
    
    def _infer_strategy_from_similarity(self, similarity_match: Dict) -> Optional[str]:
        """从相似目标推断策略"""
        technique = similarity_match.get("bypass_technique", "")
        
        # 映射绕过技术到策略
        technique_to_strategy = {
            "url_encoding": "conservative",
            "unicode_encoding": "balanced",
            "comment_insertion": "aggressive",
            "null_byte_injection": "aggressive",
            "case_manipulation": "stealthy",
            "whitespace_substitution": "stealthy",
        }
        
        return technique_to_strategy.get(technique.lower())
    
    def _calculate_recommendation_confidence(self, 
                                             strategy: str,
                                             similar_targets: List,
                                             context: Dict) -> float:
        """计算推荐的置信度"""
        base_confidence = 0.5
        
        # 有相似经验提升置信度
        if similar_targets:
            base_confidence += 0.2 * min(len(similar_targets), 5) / 5
        
        # 策略本身的表现
        strategy_stats = self.feedback_system.evaluate_strategy(strategy)
        data_quality = strategy_stats.get("data_confidence", 0.5)
        
        base_confidence *= (0.5 + 0.5 * data_quality)
        
        return min(base_confidence, 0.95)
    
    def _generate_recommendation_reasoning(self,
                                          strategy: str,
                                          method: str,
                                          similar: List,
                                          context: Dict) -> str:
        """生成推荐理由"""
        reasons = []
        
        if method == "experience_based":
            reasons.append(f"基于{len(similar)}个相似目标的成功经验")
            if similar:
                best = similar[0]
                reasons.append(f"最相似目标成功率: {best.get('similarity', 0):.0%}")
        
        elif method == "bandit_fallback":
            reasons.append("无直接经验可用，使用强化学习优化")
        
        elif method == "pure_exploration":
            reasons.append("探索新模式，可能发现新的有效策略")
        
        # 添加策略特性说明
        profile = self.strategies.get(strategy)
        if profile:
            if profile.aggressiveness > 0.7:
                reasons.append(f"选用激进策略以提高发现概率")
            elif profile.aggressiveness < 0.5:
                reasons.append(f"选用保守策略以降低被封禁风险")
        
        return "; ".join(reasons) if reasons else "基于当前数据和算法的推荐"
    
    def record_outcome(self, 
                       strategy_name: str,
                       outcome: OutcomeType,
                       confidence: float,
                       attack_record: Optional[AttackRecord] = None) -> None:
        """
        记录攻击结果并触发学习
        """
        # 1. 记录到反馈系统
        self.feedback_system.record_feedback(
            strategy_name=strategy_name,
            outcome=outcome,
            confidence=confidence,
            response_time_ms=attack_record.response_time_ms if attack_record else 0.0,
        )
        
        # 2. 更新策略统计
        if strategy_name in self.strategies:
            self.strategies[strategy_name].update_statistics(
                success=(outcome == OutcomeType.SUCCESS),
                confidence=confidence
            )
        
        # 3. 更新多臂老虎机
        reward = confidence if outcome == OutcomeType.SUCCESS else 0.0
        self.bandit.update_reward(strategy_name, reward)
        
        # 4. 记录到模式学习器
        if attack_record:
            self.pattern_learner.record_attack(attack_record)
        
        # 5. 触发自适应调整（如果需要）
        self._check_and_adapt()
    
    def _check_and_adapt(self) -> None:
        """检查是否需要自适应调整"""
        # 每10次记录后检查一次
        if len(self.feedback_system.feedback_history) % 10 != 0:
            return
        
        # 检测异常
        anomalies = self.feedback_system.detect_anomalies()
        
        if anomalies:
            severe = [a for a in anomalies if a.get("severity") == "high"]
            if severe:
                self._perform_adaptation(severe[0])
    
    def _perform_adaptation(self, anomaly: Dict) -> None:
        """执行自适应调整"""
        anomaly_type = anomaly.get("type", "")
        
        if anomaly_type == "success_rate_drop":
            # 成功率下降，切换到更保守的策略
            if self.current_strategy == "aggressive":
                logger.info("🔄 自适应：成功率下降，切换到平衡策略")
                self.current_strategy = "balanced"
                
        elif anomaly_type == "high_block_rate":
            # 高封禁率，启用隐秘模式
            logger.info("🔄 自适应：高封禁率，切换到隐秘策略")
            self.current_strategy = "stealthy"
            
        elif anomaly_type == "response_time_spike":
            # 响应时间增加，减少并发和超时
            logger.info("⏱️ 自适应：响应时间增加，调整参数")
        
        self.adaptation_count += 1
        self.last_adaptation = time.time()
    
    def get_learning_summary(self) -> Dict[str, Any]:
        """获取学习系统摘要"""
        best_arm = self.bandit.get_best_arm()
        
        summary = {
            "pattern_learner": self.pattern_learner.get_statistics(),
            "feedback_system": self.feedback_system.get_statistics(),
            "bandit_algorithm": {
                "total_arms": len(self.bandit.arms),
                "total_selections": self.bandit.total_pulls,
                "best_arm": best_arm[0] if best_arm else None,
                "best_average_reward": round(best_arm[1], 4) if best_arm else None,
            },
            "current_strategy": self.current_strategy,
            "adaptation": {
                "total_adaptations": self.adaptation_count,
                "last_adaptation": self.last_adaptation,
            },
        }
        
        return summary


class LearningEngine:
    """
    学习引擎主类
    
    整合所有学习组件，提供统一接口。
    """
    
    def __init__(self, enable_persistence: bool = True):
        self.enable_persistence = enable_persistence
        
        # 子系统
        self.pattern_learner = PatternLearner()
        self.feedback_system = FeedbackSystem()
        self.adaptive_engine = AdaptiveStrategyEngine()
        
        # 统计
        self.learning_sessions = 0
        
        # 持久化路径
        self.knowledge_path = "scanner/data/knowledge_base.json"
        
        if enable_persistence:
            self._load_existing_knowledge()
        
        logger.info(f"📚 LearningEngine 已初始化 (persistence={enable_persistence})")
    
    def _load_existing_knowledge(self) -> None:
        """加载已有的知识库"""
        if os.path.exists(self.knowledge_path):
            try:
                with open(self.knowledge_path, 'r', encoding='utf-8') as f:
                    knowledge = json.load(f)
                
                logger.info(f"✅ 已加载已有知识库 ({os.path.getsize(self.knowledge_path)} bytes)")
                
            except Exception as e:
                logger.warning(f"⚠️ 加载知识库失败: {e}")
    
    async def learn_from_scan_session(self, 
                                      scan_results: List[Dict[str, Any]],
                                      target_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        从扫描会话中学习
        
        Args:
            scan_results: 扫描结果列表
            target_info: 目标信息
            
        Returns:
            学习报告
        """
        self.learning_sessions += 1
        
        learning_report = {
            "session_id": f"learn_{int(time.time()) % 10000}",
            "timestamp": datetime.now().isoformat(),
            "records_processed": 0,
            "new_patterns_learned": 0,
            "strategies_updated": 0,
            "insights": [],
        }
        
        for result in scan_results:
            # 创建攻击记录
            record = AttackRecord(
                target_url=target_info.get("url", ""),
                vulnerability_type=result.get("type", ""),
                payload_category=result.get("category", "generic"),
                payload_used=result.get("payload", "")[:200],
                bypass_technique=result.get("bypass_technique", ""),
                outcome=OutcomeType.SUCCESS if result.get("success") else OutcomeType.FAILURE,
                success=result.get("success", False),
                status_code=result.get("response", {}).get("status", 0),
                confidence_score=result.get("evidence", {}).get("confidence", 0),
                features=self._extract_features(result, target_info),
            )
            
            # 记录到模式学习器
            self.pattern_learner.record_attack(record)
            learning_report["records_processed"] += 1
            
            # 记录到反馈系统
            strategy = result.get("strategy", "balanced")
            outcome = OutcomeType.SUCCESS if record.success else OutcomeType.FAILURE
            
            self.feedback_system.record_feedback(
                strategy_name=strategy,
                outcome=outcome,
                confidence=record.confidence_score,
                response_time_ms=result.get("response", {}).get("response_time_ms", 0),
            )
            
            # 更新策略统计
            if strategy in self.adaptive_engine.strategies:
                self.adaptive_engine.strategies[strategy].update_statistics(
                    success=record.success,
                    confidence=record.confidence_score
                )
                learning_report["strategies_updated"] += 1
        
        # 生成洞察
        learning_report["insights"] = self._generate_insights(scan_results, target_info)
        
        # 保存知识库
        if self.enable_persistence:
            self.pattern_learner.export_knowledge(self.knowledge_path)
        
        logger.info(f"📚 学习完成: 处理{learning_report['records_processed']}条记录, "
                   f"发现{learning_report['new_patterns_learned']}个新模式")
        
        return learning_report
    
    def _extract_features(self, result: Dict, target: Dict) -> Dict[str, float]:
        """提取特征向量"""
        features = {}
        
        # 目标特征
        features["has_waf"] = 1.0 if target.get("waf_detected") else 0.0
        features["framework_risk"] = self._get_framework_risk_score(target.get("framework", ""))
        features["db_present"] = 1.0 if target.get("database") else 0.0
        
        # 攻击特征
        features["is_sql_injection"] = 1.0 if "sql" in result.get("type", "").lower() else 0.0
        features["is_xss"] = 1.0 if "xss" in result.get("type", "").lower() else 0.0
        features["is_cmd_injection"] = 1.0 if any(k in result.get("type", "").lower() for k in ["cmd", "rce"]) else 0.0
        
        # 结果特征
        features["high_confidence"] = 1.0 if result.get("evidence", {}).get("confidence", 0) > 0.7 else 0.0
        features["fast_response"] = 1.0 if result.get("response", {}).get("response_time_ms", 0) < 1000 else 0.0
        features["error_status"] = 1.0 if result.get("response", {}).get("status", 0) >= 400 else 0.0
        
        return features
    
    def _get_framework_risk_score(self, framework: str) -> float:
        risk_scores = {
            "thinkphp": 0.85,
            "wordpress": 0.70,
            "drupal": 0.65,
            "joomla": 0.60,
            "asp.net": 0.55,
            "django": 0.35,
            "laravel": 0.40,
            "spring": 0.45,
        }
        return risk_scores.get(framework.lower(), 0.5)
    
    def _generate_insights(self, results: List[Dict], target: Dict) -> List[str]:
        """生成学习洞察"""
        insights = []
        
        # 成功率分析
        successful = [r for r in results if r.get("success")]
        total = len(results)
        
        if total > 0:
            success_rate = len(successful) / total
            if success_rate > 0.5:
                insights.append(f"本次扫描成功率较高({success_rate:.0%})，目标防御较弱")
            elif success_rate < 0.2:
                insights.append(f"本次扫描成功率较低({success_rate:.0%})，目标防护较强或需要调整策略")
        
        # 漏洞类型分布
        vuln_types = Counter(r.get("type", "unknown") for r in results)
        if vuln_types:
            most_common = vuln_types.most_common(1)[0]
            insights.append(f"最常见的漏洞类型: {most_common}")
        
        # WAF影响
        waf_present = target.get("waf_detected", False)
        if waf_present:
            waf_blocked = sum(1 for r in results if r.get("blocked_by_waf"))
            if waf_blocked > 0:
                insights.append(f"WAF阻止了{waf_blocked}个攻击尝试，建议使用高级绕过技术")
        
        return insights[:5]
    
    async def suggest_optimal_approach(self, 
                                       target: Dict[str, Any]) -> Dict[str, Any]:
        """
        为新目标建议最优攻击方法
        """
        suggestion = await self.adaptive_engine.suggest_strategy(target)
        
        # 补充信息
        suggestion["historical_context"] = {
            "similar_targets_found": len(
                self.pattern_learner.find_similar_targets(target)
            ),
            "total_learning_sessions": self.learning_sessions,
            "knowledge_base_size": self.pattern_learner.total_records,
        }
        
        return suggestion
    
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """获取综合学习报告"""
        return {
            "engine_info": {
                "type": "Aegis Learning Engine v1.0",
                "capabilities": [
                    "Pattern Learning from Attack History",
                    "Multi-Armed Bandit Strategy Optimization",
                    "Real-time Adaptation and Anomaly Detection",
                    "Knowledge Base Persistence",
                ],
                "session_stats": {
                    "total_learning_sessions": self.learning_sessions,
                    "knowledge_base_records": self.pattern_learner.total_records,
                    "patterns_discovered": len(self.pattern_learner.success_patterns) + len(self.pattern_learner.failure_patterns),
                },
            },
            "pattern_learner": self.pattern_learner.get_statistics(),
            "feedback_system": self.feedback_system.get_statistics(),
            "adaptive_engine": self.adaptive_engine.get_learning_summary(),
            "feature_importance": self.pattern_learner.get_feature_importance(15),
            "top_strategies": [
                self.adaptive_engine.strategies[name].to_dict()
                for name in ["conservative", "balanced", "aggressive", "stealthy"]
                if name in self.adaptive_engine.strategies
            ],
        }
    
    def export_all_knowledge(self, filepath: str) -> bool:
        """导出所有学到的知识"""
        all_knowledge = {
            "export_timestamp": datetime.now().isoformat(),
            "comprehensive_report": self.get_comprehensive_report(),
        }
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(all_knowledge, f, indent=2, ensure_ascii=False)
            
            logger.info(f"✅ 完整知识库已导出到 {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"❌ 导出失败: {e}")
            return False


def create_learning_engine(enable_persistence: bool = True) -> LearningEngine:
    """创建LearningEngine实例的便捷函数"""
    return LearningEngine(enable_persistence=enable_persistence)
