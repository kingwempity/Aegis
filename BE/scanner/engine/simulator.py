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
        self.history: List[AttackStep] = []
        self.context: Dict[str, Any] = {
            "target": self.target,
            "technologies": [],
            "current_phase": "init",
            "history": []
        }

    async def run_simulation(self) -> Dict[str, Any]:
        """执行完整的模拟攻击流程"""
        logger.info(f"🚀 开始对 {self.target} 进行模拟攻击 (策略: {self.strategy})")
        
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            # 1. 侦察阶段
            recon_result = await self.recon_engine.deep_recon(self.target, client)
            self.context["technologies"] = [t.name for t in recon_result.technologies]
            logger.info(f"🔍 侦察完成，识别技术栈: {self.context['technologies']}")

            # 2. 模拟攻击循环 (全时决策)
            max_rounds = 10
            found_vulns = []

            for i in range(max_rounds):
                self.context["current_phase"] = "exploitation"
                
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

                # 3. 结果复核 (如果是疑似漏洞)
                if self._is_potential_vuln(step):
                    logger.info(f"🎯 发现疑似漏洞，开始 LLM 复核...")
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
                        found_vulns.append({
                            "url": step.url,
                            "payload": step.payload,
                            "evidence": step.response_body[:1000],
                            "llm_analysis": verification["analysis"]
                        })
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
        # 基础的启发式判断
        indicators = ["sql syntax", "mysql_fetch", "<script>alert", "etc/passwd", "uid="]
        return any(ind in resp.text.lower() for ind in indicators)

    def _is_potential_vuln(self, step: AttackStep) -> bool:
        return step.success or step.status_code == 500

def create_simulator(target: str, strategy: str = "intelligent") -> AttackSimulator:
    return AttackSimulator(target=target, strategy=strategy)
