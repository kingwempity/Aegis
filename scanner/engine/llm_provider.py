import os
import json
import logging
from typing import Dict, Any, List, Optional
from openai import OpenAI

logger = logging.getLogger(__name__)

class LLMProvider:
    """
    LLM 服务提供者，负责与大模型通信进行攻击决策和结果复核。
    """
    def __init__(self, model: str = "gpt-4.1-mini"):
        self.client = OpenAI()
        self.model = model

    async def decide_next_step(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        全时决策：基于当前攻击上下文决定下一步行动。
        """
        prompt = f"""
你是一个专业的渗透测试专家。请分析当前的攻击上下文并决定下一步行动。
当前目标: {context.get('target')}
已识别技术栈: {context.get('technologies')}
当前阶段: {context.get('current_phase')}
历史尝试: {json.dumps(context.get('history', []), ensure_ascii=False)}
最近一次响应状态码: {context.get('last_status')}
最近一次响应内容摘要: {context.get('last_response_snippet')}

请输出 JSON 格式的决策：
{{
    "action": "continue/retry/change_vector/terminate",
    "reason": "决策原因",
    "payload_mutation": "如果需要重试，建议的 Payload 变异方向",
    "next_target_path": "建议的下一个探测路径",
    "confidence": 0.0-1.0
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"LLM 决策失败: {e}")
            return {"action": "continue", "reason": "LLM 故障降级", "confidence": 0.0}

    async def verify_vulnerability(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        结果复核：判定漏洞证据是否真实有效。
        """
        prompt = f"""
请作为安全审计员复核以下漏洞证据。
漏洞类型: {evidence.get('vuln_name')}
请求 URL: {evidence.get('url')}
Payload: {evidence.get('payload')}
响应状态码: {evidence.get('status_code')}
响应内容: {evidence.get('response_body')}

请判定该漏洞是否为真实存在（True Positive）或误报（False Positive）。
输出 JSON:
{{
    "is_valid": true/false,
    "confidence": 0.0-1.0,
    "analysis": "分析原因"
}}
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"LLM 复核失败: {e}")
            return {"is_valid": True, "confidence": 0.5, "analysis": "LLM 故障默认通过"}
