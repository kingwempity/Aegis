"""
scanner.engine.lab_generator
---------------------------
从扫描结果自动生成 Vuln Lab 场景。
将真实漏洞验证数据转化为教学场景。
"""

import logging
from typing import Dict, Any, List, Optional
from scanner.engine.llm_provider import LLMProvider

logger = logging.getLogger(__name__)

VULN_TYPE_MAP = {
    'SQL Injection': 'SQLI',
    'ThinkPHP SQL Injection': 'SQLI',
    'Django SQL Injection': 'SQLI',
    'Flask SQL Injection': 'SQLI',
    'Laravel SQL Injection': 'SQLI',
    'XSS': 'XSS_REFLECTED',
    'Reflected XSS': 'XSS_REFLECTED',
    'Stored XSS': 'XSS_STORED',
    'Command Injection': 'CMD_INJECTION',
    'Local File Inclusion': 'LFI',
    'Remote File Inclusion': 'RFI',
    'SSRF': 'SSRF',
    'XXE': 'XXE',
    'Path Traversal': 'PATH_TRAVERSAL',
    'Information Disclosure': 'INFO_DISCLOSURE',
    'Open Redirect': 'OPEN_REDIRECT',
    'CSRF': 'CSRF',
}

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


class LabScenarioGenerator:
    """从扫描结果自动生成 Vuln Lab 场景。"""

    def __init__(self, llm_provider: Optional[LLMProvider] = None):
        self.llm = llm_provider or LLMProvider()

    def generate_from_vuln_sync(self, vuln_data: Dict[str, Any], scan_task_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """同步版本：从单个漏洞数据生成场景，适用于 Celery worker。"""
        llm_result = self.llm.summarize_vuln_to_scenario_sync(vuln_data)
        if not llm_result:
            logger.warning("LLM 场景总结返回空，使用回退方案")
            llm_result = self._fallback_scenario(vuln_data)

        vuln_type = self._map_vuln_type(vuln_data)
        difficulty = self._determine_difficulty(vuln_data, llm_result)

        scenario = {
            "name": llm_result.get("scenario_name", f"{vuln_type} 场景"),
            "vuln_type": vuln_type,
            "difficulty": difficulty,
            "description": llm_result.get("description", ""),
            "attack_steps": llm_result.get("attack_steps", []),
            "remediation": llm_result.get("remediation", []),
            "learning": llm_result.get("learning", {}),
            "tags": llm_result.get("tags", []) + ["auto-generated"],
            "is_active": False,
            "is_auto_generated": True,
            "source_scan_task_id": scan_task_id,
        }

        return scenario

    async def generate_from_vuln(self, vuln_data: Dict[str, Any], scan_task_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """异步版本：从单个漏洞数据生成场景，适用于 FastAPI 等异步环境。"""
        return self.generate_from_vuln_sync(vuln_data, scan_task_id)

    def _map_vuln_type(self, vuln_data: Dict[str, Any]) -> str:
        """映射漏洞类型到 Lab VULN_TYPES。"""
        raw_type = vuln_data.get("vuln_type", "")
        if not raw_type:
            raw_type = vuln_data.get("validation_log", {}).get("vuln_type", "")

        for key, mapped in VULN_TYPE_MAP.items():
            if key.lower() in raw_type.lower():
                return mapped

        return "INFO_DISCLOSURE"

    def _determine_difficulty(self, vuln_data: Dict[str, Any], llm_result: Dict[str, Any]) -> str:
        """根据漏洞复杂度判定难度。"""
        llm_difficulty = llm_result.get("difficulty", "")
        if llm_difficulty in ("easy", "medium", "hard"):
            return llm_difficulty

        attack_steps_count = len(vuln_data.get("attack_path", {}).get("steps", []))
        if attack_steps_count >= 3:
            return "hard"
        elif attack_steps_count >= 2:
            return "medium"

        severity = vuln_data.get("validation_log", {}).get("severity", "medium")
        if severity in ("critical", "high"):
            return "hard"
        elif severity == "medium":
            return "medium"

        return "easy"

    def _fallback_scenario(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """LLM 失败时的回退场景。"""
        vuln_type = self._map_vuln_type(vuln_data)
        url = vuln_data.get("url", "N/A")
        payload = vuln_data.get("payload", "N/A")
        llm_analysis = vuln_data.get("llm_analysis", "无分析")
        attack_path = vuln_data.get("attack_path", {})
        steps_raw = attack_path.get("steps", [])

        attack_steps = []
        for i, step in enumerate(steps_raw[:3], 1):
            attack_steps.append({
                "step": i,
                "title": step.get("stage_title", f"步骤 {i}"),
                "description": step.get("description", ""),
                "request": {
                    "method": step.get("method", "GET"),
                    "url": step.get("url", ""),
                },
                "payload": payload,
                "payload_explanation": "利用漏洞特性构造的测试 Payload",
                "result": "成功触发漏洞特征" if step.get("success") else "尝试触发",
            })

        if not attack_steps:
            attack_steps.append({
                "step": 1,
                "title": "漏洞探测",
                "description": "向目标发送测试 Payload",
                "request": {"method": "GET", "url": url},
                "payload": payload,
                "payload_explanation": "利用漏洞特性构造的测试 Payload",
                "result": "成功触发漏洞特征",
            })

        return {
            "scenario_name": f"{vuln_type} 验证场景",
            "description": f"通过模拟攻击验证 {vuln_type} 漏洞。{llm_analysis}",
            "difficulty": self._determine_difficulty(vuln_data, {}),
            "attack_steps": attack_steps,
            "remediation": [
                {
                    "title": "参数化查询与输入验证",
                    "description": "使用参数化查询，避免直接拼接用户输入。对所有输入进行严格的类型和格式验证。",
                    "code": "# 示例：使用参数化查询\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
                    "language": "python",
                }
            ],
            "learning": {
                "principle": "该漏洞允许攻击者通过构造特殊输入来执行非预期操作。",
                "cwe": "CWE-89",
                "owasp": "A03:2021 Injection",
                "impact": "可能导致数据泄露、数据篡改或服务中断。",
                "references": ["https://owasp.org/Top10/"],
            },
            "tags": ["auto-generated", "fallback"],
        }
