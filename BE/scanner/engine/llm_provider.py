import os
import json
import logging
import re
from typing import Dict, Any, List, Optional
from pathlib import Path

try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

logger = logging.getLogger(__name__)


class LLMProvider:
    """
    LLM 服务提供者，支持 OpenAI、SiliconFlow、DeepSeek、NVIDIA 和本地 Ollama。
    默认使用 SiliconFlow 的 deepseek-ai/DeepSeek-R1-0528-Qwen3-8B 模型。
    """
    DEFAULT_BASE_URL = "https://api.siliconflow.cn/v1"
    DEFAULT_MODEL = "deepseek-ai/DeepSeek-R1-0528-Qwen3-8B"

    def __init__(self, model: str = None, base_url: str = None, api_key: str = None):
        if not OPENAI_AVAILABLE:
            logger.error(" 未安装 'openai' Python 包。请在运行环境执行: pip install openai")
            self.client = None
            return

        raw_base_url = base_url or os.getenv("LLM_BASE_URL", self.DEFAULT_BASE_URL)
        self.base_url = self._sanitize_base_url(raw_base_url)
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", self.DEFAULT_MODEL)

        if not self.api_key:
            logger.warning(" 未设置 API Key，请通过环境变量 LLM_API_KEY 或参数 api_key 传入")
            self.client = None
            return

        logger.info(f" 初始化 LLMProvider: BaseURL={self.base_url}, Model={self.model}")

        try:
            self.client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key
            )
        except Exception as e:
            logger.error(f" 初始化 OpenAI 客户端失败: {e}")
            self.client = None

    def _sanitize_base_url(self, url: str) -> str:
        """清理和验证BaseURL，去除末尾多余字符"""
        if not url:
            return self.DEFAULT_BASE_URL

        url = url.strip()

        url = url.rstrip(',; \t\n\r')

        if not url.endswith('/'):
            url += '/'

        return url

    def _clean_json_content(self, content: str) -> str:
        content = content.strip()
        if "```json" in content:
            content = content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            parts = content.split("```")
            if len(parts) >= 2:
                content = parts[1].strip()
        content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
        return content

    def _extract_valid_action(self, action_value: Any) -> str:
        valid_actions = ["continue", "retry", "change_vector", "terminate"]
        action_str = str(action_value).lower().strip()
        for valid in valid_actions:
            if valid in action_str:
                return valid
        return "continue"

    def _extract_valid_path(self, path_value: Any) -> str:
        if not path_value:
            return ""
        path_str = str(path_value).strip()
        if re.match(r'^[/\?]', path_str):
            return path_str.split()[0].split('?')[0] if ' ' in path_str else path_str
        match = re.search(r'([/\?][a-zA-Z0-9_\-./?=&%]*)', path_str)
        if match:
            return match.group(1)
        return ""

    async def decide_next_step(self, context: Dict[str, Any]) -> Dict[str, Any]:
        if not self.client:
            return {"action": "continue", "reason": "LLM 客户端未就绪", "confidence": 0.0}

        # 根据侦察阶段探测到的实际信息动态生成路径建议
        tech = [t.lower() for t in context.get('technologies', [])]
        frameworks = context.get('detected_frameworks', [])
        entry_points = context.get('entry_points', [])  # 侦察阶段发现的入口点
        tech_versions = context.get('tech_versions', {})  # 技术版本信息
        
        # 基于实际探测结果生成路径建议
        path_suggestions = []
        
        # 优先使用侦察阶段发现的入口点
        if entry_points:
            path_suggestions.extend(entry_points[:5])
        
        # 根据实际探测到的技术栈补充路径
        if 'php' in tech:
            path_suggestions.append("/index.php")
        if 'thinkphp' in [f.lower() for f in frameworks] or any('thinkphp' in t.lower() for t in tech):
            tp_version = tech_versions.get('thinkphp', 'unknown')
            path_suggestions.extend([
                "/index.php?s=/index/index/index",
                "/index.php?ids[]=",
                "/index.php?where[id]=",
                "/index.php?order[id]=",
            ])
        elif 'drupal' in [f.lower() for f in frameworks] or any('drupal' in t.lower() for t in tech):
            path_suggestions.extend(["/user/register", "/node/", "/?q="])
        elif 'django' in [f.lower() for f in frameworks] or any('django' in t.lower() for t in tech):
            path_suggestions.extend(["/admin/login/", "/api/", "/accounts/login/"])
        elif 'wordpress' in [f.lower() for f in frameworks] or any('wordpress' in t.lower() for t in tech):
            path_suggestions.extend(["/wp-login.php", "/xmlrpc.php", "/wp-json/"])
        elif 'laravel' in [f.lower() for f in frameworks] or any('laravel' in t.lower() for t in tech):
            path_suggestions.extend(["/login", "/api/v1/", "/debug/"])
        
        # 去重并过滤空值
        path_suggestions = list(dict.fromkeys(p for p in path_suggestions if p))
        
        # 记录失败的路径,避免重复
        failed_paths = []
        for h in context.get('history', []):
            status = h.get('status') or h.get('status_code')
            if status in [404, 403, 500]:
                # 从 URL 中提取路径
                url = h.get('url', '')
                if url:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    path = parsed.path + ('?' + parsed.query if parsed.query else '')
                    failed_paths.append(path)
        
        # 构建动态 Prompt
        prompt = f"""You are a penetration testing expert. Analyze the target and decide the next action.

RECONNAISSANCE RESULTS:
- Target: {context.get('target')}
- Technologies: {', '.join(context.get('technologies', ['Unknown']))}
- Frameworks: {', '.join(frameworks) if frameworks else 'Not detected'}
- Versions: {tech_versions if tech_versions else 'Unknown'}

DYNAMIC PATH SUGGESTIONS (based on actual recon results):
{', '.join(path_suggestions) if path_suggestions else 'No specific suggestions available. Try common paths for the detected technology.'}

PREVIOUSLY FAILED PATHS (AVOID REPEATING):
{', '.join(failed_paths) if failed_paths else 'None yet'}

RECENT HISTORY (last 5 actions):
{json.dumps(context.get('history', [])[-5:], ensure_ascii=False)}

CRITICAL: You MUST output ONLY valid JSON. No thinking process. No explanation.
Required JSON format:
{{"action":"continue","reason":"brief reason","payload_mutation":"0,updatexml(0,concat(0xa,user()),0)","next_target_path":"/index.php?s=/index/index/index&ids[0]=1","confidence":0.8}}

DECISION RULES:
- action: exactly ONE of: continue, retry, change_vector, terminate
- next_target_path: MUST use paths from "DYNAMIC PATH SUGGESTIONS" or framework-specific paths based on recon results
- payload_mutation: use technology-specific payloads (e.g., SQL injection for PHP/ThinkPHP)
- NEVER repeat paths that returned 404/403
- DO NOT use generic paths like /admin unless recon confirms the framework uses it
- confidence: 0.0 to 1.0
- Output ONLY the JSON object, nothing else"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a JSON generator. Output ONLY valid JSON. No thinking. No explanation. No markdown. Just the JSON object."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=500,
                extra_body={"chat_template_kwargs": {"thinking": False}}
            )

            raw_content = response.choices[0].message.content
            logger.debug(f" LLM 原始响应: {raw_content[:200]}...")

            if not raw_content or not raw_content.strip():
                logger.error(" LLM 返回空响应")
                return {"action": "continue", "reason": "LLM 返回空响应", "confidence": 0.0}

            content = self._clean_json_content(raw_content)

            try:
                result = json.loads(content)
                logger.debug(f" JSON 解析成功：{result}")
            except json.JSONDecodeError as json_err:
                logger.error(f" JSON 解析失败：{json_err}")
                logger.error(f"   清理后的内容：{content[:300]}")
                
                logger.info(" 尝试从自然语言中提取 JSON...")
                result = self._extract_json_from_natural_language(raw_content)
                
                if result:
                    logger.info(f" 从自然语言中提取到 JSON: action={result['action']}, path={result['next_target_path']}")
                else:
                    logger.error(" 自然语言提取也失败了")
                    return {"action": "continue", "reason": f"JSON 解析错误：{str(json_err)}", "confidence": 0.0}

            result["action"] = self._extract_valid_action(result.get("action", "continue"))
            result["next_target_path"] = self._extract_valid_path(result.get("next_target_path", ""))

            if "reason" not in result:
                result["reason"] = "LLM 未提供原因"
            if "payload_mutation" not in result:
                result["payload_mutation"] = "test"
            if "confidence" not in result:
                result["confidence"] = 0.5

            return result
        except Exception as e:
            logger.error(f"LLM 决策失败：{e}")
            import traceback
            logger.debug(f"详细错误信息:\n{traceback.format_exc()}")
            return {"action": "continue", "reason": f"LLM 错误：{str(e)}", "confidence": 0.0}

    def _extract_json_from_natural_language(self, text: str) -> Optional[Dict[str, Any]]:
        """
        当 LLM 返回自然语言而非 JSON 时，尝试从中提取关键信息构建 JSON
        """
        text_lower = text.lower()
        
        result = {
            "action": "continue",
            "reason": "",
            "payload_mutation": "test",
            "next_target_path": "",
            "confidence": 0.5
        }
        
        action_keywords = {
            "continue": ["continue", "keep going", "proceed", "next", "move on"],
            "retry": ["retry", "try again", "attempt again", "retest"],
            "change_vector": ["change", "switch", "different", "alternative", "new vector"],
            "terminate": ["terminate", "stop", "finish", "done", "complete"]
        }
        
        for action, keywords in action_keywords.items():
            if any(kw in text_lower for kw in keywords):
                result["action"] = action
                break
        
        path_patterns = [
            r'(?:path|url|target|endpoint|route)[s]?\s*(?:is|:|=|to)\s*[/\?][a-zA-Z0-9_\-./?=&%]+',
            r'/(?:admin|api|user|login|upload|config|debug|test|manager|console)',
            r'\?[a-zA-Z0-9_\-./?=&%]+',
        ]
        
        for pattern in path_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                result["next_target_path"] = match.group(0).strip()
                break
        
        reason_match = re.search(r'(?:reason|because|therefore|so)[s]?\s*(?:is|:|=)?\s*([^.\n]+)', text, re.IGNORECASE)
        if reason_match:
            result["reason"] = reason_match.group(1).strip()[:200]
        
        if not result["reason"]:
            result["reason"] = text[:100].strip()
        
        return result

    def summarize_vuln_to_scenario_sync(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        同步版本：将漏洞验证结果总结为 Vuln Lab 教学场景。
        适用于 Celery worker 等同步环境。
        """
        if not self.client:
            logger.warning("LLM 客户端未就绪，无法生成场景总结")
            return None

        vuln_type = vuln_data.get("vuln_type", vuln_data.get("validation_log", {}).get("vuln_type", "Unknown"))
        url = vuln_data.get("url", "N/A")
        payload = vuln_data.get("payload", "N/A")
        llm_analysis = vuln_data.get("llm_analysis", "无分析")
        attack_path = vuln_data.get("attack_path", {})
        attack_steps_raw = attack_path.get("steps", [])
        evidence = vuln_data.get("evidence", {})
        response_snippet = evidence.get("response_body_snippet", "")[:500]
        
        attack_steps_json = json.dumps(attack_steps_raw[:5], ensure_ascii=False, indent=2)

        prompt = f"""You are a cybersecurity education expert. Convert this real vulnerability validation result into an educational lab scenario for teaching purposes.

VULNERABILITY INFORMATION:
- Type: {vuln_type}
- Target URL: {url}
- Payload Used: {payload}
- LLM Analysis: {llm_analysis}
- Response Evidence: {response_snippet}

ATTACK STEPS (from validation):
{attack_steps_json}

Output ONLY valid JSON matching this exact structure:
{{
  "scenario_name": "Brief, descriptive name for the lab scenario",
  "description": "Clear description of the vulnerability and its context",
  "difficulty": "easy" or "medium" or "hard",
  "attack_steps": [
    {{
      "step": 1,
      "title": "Step title",
      "description": "What this step does",
      "request": {{"method": "GET", "url": "..."}},
      "payload": "The actual payload used",
      "payload_explanation": "Why this payload works",
      "response": {{"status_code": 200, "body_snippet": "..."}},
      "result": "What happened"
    }}
  ],
  "remediation": [
    {{
      "title": "Remediation title",
      "description": "How to fix this",
      "code": "Code example showing the fix",
      "language": "php" or "python" or "javascript" etc.
    }}
  ],
  "learning": {{
    "principle": "How this vulnerability works",
    "cwe": "CWE ID like CWE-89",
    "owasp": "OWASP category like A03:2021 Injection",
    "impact": "Security impact description",
    "references": ["https://example.com"]
  }},
  "tags": ["tag1", "tag2"]
}}

RULES:
- Keep attack_steps concise (3-5 steps max)
- Include real payload examples from the validation data
- Remediation MUST include code examples
- Learning section should be educational and thorough
- Difficulty based on exploitation complexity
- Output ONLY the JSON object, no markdown, no explanation"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a JSON generator. Output ONLY valid JSON. No markdown. No explanation. Just the JSON object."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=3000,
                extra_body={"chat_template_kwargs": {"thinking": False}}
            )
            
            raw_content = response.choices[0].message.content
            content = self._clean_json_content(raw_content)
            result = json.loads(content)
            
            required_fields = ["scenario_name", "description", "difficulty", "attack_steps", "remediation", "learning"]
            missing = [f for f in required_fields if f not in result]
            if missing:
                logger.warning(f"LLM 场景总结缺少字段: {missing}")
                for field in missing:
                    if field == "difficulty":
                        result[field] = "medium"
                    elif field in ("attack_steps", "remediation"):
                        result[field] = []
                    elif field == "learning":
                        result[field] = {}
                    else:
                        result[field] = "未提供"
            
            if result.get("difficulty") not in ("easy", "medium", "hard"):
                result["difficulty"] = "medium"
            
            logger.info(f"LLM 场景总结生成成功: {result.get('scenario_name')}")
            return result
            
        except Exception as e:
            logger.error(f"LLM 场景总结失败: {e}")
            return None

    async def summarize_vuln_to_scenario(self, vuln_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """异步版本：将漏洞验证结果总结为 Vuln Lab 教学场景。"""
        return self.summarize_vuln_to_scenario_sync(vuln_data)

    async def verify_vulnerability(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        if not self.client:
            return {"is_valid": True, "confidence": 0.5, "analysis": "LLM 未就绪，默认通过"}

        prompt = f"""You are a security auditor. Verify this vulnerability evidence.

Type: {evidence.get('vuln_name')}
URL: {evidence.get('url')}
Payload: {evidence.get('payload')}
Status: {evidence.get('status_code')}
Response: {evidence.get('response_body')}

Output ONLY a single line of valid JSON:
{{"is_valid":true,"confidence":0.8,"analysis":"brief analysis"}}

Rules:
- is_valid: true or false (boolean)
- confidence: 0.0 to 1.0
- Output ONLY the JSON, nothing else"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "Output ONLY valid JSON on a single line. No markdown."},
                    {"role": "user", "content": prompt}
                ],
                extra_body={"chat_template_kwargs": {"thinking": False}}
            )
            content = self._clean_json_content(response.choices[0].message.content)
            result = json.loads(content)

            if "is_valid" not in result:
                result["is_valid"] = True
            if "confidence" not in result:
                result["confidence"] = 0.5
            if "analysis" not in result:
                result["analysis"] = "LLM 未提供分析"

            return result
        except Exception as e:
            logger.error(f"LLM 复核失败: {e}")
            return {"is_valid": True, "confidence": 0.5, "analysis": f"LLM 错误: {str(e)}"}
