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
    LLM 服务提供者，支持 OpenAI、SiliconFlow、DeepSeek 和本地 Ollama。
    默认使用 SiliconFlow 的 DeepSeek-R1-Distill-Qwen-7B 模型。
    """
    DEFAULT_BASE_URL = "https://api.siliconflow.cn/v1"
    DEFAULT_MODEL = "deepseek-ai/DeepSeek-R1-Distill-Qwen-7B"

    def __init__(self, model: str = None, base_url: str = None, api_key: str = None):
        if not OPENAI_AVAILABLE:
            logger.error("❌ 未安装 'openai' Python 包。请在运行环境执行: pip install openai")
            self.client = None
            return

        raw_base_url = base_url or os.getenv("LLM_BASE_URL", self.DEFAULT_BASE_URL)
        self.base_url = self._sanitize_base_url(raw_base_url)
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", self.DEFAULT_MODEL)

        if not self.api_key:
            logger.warning("⚠️ 未设置 API Key，请通过环境变量 LLM_API_KEY 或参数 api_key 传入")
            self.client = None
            return

        logger.info(f"🤖 初始化 LLMProvider: BaseURL={self.base_url}, Model={self.model}")

        try:
            self.client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key
            )
        except Exception as e:
            logger.error(f"❌ 初始化 OpenAI 客户端失败: {e}")
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

        prompt = f"""You are a penetration testing expert. Analyze and decide the next action.

Target: {context.get('target')}
Technologies: {context.get('technologies')}
Phase: {context.get('current_phase')}
History: {json.dumps(context.get('history', []), ensure_ascii=False)}
Last Status: {context.get('last_status')}
Last Response: {context.get('last_response_snippet')}

CRITICAL: You MUST output ONLY valid JSON. No thinking process. No explanation.
Required JSON format:
{{"action":"continue","reason":"brief reason","payload_mutation":"test","next_target_path":"/admin","confidence":0.8}}

Rules:
- action: exactly ONE of: continue, retry, change_vector, terminate
- next_target_path: a URL path starting with / or ? (e.g., /admin, /?id=1, /api/user)
- payload_mutation: a simple test string
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
                max_tokens=500
            )

            raw_content = response.choices[0].message.content
            logger.debug(f"📝 LLM 原始响应: {raw_content[:200]}...")

            if not raw_content or not raw_content.strip():
                logger.error("❌ LLM 返回空响应")
                return {"action": "continue", "reason": "LLM 返回空响应", "confidence": 0.0}

            content = self._clean_json_content(raw_content)

            try:
                result = json.loads(content)
            except json.JSONDecodeError as json_err:
                logger.error(f"❌ JSON 解析失败：{json_err}")
                logger.error(f"   清理后的内容：{content[:300]}")
                
                result = self._extract_json_from_natural_language(raw_content)
                if result:
                    logger.info("✅ 从自然语言中提取到 JSON")
                else:
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
                ]
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
