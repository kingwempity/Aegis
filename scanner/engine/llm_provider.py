import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

# 自动加载 .env 文件
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / ".env"
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    pass

# 使用 try-except 保护，防止环境缺少 openai 包导致 Worker 崩溃
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
        """
        初始化 LLM 提供者。
        
        Args:
            model: 模型名称，默认 deepseek-ai/DeepSeek-R1-Distill-Qwen-7B
            base_url: API 基础地址，默认 SiliconFlow API
            api_key: API 密钥，需从环境变量 LLM_API_KEY 获取或直接传入
        """
        if not OPENAI_AVAILABLE:
            logger.error("❌ 未安装 'openai' Python 包。请在运行环境执行: pip install openai")
            self.client = None
            return

        self.base_url = base_url or os.getenv("LLM_BASE_URL", self.DEFAULT_BASE_URL)
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.model = model or os.getenv("LLM_MODEL", self.DEFAULT_MODEL)

        if not self.api_key:
            logger.warning("⚠️ 未设置 API Key，请通过环境变量 LLM_API_KEY 或参数 api_key 传入")
            self.client = None
            return

        logger.info(f" 初始化 LLMProvider: BaseURL={self.base_url}, Model={self.model}")
        
        try:
            self.client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key
            )
        except Exception as e:
            logger.error(f"❌ 初始化 OpenAI 客户端失败: {e}")
            self.client = None

    async def decide_next_step(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        全时决策：基于当前攻击上下文决定下一步行动。
        """
        if not self.client:
            return {"action": "continue", "reason": "LLM 客户端未就绪", "confidence": 0.0}

        prompt = f"""You are a penetration testing expert. Analyze the attack context and decide the next action.

Target: {context.get('target')}
Technologies: {context.get('technologies')}
Phase: {context.get('current_phase')}
History: {json.dumps(context.get('history', []), ensure_ascii=False)}
Last Status: {context.get('last_status')}
Last Response: {context.get('last_response_snippet')}

Output ONLY valid JSON (no markdown, no extra text):
{{
    "action": "continue",
    "reason": "brief reason in Chinese",
    "payload_mutation": "specific payload string",
    "next_target_path": "specific path like /admin or /api/test",
    "confidence": 0.8
}}

Rules:
- action must be ONE of: continue, retry, change_vector, terminate
- next_target_path must be a valid URL path (e.g., /admin, /api/user, /?id=1)
- payload_mutation must be a simple string, not a description
- Output ONLY the JSON object, nothing else"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": "You are a cybersecurity expert. Output ONLY valid JSON, no markdown code blocks."},
                          {"role": "user", "content": prompt}]
            )
            content = response.choices[0].message.content.strip()
            
            # 清理 markdown 代码块
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            # 移除控制字符
            content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
            
            result = json.loads(content)
            
            # 验证并规范化 action
            valid_actions = ["continue", "retry", "change_vector", "terminate"]
            action = result.get("action", "continue")
            if "/" in str(action):
                action = str(action).split("/")[0]
            if action not in valid_actions:
                action = "continue"
            result["action"] = action
            
            # 确保 next_target_path 是有效路径
            path = result.get("next_target_path", "")
            if not path or not isinstance(path, str):
                result["next_target_path"] = ""
            else:
                # 移除中文描述，只保留路径部分
                if "/" not in path[:10]:
                    result["next_target_path"] = ""
            
            return result
        except Exception as e:
            logger.error(f"LLM 决策失败: {e}")
            return {"action": "continue", "reason": f"LLM 错误: {str(e)}", "confidence": 0.0}

    async def verify_vulnerability(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        结果复核：判定漏洞证据是否真实有效。
        """
        if not self.client:
            return {"is_valid": True, "confidence": 0.5, "analysis": "LLM 未就绪，默认通过"}

        prompt = f"""You are a security auditor. Verify if this vulnerability evidence is real or false positive.

Vulnerability Type: {evidence.get('vuln_name')}
URL: {evidence.get('url')}
Payload: {evidence.get('payload')}
Status Code: {evidence.get('status_code')}
Response: {evidence.get('response_body')}

Output ONLY valid JSON (no markdown, no extra text):
{{
    "is_valid": true,
    "confidence": 0.8,
    "analysis": "brief analysis in Chinese"
}}

Rules:
- is_valid must be true or false (boolean)
- confidence must be between 0.0 and 1.0
- Output ONLY the JSON object, nothing else"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": "You are a security auditor. Output ONLY valid JSON, no markdown code blocks."},
                          {"role": "user", "content": prompt}]
            )
            content = response.choices[0].message.content.strip()
            
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            content = ''.join(char for char in content if ord(char) >= 32 or char in '\n\r\t')
            
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
