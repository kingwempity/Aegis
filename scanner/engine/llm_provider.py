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
            # 注意：某些版本的 Ollama 可能不支持 response_format={"type": "json_object"}
            # 如果报错，请尝试移除该参数并在 Prompt 中强调输出 JSON
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": "You are a cybersecurity expert. Always output JSON."},
                          {"role": "user", "content": prompt}]
            )
            content = response.choices[0].message.content
            # 尝试从返回内容中提取 JSON（防止模型返回多余文字）
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            
            return json.loads(content)
        except Exception as e:
            logger.error(f"LLM 决策失败: {e}")
            return {"action": "continue", "reason": f"LLM 错误: {str(e)}", "confidence": 0.0}

    async def verify_vulnerability(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        结果复核：判定漏洞证据是否真实有效。
        """
        if not self.client:
            return {"is_valid": True, "confidence": 0.5, "analysis": "LLM 未就绪，默认通过"}

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
                messages=[{"role": "system", "content": "You are a security auditor. Always output JSON."},
                          {"role": "user", "content": prompt}]
            )
            content = response.choices[0].message.content
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            
            return json.loads(content)
        except Exception as e:
            logger.error(f"LLM 复核失败: {e}")
            return {"is_valid": True, "confidence": 0.5, "analysis": f"LLM 错误: {str(e)}"}
