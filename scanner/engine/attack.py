"""
scanner.engine.attack
---------------------
模拟攻击引擎核心模块：
1) 攻击脚本生成 (AttackScriptGenerator) - 智能payload生成与编码
2) 攻击路径探索 (AttackPathExplorer) - 多维度路径优先级算法
3) 攻击路径搜索算法 (AttackPathSearchAlgorithm) - 基于A*的启发式最优路径搜索
4) Payload编码器 (PayloadEncoder) - 多种编码方式支持
5) 上下文感知引擎 (ContextAwareEngine) - 基于响应动态调整策略

保持无害化扫描：仅生成验证型 payload，不执行破坏性命令。

算法核心思想：
    攻击路径探索算法采用启发式搜索策略（类似A*），通过综合评价函数
    f(n) = g(n) + h(n) 引导搜索方向，优先探索更有可能形成最优攻击路径的节点。
    
    算法流程：
    1. 状态初始化 - 构建优先队列，初始化代价参数
    2. 循环搜索与节点扩展 - 取出最优节点，判断是否到达目标
    3. 启发式扩展与代价计算 - 计算g(n)、h(n)、f(n)，更新节点状态
    4. 路径回溯与最优路径输出 - 从目标节点反向回溯至起始节点

"""

from __future__ import annotations

import base64
import hashlib
import heapq
import math
import random
import re
import string
import time
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Set, Tuple, Generic, TypeVar
from collections import defaultdict
import logging
import json

# 配置日志
logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Payload类型枚举"""
    GENERIC = "generic"
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    CMD_INJECTION = "cmd_injection"
    OPEN_REDIRECT = "open_redirect"


class EncodingType(Enum):
    """编码类型枚举"""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    JSON = "json"


@dataclass
class PathCandidate:
    """
    路径候选实体。
    
    Attributes:
        url: 完整URL
        method: HTTP方法
        score: 优先级得分
        source_plugin: 来源插件ID
        depth: 路径深度
        dependencies: 依赖的路径列表
        context_hints: 上下文提示（如参数名、表单字段等）
        success_rate: 历史成功率
        last_visited: 最后访问时间戳
    """
    url: str
    method: str
    score: float
    source_plugin: str
    depth: int = 0
    dependencies: List[str] = field(default_factory=list)
    context_hints: Dict[str, Any] = field(default_factory=dict)
    success_rate: float = 0.5
    last_visited: Optional[float] = None
    
    def __hash__(self):
        return hash((self.url, self.method))


@dataclass
class PayloadVariant:
    """
    Payload变体实体。
    
    Attributes:
        original: 原始payload
        encoded: 编码后的payload
        encoding_type: 编码类型
        context_score: 上下文相关性得分
        mutation_type: 变异类型
    """
    original: str
    encoded: str
    encoding_type: EncodingType
    context_score: float = 0.0
    mutation_type: str = "original"


@dataclass
class AttackContext:
    """
    攻击上下文信息。
    
    Attributes:
        target_url: 目标URL
        response_status: 响应状态码
        response_headers: 响应头
        response_body: 响应体片段
        detected_tech: 检测到的技术栈
        input_fields: 发现的输入字段
        cookies: Cookie信息
        csrf_token: CSRF令牌
    """
    target_url: str
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    detected_tech: List[str] = field(default_factory=list)
    input_fields: List[Dict[str, str]] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_token: Optional[str] = None


class PayloadEncoder:
    """
    Payload编码器。
    
    提供多种编码方式，支持链式编码和自定义编码规则。
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL编码"""
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """双重URL编码"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64编码"""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """十六进制编码"""
        return payload.encode().hex()
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode编码"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML实体编码"""
        return ''.join(f'&#x{ord(c):x};' if ord(c) > 127 else c for c in payload)
    
    @staticmethod
    def json_encode(payload: str) -> str:
        """JSON编码"""
        return json.dumps(payload)
    
    @classmethod
    def encode(cls, payload: str, encoding_type: EncodingType) -> str:
        """
        根据编码类型对payload进行编码。
        
        Args:
            payload: 原始payload
            encoding_type: 编码类型
            
        Returns:
            编码后的payload
        """
        encoders: Dict[EncodingType, Callable[[str], str]] = {
            EncodingType.NONE: lambda x: x,
            EncodingType.URL: cls.url_encode,
            EncodingType.DOUBLE_URL: cls.double_url_encode,
            EncodingType.BASE64: cls.base64_encode,
            EncodingType.HEX: cls.hex_encode,
            EncodingType.UNICODE: cls.unicode_encode,
            EncodingType.HTML_ENTITY: cls.html_entity_encode,
            EncodingType.JSON: cls.json_encode,
        }
        return encoders.get(encoding_type, lambda x: x)(payload)
    
    @classmethod
    def chain_encode(cls, payload: str, encoding_chain: List[EncodingType]) -> str:
        """
        链式编码：按顺序应用多种编码。
        
        Args:
            payload: 原始payload
            encoding_chain: 编码类型列表
            
        Returns:
            编码后的payload
            
        Example:
            >>> cls.chain_encode("test", [EncodingType.URL, EncodingType.BASE64])
        """
        result = payload
        for encoding_type in encoding_chain:
            result = cls.encode(result, encoding_type)
        return result


class PayloadMutator:
    """
    Payload变异器。
    
    根据规则生成payload变体，包括大小写变换、注释插入、字符替换等。
    """
    
    # SQL注释模式
    SQL_COMMENT_PATTERNS = [
        (" ", " /**/ "),
        (" ", " /*!*/ "),
        (" ", " -- "),
        ("'", "\""),
        ("'", "`"),
        ("OR", "||"),
        ("AND", "&&"),
    ]
    
    # XSS变异模式
    XSS_MUTATION_PATTERNS = [
        ("<script>", "<ScRiPt>"),
        ("<script>", "<script/xss>"),
        ("<script>", "<script \n>"),
        ("alert", "prompt"),
        ("alert", "confirm"),
        ("onerror", "onError"),
        ("onerror", "ONERROR"),
    ]
    
    # 路径穿越变异
    PATH_TRAVERSAL_PATTERNS = [
        ("../", "..%2f"),
        ("../", "..%252f"),
        ("../", "..\\"),
        ("../", "..%5c"),
        ("../", "....//"),
    ]
    
    @classmethod
    def mutate_sqli(cls, payload: str) -> List[str]:
        """
        生成SQL注入payload变体。
        
        Args:
            payload: 原始SQL注入payload
            
        Returns:
            变体列表
        """
        variants = [payload]
        
        # 大小写变换
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append(''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
        
        # 注释插入
        for orig, replacement in cls.SQL_COMMENT_PATTERNS:
            if orig in payload:
                variants.append(payload.replace(orig, replacement))
        
        # 添加SQL注释后缀
        variants.extend([
            f"{payload}--",
            f"{payload}#",
            f"{payload}/*",
        ])
        
        return list(set(variants))
    
    @classmethod
    def mutate_xss(cls, payload: str) -> List[str]:
        """
        生成XSS payload变体。
        
        Args:
            payload: 原始XSS payload
            
        Returns:
            变体列表
        """
        variants = [payload]
        
        # 大小写混合
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append(''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload))
        
        # 标签变换
        for orig, replacement in cls.XSS_MUTATION_PATTERNS:
            if orig.lower() in payload.lower():
                variants.append(re.sub(re.escape(orig), replacement, payload, flags=re.IGNORECASE))
        
        # HTML实体编码
        variants.append(PayloadEncoder.html_entity_encode(payload))
        
        # 添加Null字节
        if "<" in payload:
            variants.append(payload.replace("<", "<\x00"))
        
        return list(set(variants))
    
    @classmethod
    def mutate_path_traversal(cls, payload: str) -> List[str]:
        """
        生成路径穿越payload变体。
        
        Args:
            payload: 原始路径穿越payload
            
        Returns:
            变体列表
        """
        variants = [payload]
        
        for orig, replacement in cls.PATH_TRAVERSAL_PATTERNS:
            if orig in payload:
                variants.append(payload.replace(orig, replacement))
        
        # 添加额外路径层级
        variants.append(f"{'../' * 5}{payload.lstrip('../')}")
        variants.append(f"./{payload}")
        variants.append(f".../{payload}")
        
        return list(set(variants))
    
    @classmethod
    def generate_variants(cls, payload: str, payload_type: PayloadType) -> List[str]:
        """
        根据payload类型生成变体。
        
        Args:
            payload: 原始payload
            payload_type: payload类型
            
        Returns:
            变体列表
        """
        mutators: Dict[PayloadType, Callable[[str], List[str]]] = {
            PayloadType.SQLI: cls.mutate_sqli,
            PayloadType.XSS: cls.mutate_xss,
            PayloadType.PATH_TRAVERSAL: cls.mutate_path_traversal,
            PayloadType.LFI: cls.mutate_path_traversal,
        }
        
        mutator = mutators.get(payload_type, lambda x: [x])
        return mutator(payload)


class ContextAwareEngine:
    """
    上下文感知引擎。
    
    根据目标响应分析上下文，智能选择最适合的payload和编码方式。
    """
    
    # 技术栈特征映射
    TECH_SIGNATURES = {
        "php": ["php", ".php", "X-Powered-By: PHP"],
        "thinkphp": ["thinkphp", "ThinkPHP", "X-Powered-By: ThinkPHP", "think_session", "think_path"],
        "drupal": ["drupal", "Drupal", "X-Generator: Drupal", "sites/default/files", "Drupal.settings"],
        "asp": [".asp", ".aspx", "X-AspNet-Version"],
        "java": ["jsp", ".do", "JSESSIONID", "X-Powered-By: Servlet"],
        "python": ["wsgi", "python", "csrfmiddlewaretoken"],
        "ruby": ["ruby", "rails", "_rails_session"],
        "nodejs": ["node", "express", "connect.sid"],
        "mysql": ["mysql", "mysqli", "MySQL"],
        "postgresql": ["postgresql", "pg_", "PostgreSQL"],
        "mssql": ["mssql", "SQL Server", "sqlexpress"],
        "oracle": ["oracle", "ORA-", "Oracle"],
    }
    
    # 输入字段检测模式
    INPUT_PATTERNS = [
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>',
        r'<textarea[^>]+name=["\']([^"\']+)["\']',
        r'<select[^>]+name=["\']([^"\']+)["\']',
        r'name=["\']([^"\']+)["\']',
    ]
    
    @classmethod
    def detect_technologies(cls, response_body: str, response_headers: Dict[str, str]) -> List[str]:
        """
        检测目标使用的技术栈。
        
        Args:
            response_body: 响应体
            response_headers: 响应头
            
        Returns:
            检测到的技术列表
        """
        detected = []
        combined_text = response_body.lower() + " ".join(str(v) for v in response_headers.values()).lower()
        
        for tech, signatures in cls.TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined_text:
                    detected.append(tech)
                    break
        
        return detected
    
    @classmethod
    def extract_input_fields(cls, response_body: str) -> List[Dict[str, str]]:
        """
        从响应中提取输入字段。
        
        Args:
            response_body: 响应体
            
        Returns:
            输入字段列表，每个元素包含name、type等属性
        """
        fields = []
        
        for pattern in cls.INPUT_PATTERNS:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                field_name = match.group(1)
                # 提取字段类型
                field_type = "text"
                type_match = re.search(r'type=["\']([^"\']+)["\']', match.group(0), re.IGNORECASE)
                if type_match:
                    field_type = type_match.group(1)
                
                fields.append({
                    "name": field_name,
                    "type": field_type,
                    "raw": match.group(0),
                })
        
        return fields
    
    @classmethod
    def extract_csrf_token(cls, response_body: str) -> Optional[str]:
        """
        提取CSRF令牌。
        
        Args:
            response_body: 响应体
            
        Returns:
            CSRF令牌或None
        """
        # 常见CSRF令牌字段名
        csrf_patterns = [
            r'name=["\'](?:csrf[_-]?token|_csrf|csrfmiddlewaretoken|_token|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\'](?:csrf[_-]?token|_csrf|csrfmiddlewaretoken|_token|authenticity_token)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    @classmethod
    def build_context(cls, target_url: str, response_status: int, 
                     response_headers: Dict[str, str], response_body: str) -> AttackContext:
        """
        构建攻击上下文。
        
        Args:
            target_url: 目标URL
            response_status: 响应状态码
            response_headers: 响应头
            response_body: 响应体
            
        Returns:
            AttackContext实例
        """
        return AttackContext(
            target_url=target_url,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body[:10000],  # 限制大小
            detected_tech=cls.detect_technologies(response_body, response_headers),
            input_fields=cls.extract_input_fields(response_body),
            csrf_token=cls.extract_csrf_token(response_body),
        )
    
    @classmethod
    def suggest_encoding(cls, context: AttackContext, payload_type: PayloadType) -> List[EncodingType]:
        """
        根据上下文建议最佳编码方式。
        
        Args:
            context: 攻击上下文
            payload_type: payload类型
            
        Returns:
            推荐的编码类型列表，按优先级排序
        """
        suggestions = [EncodingType.NONE]
        
        # 根据检测到的技术栈调整编码策略
        if "php" in context.detected_tech or "thinkphp" in context.detected_tech:
            suggestions.append(EncodingType.URL)
            if payload_type == PayloadType.SQLI:
                suggestions.append(EncodingType.HEX)
        
        if "asp" in context.detected_tech:
            suggestions.append(EncodingType.URL)
            if payload_type == PayloadType.SQLI:
                suggestions.append(EncodingType.BASE64)
        
        if "java" in context.detected_tech:
            suggestions.append(EncodingType.UNICODE)
        
        # 根据响应状态调整
        if context.response_status == 403:
            # 可能存在WAF，尝试多重编码
            suggestions.append(EncodingType.DOUBLE_URL)
            suggestions.append(EncodingType.BASE64)
        
        return list(set(suggestions))


class AttackScriptGenerator:
    """
    智能攻击脚本生成器。
    
    根据模板、上下文和策略生成最终的攻击请求脚本。
    支持动态payload生成、多种编码、上下文感知等功能。
    """
    
    # 默认安全payload库
    DEFAULT_SAFE_PAYLOADS: Dict[PayloadType, List[str]] = {
        PayloadType.GENERIC: ["aegis_probe"],
        PayloadType.SQLI: [
            "' OR '1'='1",
            "1' AND '1'='1",
            "' UNION SELECT NULL--",
            "1' ORDER BY 1--",
            "admin'--",
        ],
        PayloadType.XSS: [
            "<svg onload=alert(1)>",
            "\"'><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
        ],
        PayloadType.PATH_TRAVERSAL: [
            "../etc/passwd",
            "..%2f..%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "/etc/passwd",
            "..\\..\\windows\\win.ini",
        ],
        PayloadType.LFI: [
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "file:///etc/passwd",
        ],
        PayloadType.SSRF: [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254",
        ],
        PayloadType.CMD_INJECTION: [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "&& id",
        ],
    }
    
    # 内置模板变量
    BUILTIN_VARIABLES = {
        "{{BaseURL}}": lambda ctx: ctx.target_url if ctx else "",
        "{{Timestamp}}": lambda ctx: str(int(__import__("time").time())),
        "{{RandomInt}}": lambda ctx: str(random.randint(1000, 9999)),
        "{{RandomString}}": lambda ctx: ''.join(random.choices(string.ascii_lowercase, k=8)),
        "{{RandomAlpha}}": lambda ctx: ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
        "{{RandomUUID}}": lambda ctx: str(__import__("uuid").uuid4()),
        "{{MD5}}": lambda ctx: hashlib.md5(str(random.random()).encode()).hexdigest(),
        "{{Year}}": lambda ctx: time.strftime("%Y"),
        "{{Month}}": lambda ctx: time.strftime("%m"),
        "{{NewLine}}": lambda ctx: "\n",
        "{{CRLF}}": lambda ctx: "\r\n",
        "{{Tab}}": lambda ctx: "\t",
        "{{NullByte}}": lambda ctx: "\x00",
    }
    
    def __init__(self, strategy: str = "default", max_variants: int = 10):
        """
        初始化生成器。
        
        Args:
            strategy: 生成策略（default, aggressive, stealthy）
            max_variants: 每个payload生成的最大变体数
        """
        self.strategy = strategy
        self.max_variants = max_variants
        self._context: Optional[AttackContext] = None
    
    def set_context(self, context: AttackContext) -> None:
        """设置攻击上下文"""
        self._context = context
    
    def build_payloads(self, plugin: Dict[str, Any], request_def: Dict[str, Any]) -> List[PayloadVariant]:
        """
        根据插件声明和上下文生成payload变体列表。
        
        Args:
            plugin: 插件配置
            request_def: 请求定义
            
        Returns:
            PayloadVariant列表
        """
        payload_variants: List[PayloadVariant] = []
        
        # 1. 从插件配置获取基础payload
        base_payloads = self._get_base_payloads(plugin, request_def)
        
        # 2. 确定payload类型
        payload_type = self._detect_payload_type(plugin)
        
        # 3. 为每个基础payload生成变体
        for payload in base_payloads:
            # 根据策略决定是否生成变体
            if self.strategy == "aggressive":
                variants = PayloadMutator.generate_variants(payload, payload_type)[:self.max_variants]
            else:
                variants = [payload]
            
            # 4. 确定编码方式
            encodings = self._determine_encodings(payload_type)
            
            # 5. 生成编码后的变体
            for variant in variants:
                for encoding in encodings:
                    encoded = PayloadEncoder.encode(variant, encoding)
                    context_score = self._calculate_context_score(variant, payload_type)
                    
                    payload_variants.append(PayloadVariant(
                        original=payload,
                        encoded=encoded,
                        encoding_type=encoding,
                        context_score=context_score,
                        mutation_type="mutated" if variant != payload else "original",
                    ))
        
        # 按上下文得分排序
        payload_variants.sort(key=lambda v: v.context_score, reverse=True)
        
        return payload_variants[:self.max_variants * len(encodings)]
    
    def _get_base_payloads(self, plugin: Dict[str, Any], request_def: Dict[str, Any]) -> List[str]:
        """获取基础payload列表"""
        # 优先从请求定义获取
        payload_sets = request_def.get("payload_sets") or plugin.get("payload_sets")
        if isinstance(payload_sets, dict):
            if self.strategy in payload_sets:
                return [str(x) for x in payload_sets[self.strategy]]
            elif "default" in payload_sets:
                return [str(x) for x in payload_sets["default"]]
        
        # 从默认payload库获取
        payload_type = self._detect_payload_type(plugin)
        return self.DEFAULT_SAFE_PAYLOADS.get(payload_type, self.DEFAULT_SAFE_PAYLOADS[PayloadType.GENERIC])
    
    def _detect_payload_type(self, plugin: Dict[str, Any]) -> PayloadType:
        """根据插件ID和信息检测payload类型"""
        plugin_id = str(plugin.get("id", "")).lower()
        plugin_info = plugin.get("info", {})
        severity = plugin_info.get("severity", "").lower()
        
        # 根据关键词映射类型
        type_keywords = {
            PayloadType.SQLI: ["sqli", "sql", "injection"],
            PayloadType.XSS: ["xss", "cross-site", "script"],
            PayloadType.PATH_TRAVERSAL: ["traversal", "path", "lfi"],
            PayloadType.LFI: ["lfi", "local file", "include"],
            PayloadType.RFI: ["rfi", "remote file"],
            PayloadType.SSRF: ["ssrf", "server-side request"],
            PayloadType.XXE: ["xxe", "xml entity"],
            PayloadType.CMD_INJECTION: ["cmd", "command", "rce", "exec"],
        }
        
        for ptype, keywords in type_keywords.items():
            if any(kw in plugin_id for kw in keywords):
                return ptype
        
        return PayloadType.GENERIC
    
    def _determine_encodings(self, payload_type: PayloadType) -> List[EncodingType]:
        """确定要使用的编码方式"""
        base_encodings = [EncodingType.NONE]
        
        if self._context:
            # 使用上下文感知建议
            suggested = ContextAwareEngine.suggest_encoding(self._context, payload_type)
            base_encodings.extend(suggested)
        
        # 根据策略调整
        if self.strategy == "aggressive":
            base_encodings.extend([
                EncodingType.URL,
                EncodingType.DOUBLE_URL,
            ])
        elif self.strategy == "stealthy":
            # 隐蔽模式，尽量减少编码变换
            base_encodings = [EncodingType.NONE, EncodingType.URL]
        
        return list(set(base_encodings))
    
    def _calculate_context_score(self, payload: str, payload_type: PayloadType) -> float:
        """计算payload与上下文的相关性得分"""
        score = 0.5
        
        if not self._context:
            return score
        
        # 检查是否有匹配的输入字段
        for field in self._context.input_fields:
            if field.get("type") == "text" and payload_type in [PayloadType.SQLI, PayloadType.XSS]:
                score += 0.1
        
        # 检查技术栈匹配
        if ("mysql" in self._context.detected_tech or "thinkphp" in self._context.detected_tech) and payload_type == PayloadType.SQLI:
            score += 0.3
        if "php" in self._context.detected_tech and payload_type == PayloadType.LFI:
            score += 0.2
        if "drupal" in self._context.detected_tech:
            score += 0.2
        
        return min(score, 1.0)
    
    def render_path(self, raw_path: str, base_url: str, payload: Optional[str] = None) -> str:
        """
        渲染模板变量。
        
        Args:
            raw_path: 原始路径模板
            base_url: 基础URL
            payload: payload值
            
        Returns:
            渲染后的路径
        """
        result = raw_path
        
        # 替换内置变量
        result = result.replace("{{BaseURL}}", base_url.rstrip("/"))
        if payload is not None:
            result = result.replace("{{payload}}", payload)
        
        # 替换其他内置变量
        for var, getter in self.BUILTIN_VARIABLES.items():
            if var in result:
                result = result.replace(var, getter(self._context))
        
        # 警告：不要对已经渲染好的 payload 进行二次编码，否则会破坏复杂的 SQL 注入格式（如 ThinkPHP 的数组参数）
        # 仅在必要时对 BaseURL 之外的部分进行基础处理，但要保持 payload 原样
        pass
        
        return result
    
    def render_body(self, body_template: str, payload: Optional[str] = None) -> str:
        """
        渲染请求体模板。
        
        Args:
            body_template: 请求体模板
            payload: payload值
            
        Returns:
            渲染后的请求体
        """
        result = body_template
        if payload is not None:
            result = result.replace("{{payload}}", payload)
        
        # 替换其他内置变量
        for var, getter in self.BUILTIN_VARIABLES.items():
            if var in result:
                result = result.replace(var, getter(self._context))
        
        return result
    
    def build_request(self, plugin: Dict[str, Any], request_def: Dict[str, Any],
                     base_url: str, payload_variant: PayloadVariant) -> Dict[str, Any]:
        """
        构建完整的HTTP请求。
        
        Args:
            plugin: 插件配置
            request_def: 请求定义
            base_url: 基础URL
            payload_variant: payload变体
            
        Returns:
            包含url, method, headers, body的请求字典
        """
        method = request_def.get("method", "GET").upper()
        raw_paths = request_def.get("path", [])
        
        requests = []
        for raw_path in raw_paths:
            url = self.render_path(raw_path, base_url, payload_variant.encoded)
            
            # 构建请求头
            headers = dict(request_def.get("headers", {}))
            if self._context and self._context.csrf_token:
                headers["X-CSRF-Token"] = self._context.csrf_token
            
                 # 构建请求体
            body = None
            if "body" in request_def:
                body = self.render_body(request_def["body"], payload_variant.encoded)
            
            # 处理 multipart/form-data
            if headers.get("Content-Type") == "multipart/form-data":
                # 简单替换 boundary，如果 body 中包含 boundary 占位符
                if "------WebKitFormBoundary" in (body or ""):
                    boundary = "----AegisBoundary" + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                    headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                    body = body.replace("------WebKitFormBoundary", "--" + boundary)
            
            requests.append({
                "url": url,
                "method": method,
                "headers": headers,
                "body": body,
            })
        
        return requests[0] if requests else {}


class AttackPathExplorer:
    """
    智能攻击路径探索器。
    
    实现多维度路径优先级算法，支持路径依赖分析、历史数据学习、
    动态路径发现等功能。
    """
    
    # 路径风险关键词
    HIGH_RISK_KEYWORDS = {
        "admin": 0.9,
        "config": 0.85,
        "upload": 0.8,
        ".git": 0.85,
        ".svn": 0.85,
        ".env": 0.9,
        "backup": 0.75,
        "debug": 0.7,
        "test": 0.65,
        "api": 0.6,
        "login": 0.7,
        "password": 0.8,
        "secret": 0.85,
        "key": 0.7,
        "token": 0.7,
        "upload": 0.8,
        "file": 0.6,
        "download": 0.65,
        "export": 0.6,
        "import": 0.6,
        "exec": 0.75,
        "cmd": 0.75,
        "shell": 0.8,
        "eval": 0.8,
    }
    
    # HTTP方法风险权重
    METHOD_RISK_WEIGHTS = {
        "GET": 0.1,
        "POST": 0.3,
        "PUT": 0.4,
        "PATCH": 0.35,
        "DELETE": 0.5,
    }
    
    def __init__(self, learning_enabled: bool = True):
        """
        初始化路径探索器。
        
        Args:
            learning_enabled: 是否启用自适应学习
        """
        self._visited: Set[str] = set()
        self._path_history: Dict[str, List[bool]] = defaultdict(list)  # 路径 -> 成功历史
        self._discovered_paths: List[str] = []
        self._path_dependencies: Dict[str, List[str]] = {}  # 路径 -> 依赖路径
        self._learning_enabled = learning_enabled
    
    def calculate_score(self, path: str, method: str, depth: int = 0) -> float:
        """
        计算路径的综合优先级得分。
        
        评分维度：
        1. 新颖度（是否已访问）
        2. 风险等级（关键词匹配）
        3. 历史成功率
        4. 路径深度
        5. HTTP方法风险
        6. Payload注入可能性
        
        Args:
            path: 路径
            method: HTTP方法
            depth: 路径深度
            
        Returns:
            综合得分（0-1）
        """
        path_lower = path.lower()
        
        # 1. 新颖度评分
        novelty_score = 1.0 if path not in self._visited else 0.2
        
        # 2. 风险评分（关键词匹配）
        risk_score = 0.0
        for keyword, weight in self.HIGH_RISK_KEYWORDS.items():
            if keyword in path_lower:
                risk_score = max(risk_score, weight)
        
        # 3. 历史成功率
        success_rate = 0.5
        if self._learning_enabled and path in self._path_history:
            history = self._path_history[path]
            if history:
                success_rate = sum(history) / len(history)
        
        # 4. 路径深度惩罚
        depth_penalty = 0.1 * depth
        
        # 5. HTTP方法风险
        method_score = self.METHOD_RISK_WEIGHTS.get(method.upper(), 0.1)
        
        # 6. Payload注入可能性
        injection_score = 0.5 if "{{payload}}" in path_lower or "{{" in path else 0.0
        
        # 综合得分（加权平均）
        total_score = (
            0.25 * novelty_score +
            0.30 * risk_score +
            0.20 * success_rate +
            0.10 * method_score +
            0.15 * injection_score -
            depth_penalty
        )
        
        return max(0.0, min(1.0, total_score))
    
    def rank(self, plugin: Dict[str, Any], request_def: Dict[str, Any], 
            base_url: str, context: Optional[AttackContext] = None) -> List[PathCandidate]:
        """
        对插件的请求路径进行优先级排序。
        
        Args:
            plugin: 插件配置
            request_def: 请求定义
            base_url: 基础URL
            context: 攻击上下文（可选）
            
        Returns:
            排序后的PathCandidate列表
        """
        method = request_def.get("method", "GET").upper()
        candidates: List[PathCandidate] = []
        
        for raw_path in request_def.get("path", []):
            # 构建完整URL
            url = raw_path.replace("{{BaseURL}}", base_url.rstrip("/"))
            
            # 计算路径深度
            depth = raw_path.count("/") - 2 if raw_path.startswith("http") else raw_path.count("/")
            
            # 计算综合得分
            score = self.calculate_score(raw_path, method, depth)
            
            # 提取上下文提示
            context_hints = {}
            if context:
                context_hints = {
                    "detected_tech": context.detected_tech,
                    "has_csrf": context.csrf_token is not None,
                }
            
            # 获取历史成功率
            success_rate = 0.5
            if self._learning_enabled and raw_path in self._path_history:
                history = self._path_history[raw_path]
                if history:
                    success_rate = sum(history) / len(history)
            
            candidate = PathCandidate(
                url=url,
                method=method,
                score=score,
                source_plugin=plugin.get("id", "unknown"),
                depth=max(0, depth),
                context_hints=context_hints,
                success_rate=success_rate,
            )
            candidates.append(candidate)
        
        # 按得分降序排序
        candidates.sort(key=lambda c: c.score, reverse=True)
        
        return candidates
    
    def mark_visited(self, url: str) -> None:
        """标记路径为已访问"""
        self._visited.add(url)
    
    def record_result(self, path: str, success: bool) -> None:
        """
        记录扫描结果用于学习。
        
        Args:
            path: 路径
            success: 是否发现漏洞
        """
        if self._learning_enabled:
            self._path_history[path].append(success)
            # 限制历史记录长度
            if len(self._path_history[path]) > 100:
                self._path_history[path] = self._path_history[path][-100:]
    
    def discover_paths(self, response_body: str, base_url: str) -> List[str]:
        """
        从响应中发现新的路径。
        
        Args:
            response_body: 响应体
            base_url: 基础URL
            
        Returns:
            发现的新路径列表
        """
        discovered = []
        
        # 链接发现模式
        link_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'location\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in link_patterns:
            matches = re.findall(pattern, response_body, re.IGNORECASE)
            for match in matches:
                # 过滤有效路径
                if match.startswith("/") or match.startswith(base_url):
                    # 避免重复
                    if match not in self._visited and match not in discovered:
                        discovered.append(match)
        
        self._discovered_paths.extend(discovered)
        return discovered
    
    def set_path_dependency(self, path: str, depends_on: List[str]) -> None:
        """
        设置路径依赖关系。
        
        Args:
            path: 目标路径
            depends_on: 依赖的路径列表
        """
        self._path_dependencies[path] = depends_on
    
    def get_prioritized_paths(self, discovered_paths: List[str], base_url: str) -> List[PathCandidate]:
        """
        获取优先级排序后的发现路径。
        
        Args:
            discovered_paths: 发现的路径列表
            base_url: 基础URL
            
        Returns:
            排序后的PathCandidate列表
        """
        candidates = []
        
        for path in discovered_paths:
            if path.startswith("/"):
                url = base_url.rstrip("/") + path
            else:
                url = path
            
            score = self.calculate_score(path, "GET", path.count("/"))
            
            candidates.append(PathCandidate(
                url=url,
                method="GET",
                score=score,
                source_plugin="discovery",
                depth=path.count("/"),
            ))
        
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取探索统计信息。
        
        Returns:
            包含visited_count, success_rate等统计信息的字典
        """
        total_paths = len(self._path_history)
        successful_paths = sum(1 for history in self._path_history.values() if any(history))
        
        return {
            "visited_count": len(self._visited),
            "discovered_count": len(self._discovered_paths),
            "tracked_paths": total_paths,
            "successful_paths": successful_paths,
            "learning_enabled": self._learning_enabled,
        }


# =============================================================================
# 攻击路径搜索算法（基于A*的启发式最优路径搜索）
# =============================================================================

@dataclass
class AttackPathNode:
    """
    攻击路径节点实体。
    
    表示攻击路径搜索空间中的一个节点，包含从起始节点到当前节点的
    累计代价、启发式代价估计以及综合评价函数值。
    
    Attributes:
        node_id: 节点唯一标识符（通常是URL或路径）
        url: 完整URL
        method: HTTP方法
        g_cost: 累计代价 g(n)，从起始节点到当前节点的实际攻击代价
        h_cost: 启发式代价 h(n)，从当前节点到目标节点的预期攻击成本
        f_cost: 综合评价函数 f(n) = g(n) + h(n)
        parent: 父节点引用，用于路径回溯
        depth: 节点深度（从起始节点开始的跳数）
        attack_vector: 关联的攻击向量信息
        vulnerabilities: 在该节点发现的漏洞列表
        visited: 是否已被访问/扩展
        timestamp: 节点创建时间戳
        
    Notes:
        - g(n) 代表已知的实际代价，随路径扩展累加
        - h(n) 是对剩余代价的估计，需要满足可采纳性（admissible）
        - f(n) 用于优先队列排序，值越小优先级越高
    """
    node_id: str
    url: str
    method: str = "GET"
    g_cost: float = 0.0
    h_cost: float = 0.0
    f_cost: float = 0.0
    parent: Optional["AttackPathNode"] = None
    depth: int = 0
    attack_vector: Optional[Dict[str, Any]] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    visited: bool = False
    timestamp: float = field(default_factory=time.time)
    
    def __lt__(self, other: "AttackPathNode") -> bool:
        """
        小于比较运算符，用于优先队列排序。
        
        优先级规则：
        1. f(n) 值较小的优先
        2. f(n) 相等时，h(n) 较小的优先（更接近目标）
        """
        if self.f_cost != other.f_cost:
            return self.f_cost < other.f_cost
        return self.h_cost < other.h_cost
    
    def __eq__(self, other: object) -> bool:
        """相等比较，基于节点ID"""
        if not isinstance(other, AttackPathNode):
            return False
        return self.node_id == other.node_id
    
    def __hash__(self) -> int:
        """哈希值，基于节点ID"""
        return hash(self.node_id)
    
    def update_f_cost(self) -> None:
        """更新综合评价函数值 f(n) = g(n) + h(n)"""
        self.f_cost = self.g_cost + self.h_cost
    
    def get_path(self) -> List["AttackPathNode"]:
        """
        从当前节点回溯到起始节点，获取完整路径。
        
        Returns:
            从起始节点到当前节点的路径列表
        """
        path = []
        current: Optional[AttackPathNode] = self
        while current is not None:
            path.append(current)
            current = current.parent
        return list(reversed(path))
    
    def get_path_cost(self) -> float:
        """
        获取从起始节点到当前节点的总代价。
        
        Returns:
            累计代价 g(n)
        """
        return self.g_cost


class HeuristicEvaluator(ABC):
    """
    启发式评估器抽象基类。
    
    定义启发式函数 h(n) 的计算接口。启发式函数用于估计从当前节点
    到目标节点的预期代价，是A*算法的核心组件。
    
    设计原则：
    1. 可采纳性（Admissible）：h(n) 不超过实际最优代价
    2. 一致性（Consistent）：h(n) ≤ c(n,n') + h(n')，其中c是边代价
    3. 信息性：h(n) 应尽可能接近实际代价，以提高搜索效率
    
    Notes:
        - 可采纳的启发式保证A*找到最优解
        - 更接近实际代价的启发式能减少扩展节点数
        - 启发式函数的设计需要平衡准确性和计算开销
    """
    
    @abstractmethod
    def evaluate(self, node: AttackPathNode, target: AttackPathNode, 
                 context: Optional[AttackContext] = None) -> float:
        """
        计算从当前节点到目标节点的启发式代价估计。
        
        Args:
            node: 当前节点
            target: 目标节点
            context: 攻击上下文信息
            
        Returns:
            启发式代价估计值 h(n)
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """获取评估器名称"""
        pass


class MultiDimensionalHeuristic(HeuristicEvaluator):
    """
    多维度启发式评估器。
    
    综合多个维度计算启发式代价，包括：
    1. 网络距离 - URL路径深度差、域名差异
    2. 攻击难度 - 基于漏洞类型、防护机制评估
    3. 历史成功率 - 基于历史扫描数据
    4. 风险评估 - 基于路径关键词风险权重
    5. 技术栈匹配 - 目标技术栈与攻击向量的匹配度
    
    Notes:
        - 各维度权重可配置
        - 支持动态调整权重策略
        - 归一化处理确保各维度贡献平衡
    """
    
    # 默认维度权重
    DEFAULT_WEIGHTS = {
        "network_distance": 0.20,
        "attack_difficulty": 0.25,
        "historical_success": 0.20,
        "risk_assessment": 0.20,
        "tech_match": 0.15,
    }
    
    # 漏洞利用难度系数（越高越难）
    VULN_DIFFICULTY = {
        PayloadType.GENERIC: 0.5,
        PayloadType.SQLI: 0.3,
        PayloadType.XSS: 0.2,
        PayloadType.PATH_TRAVERSAL: 0.25,
        PayloadType.LFI: 0.25,
        PayloadType.RFI: 0.35,
        PayloadType.SSRF: 0.4,
        PayloadType.XXE: 0.35,
        PayloadType.CMD_INJECTION: 0.45,
    }
    
    def __init__(self, weights: Optional[Dict[str, float]] = None,
                 learning_enabled: bool = True):
        """
        初始化多维度启发式评估器。
        
        Args:
            weights: 各维度权重配置，None则使用默认权重
            learning_enabled: 是否启用历史数据学习
        """
        self._weights = weights or self.DEFAULT_WEIGHTS.copy()
        self._learning_enabled = learning_enabled
        self._success_history: Dict[str, List[bool]] = defaultdict(list)
        self._path_costs: Dict[str, List[float]] = defaultdict(list)
    
    def evaluate(self, node: AttackPathNode, target: AttackPathNode,
                 context: Optional[AttackContext] = None) -> float:
        """
        计算多维度启发式代价。
        
        Args:
            node: 当前节点
            target: 目标节点
            context: 攻击上下文
            
        Returns:
            启发式代价估计值 h(n) ∈ [0, 1]
            
        Notes:
            - 返回值越小表示越接近目标（代价越低）
            - 各维度独立计算后加权平均
            - 归一化处理确保结果在合理范围
        """
        scores: Dict[str, float] = {}
        
        # 1. 网络距离评估
        scores["network_distance"] = self._evaluate_network_distance(node, target)
        
        # 2. 攻击难度评估
        scores["attack_difficulty"] = self._evaluate_attack_difficulty(node, context)
        
        # 3. 历史成功率评估
        scores["historical_success"] = self._evaluate_historical_success(node)
        
        # 4. 风险评估
        scores["risk_assessment"] = self._evaluate_risk(node)
        
        # 5. 技术栈匹配评估
        scores["tech_match"] = self._evaluate_tech_match(node, context)
        
        # 加权平均
        h_cost = sum(
            scores.get(dim, 0.5) * self._weights.get(dim, 0.0)
            for dim in self.DEFAULT_WEIGHTS.keys()
        )
        
        # 归一化到 [0, 1]
        return max(0.0, min(1.0, h_cost))
    
    def _evaluate_network_distance(self, node: AttackPathNode, 
                                    target: AttackPathNode) -> float:
        """
        评估网络距离。
        
        计算维度：
        - 路径深度差
        - URL相似度
        
        Args:
            node: 当前节点
            target: 目标节点
            
        Returns:
            网络距离评分 ∈ [0, 1]，越小越接近
        """
        # 路径深度差
        depth_diff = abs(node.depth - target.depth)
        depth_score = min(depth_diff * 0.1, 1.0)
        
        # URL路径相似度
        node_path = self._extract_path(node.url)
        target_path = self._extract_path(target.url)
        
        # 计算路径编辑距离
        path_similarity = self._calculate_path_similarity(node_path, target_path)
        
        # 综合评分
        return 0.5 * depth_score + 0.5 * (1.0 - path_similarity)
    
    def _evaluate_attack_difficulty(self, node: AttackPathNode,
                                     context: Optional[AttackContext]) -> float:
        """
        评估攻击难度。
        
        考虑因素：
        - 攻击向量类型
        - 是否存在防护机制
        - 需要的认证级别
        
        Args:
            node: 当前节点
            context: 攻击上下文
            
        Returns:
            攻击难度评分 ∈ [0, 1]，越高越难
        """
        base_difficulty = 0.5
        
        # 根据攻击向量调整
        if node.attack_vector:
            vuln_type = node.attack_vector.get("vuln_type")
            if isinstance(vuln_type, PayloadType):
                base_difficulty = self.VULN_DIFFICULTY.get(vuln_type, 0.5)
            elif isinstance(vuln_type, str):
                try:
                    base_difficulty = self.VULN_DIFFICULTY.get(
                        PayloadType(vuln_type.lower()), 0.5
                    )
                except ValueError:
                    pass
        
        # 根据上下文调整
        if context:
            # 检测到WAF或防护
            if context.response_status == 403:
                base_difficulty += 0.2
            
            # 需要认证
            if "login" in node.url.lower() or "auth" in node.url.lower():
                base_difficulty += 0.1
        
        return min(1.0, base_difficulty)
    
    def _evaluate_historical_success(self, node: AttackPathNode) -> float:
        """
        评估历史成功率。
        
        Args:
            node: 当前节点
            
        Returns:
            历史成功率评分 ∈ [0, 1]，越高表示历史上越容易成功
        """
        if not self._learning_enabled:
            return 0.5
        
        history = self._success_history.get(node.node_id, [])
        if not history:
            return 0.5
        
        # 计算成功率
        success_rate = sum(history) / len(history)
        
        # 返回失败率作为代价（成功率越高，代价越低）
        return 1.0 - success_rate
    
    def _evaluate_risk(self, node: AttackPathNode) -> float:
        """
        评估路径风险。
        
        高风险路径通常更容易发现漏洞，因此代价更低。
        
        Args:
            node: 当前节点
            
        Returns:
            风险评分 ∈ [0, 1]，越高表示风险越低（代价越高）
        """
        url_lower = node.url.lower()
        
        # 检查高风险关键词
        max_risk = 0.0
        for keyword, risk_weight in AttackPathExplorer.HIGH_RISK_KEYWORDS.items():
            if keyword in url_lower:
                max_risk = max(max_risk, risk_weight)
        
        # 风险越高，代价越低（返回 1 - 风险权重）
        return 1.0 - max_risk
    
    def _evaluate_tech_match(self, node: AttackPathNode,
                             context: Optional[AttackContext]) -> float:
        """
        评估技术栈匹配度。
        
        攻击向量与目标技术栈匹配时，成功概率更高。
        
        Args:
            node: 当前节点
            context: 攻击上下文
            
        Returns:
            匹配度评分 ∈ [0, 1]，越高表示不匹配（代价越高）
        """
        if not context or not node.attack_vector:
            return 0.5
        
        detected_tech = set(context.detected_tech)
        attack_tech = node.attack_vector.get("target_tech", set())
        
        if not attack_tech:
            return 0.5
        
        # 计算交集比例
        if isinstance(attack_tech, list):
            attack_tech = set(attack_tech)
        
        match_ratio = len(detected_tech & attack_tech) / len(attack_tech)
        
        # 匹配度越高，代价越低
        return 1.0 - match_ratio
    
    @staticmethod
    def _extract_path(url: str) -> str:
        """从URL提取路径部分"""
        try:
            parsed = urllib.parse.urlparse(url)
            return parsed.path
        except Exception:
            return url
    
    @staticmethod
    def _calculate_path_similarity(path1: str, path2: str) -> float:
        """
        计算路径相似度（基于最长公共子序列）。
        
        Args:
            path1: 第一个路径
            path2: 第二个路径
            
        Returns:
            相似度 ∈ [0, 1]
        """
        if not path1 or not path2:
            return 0.0
        
        # 分割路径段
        seg1 = [s for s in path1.split("/") if s]
        seg2 = [s for s in path2.split("/") if s]
        
        if not seg1 or not seg2:
            return 0.0
        
        # 计算最长公共子序列长度
        m, n = len(seg1), len(seg2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seg1[i - 1] == seg2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1] + 1
                else:
                    dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
        
        lcs_length = dp[m][n]
        return lcs_length / max(m, n)
    
    def record_result(self, node_id: str, success: bool, cost: float = 0.0) -> None:
        """
        记录扫描结果用于学习。
        
        Args:
            node_id: 节点ID
            success: 是否发现漏洞
            cost: 实际攻击代价
        """
        if self._learning_enabled:
            self._success_history[node_id].append(success)
            if cost > 0:
                self._path_costs[node_id].append(cost)
            
            # 限制历史记录长度
            if len(self._success_history[node_id]) > 100:
                self._success_history[node_id] = self._success_history[node_id][-100:]
    
    def get_name(self) -> str:
        """获取评估器名称"""
        return "MultiDimensionalHeuristic"


class CostCalculator:
    """
    攻击代价计算器。
    
    计算从一个节点到其邻接节点的边代价（攻击代价）。
    代价计算考虑多个因素：
    1. 基础代价 - HTTP请求成本
    2. 时间代价 - 攻击所需时间
    3. 检测风险 - 被检测的可能性
    4. 成功概率 - 攻击成功的概率
    """
    
    # HTTP方法基础代价
    METHOD_COST = {
        "GET": 0.1,
        "POST": 0.2,
        "PUT": 0.3,
        "DELETE": 0.4,
        "PATCH": 0.25,
    }
    
    # 响应状态码代价调整
    STATUS_COST_ADJUSTMENT = {
        200: 0.0,      # 成功，无额外代价
        301: 0.1,      # 重定向，轻微代价
        302: 0.1,
        400: 0.3,      # 客户端错误，中等代价
        401: 0.4,      # 需要认证
        403: 0.5,      # 禁止访问，高代价
        404: 0.2,      # 未找到
        500: 0.3,      # 服务器错误
    }
    
    @classmethod
    def calculate_edge_cost(cls, from_node: AttackPathNode, to_node: AttackPathNode,
                           response_status: int = 200,
                           response_time: float = 0.0,
                           context: Optional[AttackContext] = None) -> float:
        """
        计算边代价（从一个节点到另一个节点的攻击代价）。
        
        Args:
            from_node: 起始节点
            to_node: 目标节点
            response_status: HTTP响应状态码
            response_time: 响应时间（秒）
            context: 攻击上下文
            
        Returns:
            边代价值 ∈ [0, +∞)
            
        Notes:
            - 代价越低表示攻击越容易
            - 基础代价 + 方法代价 + 状态码调整 + 时间代价
        """
        # 基础代价
        base_cost = 0.1
        
        # HTTP方法代价
        method_cost = cls.METHOD_COST.get(to_node.method.upper(), 0.2)
        
        # 状态码调整
        status_adjustment = cls.STATUS_COST_ADJUSTMENT.get(response_status, 0.2)
        
        # 时间代价（归一化）
        time_cost = min(response_time / 10.0, 1.0) * 0.2
        
        # 深度代价（越深代价越高）
        depth_cost = to_node.depth * 0.05
        
        # 认证代价
        auth_cost = 0.0
        if context and context.csrf_token:
            auth_cost = 0.1
        
        total_cost = base_cost + method_cost + status_adjustment + time_cost + depth_cost + auth_cost
        
        return max(0.0, total_cost)
    
    @classmethod
    def calculate_cumulative_cost(cls, path: List[AttackPathNode]) -> float:
        """
        计算路径的累计代价。
        
        Args:
            path: 节点路径列表
            
        Returns:
            累计代价
        """
        if not path:
            return 0.0
        
        total = path[0].g_cost
        for node in path[1:]:
            total += node.g_cost
        
        return total


@dataclass
class AttackPathResult:
    """
    攻击路径搜索结果实体。
    
    Attributes:
        success: 搜索是否成功
        path: 最优攻击路径（节点列表）
        total_cost: 路径总代价
        nodes_expanded: 扩展的节点数
        nodes_visited: 访问的节点数
        search_time: 搜索耗时（秒）
        vulnerabilities_found: 发现的漏洞总数
        path_nodes: 路径节点ID列表（用于序列化）
        statistics: 详细统计信息
    """
    success: bool
    path: List[AttackPathNode] = field(default_factory=list)
    total_cost: float = 0.0
    nodes_expanded: int = 0
    nodes_visited: int = 0
    search_time: float = 0.0
    vulnerabilities_found: int = 0
    path_nodes: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典格式。
        
        Returns:
            可序列化的字典表示
        """
        return {
            "success": self.success,
            "path_nodes": [node.node_id for node in self.path],
            "path_urls": [node.url for node in self.path],
            "total_cost": self.total_cost,
            "nodes_expanded": self.nodes_expanded,
            "nodes_visited": self.nodes_visited,
            "search_time": self.search_time,
            "vulnerabilities_found": self.vulnerabilities_found,
            "statistics": self.statistics,
        }
    
    def get_attack_chain(self) -> List[Dict[str, Any]]:
        """
        获取攻击链详情。
        
        Returns:
            攻击链步骤列表
        """
        chain = []
        for i, node in enumerate(self.path):
            step = {
                "step": i + 1,
                "node_id": node.node_id,
                "url": node.url,
                "method": node.method,
                "g_cost": node.g_cost,
                "h_cost": node.h_cost,
                "f_cost": node.f_cost,
                "vulnerabilities": node.vulnerabilities,
            }
            chain.append(step)
        return chain


class AttackPathSearchAlgorithm:
    """
    攻击路径搜索算法。
    
    基于A*思想的启发式最优路径搜索算法，用于在网络攻击路径分析、
    漏洞传播建模及攻击链构建等场景中寻找最优攻击路径。
    
    算法流程：
    ┌─────────────────────────────────────────────────────────────────┐
    │ 一、状态初始化阶段                                               │
    │   • 接收起始节点与目标节点                                        │
    │   • 构建优先队列（开放列表）                                       │
    │   • 初始化代价参数 g(n)、h(n)、f(n)                               │
    │   • 建立父节点映射表                                              │
    ├─────────────────────────────────────────────────────────────────┤
    │ 二、循环搜索与节点扩展阶段                                        │
    │   WHILE 队列非空:                                                │
    │     • 取出 f(n) 最优节点                                         │
    │     • IF 到达目标节点: 进入路径回溯                               │
    │     • ELSE: 扩展邻接节点                                         │
    ├─────────────────────────────────────────────────────────────────┤
    │ 三、启发式扩展与代价计算阶段                                      │
    │   FOR 每个邻接节点:                                              │
    │     • 计算 g(n) = 累计攻击代价                                    │
    │     • 计算 h(n) = 启发式估计                                      │
    │     • 计算 f(n) = g(n) + h(n)                                    │
    │     • 更新节点状态与父节点                                        │
    │     • 加入优先队列                                               │
    ├─────────────────────────────────────────────────────────────────┤
    │ 四、路径回溯与最优路径输出阶段                                    │
    │   • 从目标节点反向回溯至起始节点                                   │
    │   • 构建完整攻击路径                                              │
    │   • 输出最优攻击路径及代价                                        │
    └─────────────────────────────────────────────────────────────────┘
    
    使用示例：
        algorithm = AttackPathSearchAlgorithm(heuristic=MultiDimensionalHeuristic())
        result = algorithm.search(start_node, target_node, adjacency_func)
        if result.success:
            print(f"最优路径: {[n.url for n in result.path]}")
            print(f"总代价: {result.total_cost}")
    
    Notes:
        - 启发式函数需要满足可采纳性以保证最优解
        - 支持多种启发式策略，可通过构造函数注入
        - 支持学习模式，记录历史结果优化后续搜索
    """
    
    def __init__(self, 
                 heuristic: Optional[HeuristicEvaluator] = None,
                 max_iterations: int = 10000,
                 learning_enabled: bool = True,
                 cost_threshold: float = 10.0):
        """
        初始化攻击路径搜索算法。
        
        Args:
            heuristic: 启发式评估器，None则使用默认的多维度评估器
            max_iterations: 最大迭代次数，防止无限循环
            learning_enabled: 是否启用学习模式
            cost_threshold: 代价阈值，超过此值的路径将被剪枝
        """
        self._heuristic = heuristic or MultiDimensionalHeuristic()
        self._max_iterations = max_iterations
        self._learning_enabled = learning_enabled
        self._cost_threshold = cost_threshold
        
        # 搜索状态
        self._open_list: List[AttackPathNode] = []  # 优先队列
        self._closed_set: Set[str] = set()  # 已访问集合
        self._node_map: Dict[str, AttackPathNode] = {}  # 节点映射
        self._g_scores: Dict[str, float] = {}  # 最优g值记录
        
        # 统计信息
        self._nodes_expanded = 0
        self._nodes_visited = 0
        self._start_time = 0.0
    
    def search(self, 
               start_node: AttackPathNode,
               target_node: AttackPathNode,
               adjacency_func: Callable[[AttackPathNode], List[AttackPathNode]],
               context: Optional[AttackContext] = None) -> AttackPathResult:
        """
        执行攻击路径搜索。
        
        这是算法的主入口方法，执行完整的A*搜索流程。
        
        Args:
            start_node: 起始节点
            target_node: 目标节点
            adjacency_func: 邻接节点获取函数，输入一个节点，返回其邻接节点列表
            context: 攻击上下文
            
        Returns:
            AttackPathResult 搜索结果
            
        Notes:
            算法时间复杂度: O(b^d)，其中b是分支因子，d是解深度
            空间复杂度: O(b^d)
        """
        # 记录开始时间
        self._start_time = time.time()
        
        # 重置搜索状态
        self._reset_state()
        
        # ==================== 一、状态初始化阶段 ====================
        self._initialize(start_node, target_node, context)
        
        # ==================== 二、循环搜索与节点扩展阶段 ====================
        iterations = 0
        while self._open_list and iterations < self._max_iterations:
            iterations += 1
            
            # 取出f(n)最优节点
            current = heapq.heappop(self._open_list)
            self._nodes_expanded += 1
            
            # 跳过已访问节点
            if current.node_id in self._closed_set:
                continue
            
            # 标记为已访问
            self._closed_set.add(current.node_id)
            self._nodes_visited += 1
            
            logger.debug(f"🔍 扩展节点: {current.node_id}, f={current.f_cost:.3f}, g={current.g_cost:.3f}, h={current.h_cost:.3f}")
            
            # 判断是否到达目标节点
            if self._is_target(current, target_node):
                # ==================== 四、路径回溯与最优路径输出阶段 ====================
                return self._build_success_result(current)
            
            # ==================== 三、启发式扩展与代价计算阶段 ====================
            self._expand_node(current, target_node, adjacency_func, context)
        
        # 搜索失败
        return self._build_failure_result()
    
    def _reset_state(self) -> None:
        """重置搜索状态"""
        self._open_list = []
        self._closed_set = set()
        self._node_map = {}
        self._g_scores = {}
        self._nodes_expanded = 0
        self._nodes_visited = 0
    
    def _initialize(self, start_node: AttackPathNode, target_node: AttackPathNode,
                   context: Optional[AttackContext]) -> None:
        """
        状态初始化阶段。
        
        执行以下初始化操作：
        1. 构建开放列表（优先队列）
        2. 将起始节点加入队列
        3. 初始化各节点的代价参数
        4. 建立节点映射表
        
        Args:
            start_node: 起始节点
            target_node: 目标节点
            context: 攻击上下文
        """
        # 计算起始节点的启发式代价
        start_node.h_cost = self._heuristic.evaluate(start_node, target_node, context)
        start_node.g_cost = 0.0
        start_node.update_f_cost()
        
        # 初始化记录
        self._g_scores[start_node.node_id] = 0.0
        self._node_map[start_node.node_id] = start_node
        
        # 将起始节点加入优先队列
        heapq.heappush(self._open_list, start_node)
        
        logger.debug(f"🚀 初始化搜索: 起点={start_node.node_id}, 终点={target_node.node_id}")
    
    def _expand_node(self, current: AttackPathNode, target: AttackPathNode,
                    adjacency_func: Callable[[AttackPathNode], List[AttackPathNode]],
                    context: Optional[AttackContext]) -> None:
        """
        启发式扩展与代价计算阶段。
        
        对于当前节点的每一个邻接节点，执行：
        1. 计算路径代价 g(n)
        2. 计算启发式代价 h(n)
        3. 计算综合评价函数 f(n) = g(n) + h(n)
        4. 更新节点状态
        5. 加入优先队列
        
        Args:
            current: 当前扩展节点
            target: 目标节点
            adjacency_func: 邻接节点获取函数
            context: 攻击上下文
        """
        # 获取邻接节点
        neighbors = adjacency_func(current)
        
        for neighbor in neighbors:
            # 跳过已访问节点
            if neighbor.node_id in self._closed_set:
                continue
            
            # 计算从起始节点到邻接节点的累计代价 g(n)
            edge_cost = CostCalculator.calculate_edge_cost(
                current, neighbor, context=context
            )
            tentative_g = current.g_cost + edge_cost
            
            # 剪枝：超过代价阈值
            if tentative_g > self._cost_threshold:
                continue
            
            # 检查是否发现更优路径
            if neighbor.node_id in self._g_scores:
                if tentative_g >= self._g_scores[neighbor.node_id]:
                    continue  # 已有更优路径，跳过
            
            # 更新节点状态
            neighbor.g_cost = tentative_g
            neighbor.h_cost = self._heuristic.evaluate(neighbor, target, context)
            neighbor.update_f_cost()
            neighbor.parent = current
            neighbor.depth = current.depth + 1
            
            # 记录最优g值
            self._g_scores[neighbor.node_id] = tentative_g
            self._node_map[neighbor.node_id] = neighbor
            
            # 加入优先队列
            heapq.heappush(self._open_list, neighbor)
            
            logger.debug(f"  ➕ 添加节点: {neighbor.node_id}, f={neighbor.f_cost:.3f}, g={neighbor.g_cost:.3f}, h={neighbor.h_cost:.3f}")
    
    def _is_target(self, node: AttackPathNode, target: AttackPathNode) -> bool:
        """
        判断是否到达目标节点。
        
        Args:
            node: 当前节点
            target: 目标节点
            
        Returns:
            是否为目标节点
        """
        # 精确匹配
        if node.node_id == target.node_id:
            return True
        
        # URL匹配
        if node.url == target.url:
            return True
        
        # 检查是否在目标节点集合中（可以是多个目标）
        if hasattr(target, 'target_ids') and node.node_id in target.target_ids:
            return True
        
        return False
    
    def _build_success_result(self, target_node: AttackPathNode) -> AttackPathResult:
        """
        构建成功搜索结果。
        
        从目标节点反向回溯至起始节点，构建完整攻击路径。
        
        Args:
            target_node: 目标节点
            
        Returns:
            AttackPathResult 成功结果
        """
        # 回溯路径
        path = target_node.get_path()
        
        # 统计漏洞数
        vuln_count = sum(len(node.vulnerabilities) for node in path)
        
        # 记录结果用于学习
        if self._learning_enabled and isinstance(self._heuristic, MultiDimensionalHeuristic):
            for node in path:
                self._heuristic.record_result(node.node_id, len(node.vulnerabilities) > 0, node.g_cost)
        
        search_time = time.time() - self._start_time
        
        logger.info(f"✅ 搜索成功: 路径长度={len(path)}, 总代价={target_node.g_cost:.3f}, "
                   f"扩展节点={self._nodes_expanded}, 耗时={search_time:.3f}s")
        
        return AttackPathResult(
            success=True,
            path=path,
            total_cost=target_node.g_cost,
            nodes_expanded=self._nodes_expanded,
            nodes_visited=self._nodes_visited,
            search_time=search_time,
            vulnerabilities_found=vuln_count,
            path_nodes=[node.node_id for node in path],
            statistics={
                "algorithm": "A*",
                "heuristic": self._heuristic.get_name(),
                "iterations": self._nodes_expanded,
                "avg_cost_per_node": target_node.g_cost / len(path) if path else 0,
            }
        )
    
    def _build_failure_result(self) -> AttackPathResult:
        """
        构建失败搜索结果。
        
        Returns:
            AttackPathResult 失败结果
        """
        search_time = time.time() - self._start_time
        
        logger.warning(f"❌ 搜索失败: 扩展节点={self._nodes_expanded}, 耗时={search_time:.3f}s")
        
        return AttackPathResult(
            success=False,
            path=[],
            total_cost=0.0,
            nodes_expanded=self._nodes_expanded,
            nodes_visited=self._nodes_visited,
            search_time=search_time,
            statistics={
                "algorithm": "A*",
                "heuristic": self._heuristic.get_name(),
                "failure_reason": "no_path_found" if not self._open_list else "max_iterations_reached",
            }
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取算法统计信息。
        
        Returns:
            统计信息字典
        """
        return {
            "nodes_expanded": self._nodes_expanded,
            "nodes_visited": self._nodes_visited,
            "open_list_size": len(self._open_list),
            "closed_set_size": len(self._closed_set),
            "heuristic": self._heuristic.get_name(),
            "learning_enabled": self._learning_enabled,
        }


class AttackGraphBuilder:
    """
    攻击图构建器。
    
    根据扫描结果和发现的路径构建攻击图，用于可视化攻击路径
    和进行更复杂的攻击路径分析。
    """
    
    def __init__(self):
        """初始化攻击图构建器"""
        self._nodes: Dict[str, AttackPathNode] = {}
        self._edges: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
    
    def add_node(self, node: AttackPathNode) -> None:
        """添加节点"""
        self._nodes[node.node_id] = node
    
    def add_edge(self, from_id: str, to_id: str, cost: float = 1.0) -> None:
        """添加边"""
        self._edges[from_id].append((to_id, cost))
    
    def get_neighbors(self, node_id: str) -> List[Tuple[AttackPathNode, float]]:
        """获取节点的邻接节点"""
        neighbors = []
        for neighbor_id, cost in self._edges.get(node_id, []):
            if neighbor_id in self._nodes:
                neighbors.append((self._nodes[neighbor_id], cost))
        return neighbors
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "nodes": {
                node_id: {
                    "url": node.url,
                    "method": node.method,
                    "g_cost": node.g_cost,
                    "vulnerabilities": len(node.vulnerabilities),
                }
                for node_id, node in self._nodes.items()
            },
            "edges": dict(self._edges),
        }


# =============================================================================
# 便捷函数
# =============================================================================

def create_default_generator() -> AttackScriptGenerator:
    """创建默认配置的攻击脚本生成器"""
    return AttackScriptGenerator(strategy="default", max_variants=10)


def create_aggressive_generator() -> AttackScriptGenerator:
    """创建激进模式的攻击脚本生成器"""
    return AttackScriptGenerator(strategy="aggressive", max_variants=20)


def create_default_explorer() -> AttackPathExplorer:
    """创建默认配置的路径探索器"""
    return AttackPathExplorer(learning_enabled=True)


def create_default_search_algorithm() -> AttackPathSearchAlgorithm:
    """
    创建默认配置的攻击路径搜索算法。
    
    Returns:
        配置好的AttackPathSearchAlgorithm实例
    """
    return AttackPathSearchAlgorithm(
        heuristic=MultiDimensionalHeuristic(),
        max_iterations=10000,
        learning_enabled=True,
    )


def create_attack_node(url: str, method: str = "GET", 
                       node_id: Optional[str] = None,
                       attack_vector: Optional[Dict[str, Any]] = None) -> AttackPathNode:
    """
    创建攻击路径节点的便捷函数。
    
    Args:
        url: 节点URL
        method: HTTP方法
        node_id: 节点ID，None则使用URL
        attack_vector: 攻击向量信息
        
    Returns:
        AttackPathNode实例
    """
    return AttackPathNode(
        node_id=node_id or url,
        url=url,
        method=method,
        attack_vector=attack_vector,
    )
