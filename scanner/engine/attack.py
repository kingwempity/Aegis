"""
scanner.engine.attack
---------------------
模拟攻击引擎核心模块：
1) 攻击脚本生成 (AttackScriptGenerator) - 智能payload生成与编码
2) 攻击路径探索 (AttackPathExplorer) - 多维度路径优先级算法
3) Payload编码器 (PayloadEncoder) - 多种编码方式支持
4) 上下文感知引擎 (ContextAwareEngine) - 基于响应动态调整策略

保持无害化扫描：仅生成验证型 payload，不执行破坏性命令。


"""

from __future__ import annotations

import base64
import hashlib
import random
import re
import string
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable, Set, Tuple
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
        if "php" in context.detected_tech:
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
        if "mysql" in self._context.detected_tech and payload_type == PayloadType.SQLI:
            score += 0.2
        if "php" in self._context.detected_tech and payload_type == PayloadType.LFI:
            score += 0.2
        
        return min(score, 1.0)
    
    def render_path(self, raw_path: str, base_url: str, payload: str) -> str:
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
        result = result.replace("{{payload}}", payload)
        
        # 替换其他内置变量
        for var, getter in self.BUILTIN_VARIABLES.items():
            if var in result:
                result = result.replace(var, getter(self._context))
        
        return result
    
    def render_body(self, body_template: str, payload: str) -> str:
        """
        渲染请求体模板。
        
        Args:
            body_template: 请求体模板
            payload: payload值
            
        Returns:
            渲染后的请求体
        """
        result = body_template.replace("{{payload}}", payload)
        
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


# 便捷函数
def create_default_generator() -> AttackScriptGenerator:
    """创建默认配置的攻击脚本生成器"""
    return AttackScriptGenerator(strategy="default", max_variants=10)


def create_aggressive_generator() -> AttackScriptGenerator:
    """创建激进模式的攻击脚本生成器"""
    return AttackScriptGenerator(strategy="aggressive", max_variants=20)


def create_default_explorer() -> AttackPathExplorer:
    """创建默认配置的路径探索器"""
    return AttackPathExplorer(learning_enabled=True)