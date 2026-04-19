"""
scanner.engine.recon
--------------------
增强型侦察模块（Reconnaissance Engine）

基于现有ContextAwareEngine的全面升级，提供深度目标侦察能力：

核心能力：
1. 深度指纹识别 - 技术、版本、补丁级别
2. WAF/防护系统指纹识别 - 厂商、规则集、强度评估
3. 应用架构推断 - 微服务/单体/负载均衡
4. 认证机制识别 - OAuth/JWT/Session/Cookie
5. API端点发现 - GraphQL/REST/SOAP
6. 第三方组件识别 - jQuery/React/Vue版本
7. 攻击面分析 - 入口点、参数、功能点

设计原则：
    - 渐进式探测：从被动到主动，逐步深入
    - 特征库驱动：基于已知特征模式匹配
    - 上下文关联：多维度信息交叉验证
    - 低干扰性：最小化对目标的影响
"""

from __future__ import annotations

import re
import time
import json
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum
import logging
import httpx

logger = logging.getLogger(__name__)


class WAFType(Enum):
    """WAF厂商类型枚举"""
    UNKNOWN = "unknown"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AZURE_WAF = "azure_waf"
    MODSECURITY = "modsecurity"
    INCAPSULA = "incapsula"
    AKAMAI = "akamai"
    SUCURI = "sucuri"
    F5_BIG_IP = "f5_big_ip"
    BARRACUDA = "barracuda"
    IMPERVA = "imperva"
    CITRIX = "citrix"
    RADWARE = "radware"
    FORTINET = "fortinet"
    DENYALL = "denyall"
    WALLARM = "wallarm"
    COMODO = "comodo"
    SECUREIIS = "secureiis"
    WEBKNIGHT = "webknight"
    BINARYSEC = "binarysec"
    HYPERGUARD = "hyperguard"
    NETSCALER = "netscaler"
    QUICK Defense = "quick_defense"


class ArchitectureType(Enum):
    """应用架构类型"""
    UNKNOWN = "unknown"
    MONOLITHIC = "monolithic"           # 单体应用
    MICROSERVICES = "microservices"     # 微服务架构
    LOAD_BALANCED = "load_balanced"    # 负载均衡
    CDN_PROXIED = "cdn_proxied"        # CDN代理
    SERVERLESS = "serverless"          # 无服务器架构
    CONTAINERIZED = "containerized"    # 容器化部署


class AuthType(Enum):
    """认证机制类型"""
    NONE = "none"
    SESSION_COOKIE = "session_cookie"
    JWT_TOKEN = "jwt_token"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    DIGEST_AUTH = "digest_auth"
    API_KEY = "api_key"
    FORM_BASED = "form_based"
    SAML = "saml"
    LDAP = "ldap"
    MULTI_FACTOR = "multi_factor"


class ProtectionLevel(Enum):
    """防护强度等级"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERY_HIGH = 4


@dataclass
class TechnologyInfo:
    """技术信息实体"""
    name: str
    category: str  # framework/language/database/server/cdn/cms
    version: Optional[str] = None
    confidence: float = 0.0
    fingerprints: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": round(self.confidence, 3),
            "fingerprints": self.fingerprints,
        }


@dataclass
class WAFFingerprint:
    """WAF指纹信息"""
    waf_type: WAFType = WAFType.UNKNOWN
    vendor_name: str = ""
    version: Optional[str] = None
    protection_level: ProtectionLevel = ProtectionLevel.NONE
    confidence: float = 0.0
    detected_signatures: List[str] = field(default_factory=list)
    bypass_recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "waf_type": self.waf_type.value,
            "vendor_name": self.vendor_name,
            "version": self.version,
            "protection_level": self.protection_level.value,
            "confidence": round(self.confidence, 3),
            "detected_signatures": self.detected_signatures,
            "bypass_recommendations": self.bypass_recommendations,
        }


@dataclass
class EntryPoint:
    """入口点信息"""
    url: str
    method: str = "GET"
    parameters: List[Dict[str, str]] = field(default_factory=list)
    auth_required: bool = False
    functionality: str = ""  # login/api/upload/admin etc.
    risk_score: float = 0.5
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "auth_required": self.auth_required,
            "functionality": self.functionality,
            "risk_score": round(self.risk_score, 3),
        }


@dataclass
class ReconResult:
    """侦察结果"""
    target_url: str
    timestamp: float = field(default_factory=time.time)
    
    # 技术栈信息
    technologies: List[TechnologyInfo] = field(default_factory=list)
    primary_framework: Optional[str] = None
    primary_language: Optional[str] = None
    primary_database: Optional[str] = None
    
    # WAF/防护信息
    waf_fingerprint: WAFFingerprint = field(default_factory=WAFFingerprint)
    
    # 架构信息
    architecture: ArchitectureType = ArchitectureType.UNKNOWN
    is_behind_cdn: bool = False
    is_load_balanced: bool = False
    
    # 认证信息
    auth_mechanism: AuthType = AuthType.NONE
    auth_endpoints: List[str] = field(default_factory=list)
    session_config: Dict[str, Any] = field(default_factory=dict)
    
    # 入口点
    entry_points: List[EntryPoint] = field(default_factory=list)
    api_endpoints: List[EntryPoint] = field(default_factory=list)
    sensitive_paths: List[str] = field(default_factory=list)
    
    # 第三方组件
    third_party_components: Dict[str, str] = field(default_factory=dict)
    
    # 安全头信息
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)
    
    # 其他发现
    interesting_headers: Dict[str, str] = field(default_factory=dict)
    comments_or_debug_info: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "technologies": [t.to_dict() for t in self.technologies],
            "primary_framework": self.primary_framework,
            "primary_language": self.primary_language,
            "primary_database": self.primary_database,
            "waf_fingerprint": self.waf_fingerprint.to_dict(),
            "architecture": self.architecture.value,
            "is_behind_cdn": self.is_behind_cdn,
            "is_load_balanced": self.is_load_balanced,
            "auth_mechanism": self.auth_mechanism.value,
            "auth_endpoints": self.auth_endpoints,
            "session_config": self.session_config,
            "entry_points": [ep.to_dict() for ep in self.entry_points],
            "api_endpoints": [ep.to_dict() for ep in self.api_endpoints],
            "sensitive_paths": self.sensitive_paths,
            "third_party_components": self.third_party_components,
            "security_headers": self.security_headers,
            "missing_security_headers": self.missing_security_headers,
            "interesting_headers": self.interesting_headers,
            "comments_or_debug_info": self.comments_or_debug_info,
        }


class ReconEngine:
    """
    增强型侦察引擎
    
    提供全面的目标侦察能力，为后续攻击提供充分的上下文信息。
    
    使用示例:
        >>> engine = ReconEngine()
        >>> result = await engine.deep_recon("http://example.com", client)
        >>> print(result.primary_framework)  # 'ThinkPHP'
        >>> print(result.waf_fingerprint.waf_type)  # WAFType.CLOUDFLARE
    """
    
    # ==================== 技术栈特征库 ====================
    
    FRAMEWORK_SIGNATURES = {
        'thinkphp': {
            'patterns': [
                r'thinkphp',
                r'ThinkPHP',
                r'Think\\',
                r'Think\\\\',
                r'__think__',
                r'think_',
                r's=/',
                r'?s=',
                r'Var_Pathinfo',
                r'think_trace',
            ],
            'version_patterns': [
                (r'ThinkPHP\s*[\(]?(\d+\.\d+)', 'header'),
                (r'think_version\s*=\s*[\'"](\d+\.\d+)', 'body'),
            ],
            'category': 'framework',
        },
        'django': {
            'patterns': [
                r'django',
                r'csrfmiddlewaretoken',
                r'Django Settings Module',
                r'DJANGO_SETTINGS_MODULE',
                r'django\.contrib',
                r'Exception Type.*Exception Value',
                r'Report at.*using Django',
                r'You\'re seeing this error because you have DEBUG = True',
            ],
            'version_patterns': [
                (r'Django/(\d+\.\d+)', 'header'),
                (r'using Django (\d+\.\d+)', 'body'),
            ],
            'category': 'framework',
        },
        'drupal': {
            'patterns': [
                r'Drupal',
                r'Drupal\.settings',
                r'X-Generator: Drupal',
                r'Drupal\.ajax',
                r'form_build_id',
                r'form_token',
                r'drupal-settings-json',
                r'sites/default/files',
            ],
            'version_patterns': [
                (r'Drupal\s+(\d+)', 'header'),
                (r'Drupal \d+\.(\d+)', 'meta'),
            ],
            'category': 'cms',
        },
        'wordpress': {
            'patterns': [
                r'wp-content',
                r'wp-includes',
                r'wp-json',
                r'wordpress',
                r'XML-RPC server accepts POST requests only',
                r'generator.*WordPress',
            ],
            'version_patterns': [
                (r'generator.*WordPress\s+(\d+\.\d+)', 'meta'),
            ],
            'category': 'cms',
        },
        'laravel': {
            'patterns': [
                r'laravel',
                r'Laravel',
                r'laravel_session',
                r'XSRF-TOKEN',
                r'laravel_token',
            ],
            'version_patterns': [
                (r'Laravel\s+v?(\d+\.\d+)', 'cookie'),
            ],
            'category': 'framework',
        },
        'spring': {
            'patterns': [
                r'Spring Framework',
                r'org\.springframework',
                r'.*\.spring\.',
                r'Whitelabel Error Page',
            ],
            'version_patterns': [
                (r'Spring\s+(\d+\.\d+)', 'header'),
            ],
            'category': 'framework',
        },
        'express': {
            'patterns': [
                r'X-Powered-By:\s*Express',
                r'connect\.sid',
            ],
            'version_patterns': [],
            'category': 'framework',
        },
        'flask': {
            'patterns': [
                r'Flask',
                r'werkzeug',
            ],
            'version_patterns': [
                (r'Werkzeug/(\d+\.\d+)', 'header'),
            ],
            'category': 'framework',
        },
        'rails': {
            'patterns': [
                r'Ruby on Rails',
                r'Rails',
                r'X-Request-Id',
                r'X-Runtime',
                r'rails CSRF',
            ],
            'version_patterns': [
                (r'Rails/(\d+\.\d+)', 'header'),
            ],
            'category': 'framework',
        },
        'asp.net': {
            'patterns': [
                r'ASP\.NET',
                r'X-AspNet-Version',
                r'X-Powered-By: ASP\.NET',
                r'__VIEWSTATE',
                r'__EVENTVALIDATION',
                r'\.aspx',
                r'System\.Web',
            ],
            'version_patterns': [
                (r'ASP\.NET\s+(\d+\.\d+)', 'header'),
            ],
            'category': 'framework',
        },
        'php': {
            'patterns': [
                r'PHP/',
                r'X-Powered-By: PHP',
                r'.php',
                r'Zend Engine',
                r'Laravel',
                r'WordPress',
                r'Drupal',
                r'Magento',
                r'Joomla',
            ],
            'version_patterns': [
                (r'PHP/(\d+\.\d+)', 'header'),
            ],
            'category': 'language',
        },
        'java': {
            'patterns': [
                r'JSP',
                r'JSESSIONID',
                r'Java/',
                r'Spring',
                r'Struts',
                r'Apache Tomcat',
                r'Jetty',
                r'javax\.servlet',
            ],
            'version_patterns': [
                (r'Java/\d+\.(\d+)', 'header'),
                (r'Apache Tomcat/(\d+\.\d+)', 'header'),
            ],
            'category': 'language',
        },
        'python': {
            'patterns': [
                r'Python/',
                r'Django',
                r'Flask',
                r'FastAPI',
                r'Pyramid',
                r'wsgi',
            ],
            'version_patterns': [
                (r'Python/(\d+\.\d+)', 'header'),
            ],
            'category': 'language',
        },
        'nodejs': {
            'patterns': [
                r'Node.js',
                r'Express',
                r'Next.js',
                r'Nuxt.js',
                r'connect\.sid',
            ],
            'version_patterns': [
                (r'Node\.js\s+v?(\d+\.\d+)', 'header'),
            ],
            'category': 'language',
        },
        'mysql': {
            'patterns': [
                r'mysql',
                r'MySQL',
                r'mysqli',
                r'pdo_mysql',
                r'SQL syntax.*MySQL',
                r'mysql_fetch_array',
                r'MySQLSyntaxErrorException',
                r'SQLSTATE\[',
            ],
            'version_patterns': [
                (r'MySQL\s+(\d+\.\d+)', 'error'),
            ],
            'category': 'database',
        },
        'postgresql': {
            'patterns': [
                r'postgresql',
                r'PostgreSQL',
                r'pg_',
                r'PSQL:',
                r'pg_query',
                r'PostgreSQL query failed',
            ],
            'version_patterns': [
                (r'PostgreSQL\s+(\d+\.\d+)', 'error'),
            ],
            'category': 'database',
        },
        'mssql': {
            'patterns': [
                r'Microsoft SQL Server',
                r'SQL Server',
                r'SQLServer',
                mssql_driver_pattern := r'(sqlsrv|SQLSRV|pdo_sqlsrv|odbc)',
                r'Microsoft OLE DB Provider for SQL Server',
            ],
            'version_patterns': [],
            'category': 'database',
        },
        'oracle': {
            'patterns': [
                r'Oracle',
                r'ORA-',
                r'oracle\.jdbc',
                r'Oracle Database',
            ],
            'version_patterns': [
                (r'ORA-\d{5}', 'error'),
            ],
            'category': 'database',
        },
        'mongodb': {
            'patterns': [
                r'MongoDB',
                r'mongodb',
                r'MongoError',
            ],
            'version_patterns': [],
            'category': 'database',
        },
        'redis': {
            'patterns': [
                r'redis',
                r'Redis',
            ],
            'version_patterns': [],
            'category': 'database',
        },
        'nginx': {
            'patterns': [
                r'nginx',
                r'nginx/',
            ],
            'version_patterns': [
                (r'nginx/(\d+\.\d+)', 'server'),
            ],
            'category': 'server',
        },
        'apache': {
            'patterns': [
                r'Apache',
                r'httpd',
                r'mod_',
                r'\.htaccess',
                r'server: apache',
            ],
            'version_patterns': [
                (r'Apache/?(\d+\.\d+)', 'server'),
            ],
            'category': 'server',
        },
        'iis': {
            'patterns': [
                r'IIS/',
                r'Microsoft-IIS',
                r'Internet Information Services',
            ],
            'version_patterns': [
                (r'IIS/(\d+\.\d+)', 'server'),
            ],
            'category': 'server',
        }
    }
    
    # ==================== WAF特征库 ====================
    
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: {
            'headers': {
                'cf-ray': True,
                'cf-connecting-ip': True,
                'cf-ipcountry': True,
                'cf-cache-status': True,
                'cf-request-id': True,
                'server': ['cloudflare'],
            },
            'cookies': {
                '__cfduid': True,
                'cf_clearance': True,
            },
            'body_patterns': [
                r'cloudflare',
                r'cf-browser-verify',
                r'attention required.*cloudflare',
                r'just a moment.*cloudflare',
            ],
            'status_codes': [403, 503],
            'bypass_tips': [
                '使用Cloudflare Workers绕过',
                '尝试直接访问源站IP',
                '使用Cloudflare-specific bypass techniques',
            ],
        },
        WAFType.AWS_WAF: {
            'headers': {
                'x-amz-cf-id': True,
                'x-amzn-requestid': True,
                'x-amz-cf-pop': True,
                'via': ['Amazon CloudFront'],
                'x-cache': True,
                'x-amz-cf-invoked-type': True,
            },
            'cookies': {},
            'body_patterns': [
                r'AWS Managed Rules',
                r'AWS WAF',
                r'Request blocked by AWS WAF',
            ],
            'status_codes': [403, 405],
            'bypass_tips': [
                '检查AWS WAF规则配置',
                '尝试不同的HTTP方法',
                '使用IP白名单绕过',
            ],
        },
        WAFType.AZURE_WAF: {
            'headers': {
                'x-azure-ref': True,
                'x-ms-ref': True,
                'x-forwarded-for': True,
                'request-context': True,
            },
            'cookies': {
                'ARRAffinity': True,
                'ARRAffinitySameSite': True,
            },
            'body_patterns': [
                r'Azure Web App',
                r'Application Gateway',
                r'Azure Front Door',
                r'Request blocked by Azure WAF',
            ],
            'status_codes': [403, 405],
            'bypass_tips': [
                '检查Azure WAF策略',
                '尝试Azure Front Door直接访问',
            ],
        },
        WAFType.MODSECURITY: {
            'headers': {
                'server': ['ModSecurity'],
                'x-mod-security-rule': True,
            },
            'cookies': {},
            'body_patterns': [
                r'ModSecurity',
                r'Web Application Firewall',
                r'blocked by mod_security',
                r'modsecurity_error',
            ],
            'status_codes': [403, 406],
            'bypass_tips': [
                '使用ModSecurity规则绕过技巧',
                '尝试编码绕过（URL编码、Unicode等）',
                '利用已知ModSecurity规则缺陷',
            ],
        },
        WAFType.INCAPSULA: {
            'headers': {
                'x-iinfo': True,
                'x-cdn': ['Incapsula'],
                'x-redirect-reason': True,
                'visid_incap': True,
                'incap_ses': True,
            },
            'cookies': {
                'incap_ses_': True,
                'visid_incap_': True,
            },
            'body_patterns': [
                r'Incapsula Incident ID',
                r'Incapsula',
                r'website is under DDoS attack',
            ],
            'status_codes': [403, 503],
            'bypass_tips': [
                '尝试Incapsula缓存绕过',
                '使用不同的User-Agent',
            ],
        },
        WAFType.AKAMAI: {
            'headers': {
                'x-akamai-transformed': True,
                'x-akamai-logged-in': True,
                'x-cache-remote': True,
                'x-akamai-session-handle': True,
            },
            'cookies': {
                'akavpau_': True,
            },
            'body_patterns': [
                r'AkamaiGHost',
                r'Akamai Bot Manager',
                r'Access Denied.*Akamai',
            ],
            'status_codes': [403, 406],
            'bypass_tips': [
                '使用Akamai特定的绕过方法',
                '尝试不同的请求路径',
            ],
        },
        WAFType.SUCURI: {
            'headers': {
                'x-sucuri-id': True,
                'x-sucuri-cache': True,
                'x-sucuri-country': True,
            },
            'cookies': {},
            'body_patterns': [
                r'Access Denied - Sucuri Website Firewall',
                r'Sucuri',
                r'Blocked by Sucuri Firewall',
            ],
            'status_codes': [403, 406],
            'bypass_tips': [
                '访问Sucuri允许的页面',
                '尝试IP白名单',
            ],
        },
        WAFType.F5_BIG_IP: {
            'headers': {
                'x-wa-info': True,
                'server': ['BIG-IP', 'bigip'],
            },
            'cookies': {
                'BIGipServer': True,
                'F5_STRICT': True,
            },
            'body_patterns': [
                r'Traffic Server found a problem',
                r'F5 Network',
                r'BigIP',
            ],
            'status_codes': [403, 406],
            'bypass_tips': [
                '使用F5 ASM绕过技术',
                '尝试不同的编码方式',
            ],
        },
        WAFType.BARRACUDA: {
            'headers': {
                'barra_counter_session': True,
                'barra_sessionId': True,
                'x-barracuda': True,
            },
            'cookies': {
                'barra_counter_session': True,
            },
            'body_patterns': [
                r'Barracuda Networks Security',
                r'Barracuda WAF',
                r'Access denied by Barracuda',
            ],
            'status_codes': [403, 406],
            'bypass_tips': [
                '使用Barracuda特定绕过方法',
            ],
        },
        WAFType.IMPERVA: {
            'headers': {
                'x-iinfo': True,
                'x-visitors-country': True,
                'x-CDN': ['Imperva Incapsula'],
            },
            'cookies': {
                'incap_ses_': True,
                'visid_inap_': True,
                '_incap_ses_': True,
            },
            'body_patterns': [
                r'Incapsula Incident ID',
                r'Click here to continue',
                r'Imperva Security',
            ],
            'status_codes': [403, 503],
            'bypass_tips': [
                '使用Imperva特定绕过方法',
            ],
        },
        WAFType.WEBKNIGHT: {
            'headers': {
                'server': ['Webknight'],
            },
            'cookies': {},
            'body_patterns': [
                r'WebKnight Application Firewall',
                r'Request Rejected by WebKnight',
            ],
            'status_codes': [403, 999],
            'bypass_tips': [
                '使用WebKnight绕过技巧',
            ],
        },
    }
    
    # ==================== 第三方组件特征库 ====================
    
    THIRD_PARTY_SIGNATURES = {
        'jquery': {
            'patterns': [
                r'jquery[\.-]?(\d+\.\d+\.\d+)?',
                r'jQuery',
                r'jquery\.min\.js',
            ],
            'extract_version': r'jquery[\.-]?(\d+\.\d+\.\d+)',
        },
        'react': {
            'patterns': [
                r'react[\.-]?(\d+\.\d+\.\d+)?',
                r'_next/static',
                r'__NEXT_DATA__',
                r'react-dom',
                r'createElement',
            ],
            'extract_version': r'react[\.-]?(\d+\.\d+\.\d+)',
        },
        'vue': {
            'patterns': [
                r'vue[\.-]?(\d+\.\d+\.\d+)?',
                r'Vue\.config',
                r'v-cloak',
                r'vue-router',
            ],
            'extract_version': r'vue[\.-]?(\d+\.\d+\.\d+)',
        },
        'angular': {
            'patterns': [
                r'angular[\.-]?(\d+\.\d+\.\d+)?',
                r'ng-version',
                r'ng-app',
                r'angular\.module',
            ],
            'extract_version': r'angular[\.-]?(\d+\.\d+\.\d+)',
        },
        'bootstrap': {
            'patterns': [
                r'bootstrap[\.-]?(\d+\.\d+\.\d+)?',
                r'bootstrap\.min\.css',
                r'bootstrap\.min\.js',
            ],
            'extract_version': r'bootstrap[\.-]?(\d+\.\d+\.\d+)',
        },
        'fontawesome': {
            'patterns': [
                r'font-awesome[\.-]?(\d+\.\d+\.\d+)?',
                r'fontawesome',
            ],
            'extract_version': r'font-awesome[\.-]?(\d+\.\d+\.\d+)',
        },
        'axios': {
            'patterns': [
                r'axios[\.-]?(\d+\.\d+\.\d+)?',
            ],
            'extract_version': r'axios[\.-]?(\d+\.\d+\.\d+)',
        },
    }
    
    # ==================== 敏感路径列表 ====================
    
    SENSITIVE_PATHS = [
        '/admin', '/administrator', '/admin/login', '/admin/index',
        '/login', '/user/login', '/signin', '/account/login',
        '/api', '/api/v1', '/graphql', '/rest', '/soap',
        '/upload', '/uploads', '/files', '/media',
        '/backup', '/backups', '/db', '/database',
        '/config', '/configuration', '/settings',
        '/debug', '/test', '/dev', '/development',
        '/console', '/terminal', '/shell', '/cmd',
        '/phpmyadmin', '/adminer', '/mysql',
        '/git/config', '/svn/entries', '.env', '.git',
        '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
        '/.well-known/', '/security.txt',
        '/wp-admin', '/wp-login.php', '/xmlrpc.php',
        '/drupal', '/user/register', '/user/login',
        '/manage', '/management', '/monitor',
        '/swagger-ui.html', '/api-docs', '/redoc',
        '/grafana', '/prometheus', '/metrics',
        '/jenkins', '/jira', '/confluence',
    ]
    
    # ==================== 安全头列表 ====================
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Frame-Options': 'Clickjacking Protection',
        'X-Content-Type-Options': 'MIME Sniffing',
        'X-XSS-Protection': 'XSS Filter',
        'Referrer-Policy': 'Referrer Policy',
        'Permissions-Policy': 'Feature Policy',
        'Cross-Origin-Opener-Policy': 'COOP',
        'Cross-Origin-Resource-Policy': 'CORP',
        'Cross-Origin-Embedder-Policy': 'COEP',
        'Cache-Control': 'Cache Control',
        'Pragma': 'Cache Control (Legacy)',
        'Expires': 'Cache Control (Legacy)',
    }
    
    def __init__(self, max_depth: int = 3, timeout: float = 10.0):
        """
        初始化侦察引擎
        
        Args:
            max_depth: 最大探测深度
            timeout: 请求超时时间（秒）
        """
        self.max_depth = max_depth
        self.timeout = timeout
        
        # 缓存已发现的URL
        self._visited_urls: Set[str] = set()
        
        # 探测历史
        self._probe_history: List[Dict[str, Any]] = []
    
    async def deep_recon(self, target: str, client: httpx.AsyncClient) -> ReconResult:
        """
        执行深度侦察
        
        Args:
            target: 目标URL
            client: HTTP客户端
            
        Returns:
            完整的侦察结果
        """
        logger.info(f"🔍 开始深度侦察: {target}")
        start_time = time.time()
        
        result = ReconResult(target_url=target)
        
        try:
            # 阶段1：基础请求与响应分析
            resp = await client.get(target, follow_redirects=True)
            
            # 分析响应头和响应体
            result.security_headers = self._analyze_security_headers(dict(resp.headers))
            result.missing_security_headers = self._find_missing_security_headers(resp.headers)
            result.interesting_headers = self._find_interesting_headers(resp.headers)
            result.comments_or_debug_info = self._find_comments_and_debug_info(resp.text)
            
            # 阶段2：技术栈识别
            result.technologies = self._detect_technologies(
                response_body=resp.text,
                response_headers=dict(resp.headers),
                status_code=resp.status_code,
            )
            result.primary_framework = self._determine_primary_framework(result.technologies)
            result.primary_language = self._determine_primary_language(result.technologies)
            result.primary_database = self._determine_primary_database(result.technologies)
            
            # 阶段3：WAF/防护识别
            result.waf_fingerprint = await self._identify_waf(target, client, resp)
            
            # 阶段4：架构推断
            result.architecture = self._infer_architecture(resp.headers, resp.text)
            result.is_behind_cdn = self._check_cdn_presence(resp.headers)
            result.is_load_balanced = self._check_load_balancing(resp.headers, resp.text)
            
            # 阶段5：认证机制识别
            result.auth_mechanism, result.auth_endpoints, result.session_config = \
                self._identify_auth_mechanism(resp.text, dict(resp.headers))
            
            # 阶段6：入口点发现
            result.entry_points = self._discover_entry_points(resp.text, target)
            result.api_endpoints = self._discover_api_endpoints(resp.text, target)
            result.sensitive_paths = await self._probe_sensitive_paths(target, client)
            
            # 阶段7：第三方组件识别
            result.third_party_components = self._identify_third_party_components(resp.text)
            
            elapsed = time.time() - start_time
            logger.info(f"✅ 侦察完成 ({elapsed:.2f}s): 发现 {len(result.technologies)} 个技术, "
                       f"WAF={result.waf_fingerprint.waf_type.value}, "
                       f"架构={result.architecture.value}")
            
        except Exception as e:
            logger.error(f"❌ 侦察失败: {e}")
            result.comments_or_debug_info.append(f"Recon Error: {str(e)}")
        
        return result
    
    def _detect_technologies(self, response_body: str, 
                            response_headers: Dict[str, str],
                            status_code: int) -> List[TechnologyInfo]:
        """
        检测目标使用的所有技术
        
        Args:
            response_body: 响应体
            response_headers: 响应头
            status_code: 状态码
            
        Returns:
            检测到的技术列表
        """
        detected = []
        combined_text = (
            response_body.lower() + 
            "\n" + 
            json.dumps(response_headers).lower()
        )
        
        for tech_name, sig in self.FRAMEWORK_SIGNATURES.items():
            matches = []
            confidence = 0.0
            version = None
            
            # 检查主体模式
            for pattern in sig['patterns']:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    matches.append(pattern)
                    confidence += 0.15
            
            # 尝试提取版本
            if sig['version_patterns']:
                for pattern, source in sig['version_patterns']:
                    if source == 'header':
                        text_to_search = json.dumps(response_headers)
                    elif source == 'body':
                        text_to_search = response_body
                    elif source == 'meta':
                        text_to_search = response_body
                    elif source == 'error':
                        text_to_search = response_body
                    elif source == 'cookie':
                        text_to_search = json.dumps(response_headers)
                    else:
                        text_to_search = combined_text
                    
                    match = re.search(pattern, text_to_search, re.IGNORECASE)
                    if match:
                        version = match.group(1)
                        confidence += 0.25
            
            # 根据状态码调整置信度
            if status_code >= 500 and tech_name in ['php', 'java', 'python']:
                confidence += 0.1
            
            if confidence > 0.2:
                detected.append(TechnologyInfo(
                    name=tech_name.title(),
                    category=sig['category'],
                    version=version,
                    confidence=min(confidence, 1.0),
                    fingerprints=matches[:5],  # 只保留前5个匹配
                ))
        
        # 按置信度排序
        detected.sort(key=lambda x: x.confidence, reverse=True)
        
        return detected[:10]  # 返回前10个最可能的技术
    
    async def _identify_waf(self, target: str, 
                          client: httpx.AsyncClient,
                          initial_response: httpx.Response) -> WAFFingerprint:
        """
        识别WAF/防护系统
        
        通过多种方式检测WAF：
        1. 响应头分析
        2. Cookie分析
        3. 响应体关键词
        4. 主动探测（发送可疑请求）
        """
        fingerprint = WAFFingerprint()
        
        headers_lower = {k.lower(): v for k, v in initial_response.headers.items()}
        cookies_str = "; ".join(initial_response.cookies.keys())
        body_lower = initial_response.text.lower() if initial_response.text else ""
        
        scores: Dict[WAFType, float] = {}
        signatures_found: Dict[WAFType, List[str]] = {}
        
        # 检查每个WAF类型的特征
        for waf_type, sig in self.WAF_SIGNATURES.items():
            score = 0.0
            found_signatures = []
            
            # 检查响应头
            for header_name, expected_value in sig['headers'].items():
                if header_name in headers_lower:
                    header_value = headers_lower[header_name].lower()
                    
                    if isinstance(expected_value, list):
                        if any(v.lower() in header_value for v in expected_value):
                            score += 0.25
                            found_signatures.append(f"Header:{header_name}={expected_value}")
                    else:
                        score += 0.20
                        found_signatures.append(f"Header:{header_name}")
            
            # 检查Cookie
            for cookie_name, _ in sig['cookies'].items():
                if cookie_name.lower() in cookies_str.lower():
                    score += 0.20
                    found_signatures.append(f"Cookie:{cookie_name}")
            
            # 检查响应体
            for pattern in sig['body_patterns']:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    score += 0.30
                    found_signatures.append(f"BodyPattern:{pattern[:30]}")
            
            # 检查状态码
            if initial_response.status_code in sig['status_codes']:
                score += 0.10
                found_signatures.append(f"Status:{initial_response.status_code}")
            
            if score > 0.3:
                scores[waf_type] = score
                signatures_found[waf_type] = found_signatures
        
        # 选择得分最高的WAF类型
        if scores:
            best_waf = max(scores.keys(), key=lambda x: scores[x])
            fingerprint.waf_type = best_waf
            fingerprint.confidence = scores[best_waf]
            fingerprint.detected_signatures = signatures_found[best_waf]
            fingerprint.vendor_name = best_waf.value.replace('_', ' ').title()
            
            # 获取绕过建议
            if best_waf in self.WAF_SIGNATURES:
                fingerprint.bypass_recommendations = \
                    self.WAF_SIGNATURES[best_waf]['bypass_tips']
            
            # 评估防护强度
            total_score = sum(scores.values())
            if total_score > 1.5:
                fingerprint.protection_level = ProtectionLevel.VERY_HIGH
            elif total_score > 1.0:
                fingerprint.protection_level = ProtectionLevel.HIGH
            elif total_score > 0.5:
                fingerprint.protection_level = ProtectionLevel.MEDIUM
            else:
                fingerprint.protection_level = ProtectionLevel.LOW
        
        return fingerprint
    
    def _analyze_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """分析安全相关的响应头"""
        security_headers = {}
        
        for header_name, description in self.SECURITY_HEADERS.items():
            value = headers.get(header_name)
            if value:
                security_headers[header_name] = value
        
        return security_headers
    
    def _find_missing_security_headers(self, headers) -> List[str]:
        """查找缺失的安全头"""
        missing = []
        
        # 必须的安全头
        critical_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
        ]
        
        for header in critical_headers:
            if header not in headers:
                missing.append(header)
        
        return missing
    
    def _find_interesting_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """查找有趣或非标准的响应头"""
        interesting = {}
        
        patterns = {
            'x-powered-by': 'Technology disclosure',
            'x-aspnet-version': 'ASP.NET version',
            'x-runtime': 'Response time',
            'x-request-id': 'Request tracking',
            'x-debug-token': 'Debug mode',
            'x-source': 'Source code reference',
            'server': 'Server information',
            'via': 'Proxy/CDN information',
            'x-cache': 'Cache status',
            'x-ratelimit': 'Rate limiting',
            'set-cookie': 'Session management',
        }
        
        for header, reason in patterns.items():
            value = headers.get(header)
            if value:
                interesting[f"{header} ({reason})"] = value
        
        return interesting
    
    def _find_comments_and_debug_info(self, body: str) -> List[str]:
        """从HTML中提取注释和调试信息"""
        findings = []
        
        if not body:
            return findings
        
        # HTML注释
        html_comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        for comment in html_comments:
            comment = comment.strip()
            if len(comment) > 5 and not comment.startswith('[if'):
                findings.append(f"HTML Comment: {comment[:100]}")
        
        # JavaScript注释（如果包含在HTML中）
        js_comments = re.findall(r'//.*?$|/\*.*?\*/', body, re.MULTILINE | re.DOTALL)
        for comment in js_comments:
            comment = comment.strip()
            if any(keyword in comment.lower() for keyword in 
                   ['todo', 'fixme', 'hack', 'debug', 'xxx', 'password', 'secret']):
                findings.append(f"JS Comment: {comment[:100]}")
        
        # 调试信息
        debug_patterns = [
            (r'DEBUG\s*=\s*True', 'Debug Mode Enabled'),
            (r'var_dump\(', 'PHP var_dump Found'),
            (r'print_r\(', 'PHP print_r Found'),
            (r'console\.(log|debug|warn)', 'JavaScript Console Output'),
            (r'<pre>', '<pre> Tag Found'),
            (r'error_reporting', 'PHP Error Reporting'),
            (r'display_errors', 'PHP Display Errors'),
            (r'Stack Trace:', 'Stack Trace Visible'),
            (r'Exception:', 'Exception Details Visible'),
            (r'Warning:.*\.php on line', 'PHP Warning with Line Number'),
            (r'Notice:.*\.php on line', 'PHP Notice with Line Number'),
        ]
        
        for pattern, description in debug_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                findings.append(description)
        
        return findings[:20]  # 限制数量
    
    def _infer_architecture(self, headers: Dict[str, str], 
                           body: str) -> ArchitectureType:
        """推断应用架构类型"""
        
        # 检查CDN特征
        cdn_indicators = ['cf-ray', 'x-cdn', 'x-akamai', 'x-sucuri-id']
        if any(indicator in headers.keys() for indicator in cdn_indicators):
            return ArchitectureType.CDN_PROXIED
        
        # 检查负载均衡特征
        lb_indicators = [
            ('set-cookie', r'__cfduid'),  # Cloudflare
            ('set-cookie', r'AWSELB'),     # AWS ELB
            ('set-cookie', r'BIGipServer'),# F5 LTM
            ('via', r'load.?balancer'),
            ('x-forwarded-for', r'.+'),
        ]
        
        lb_count = 0
        for header, pattern in lb_indicators:
            value = headers.get(header, '')
            if re.search(pattern, value, re.IGNORECASE):
                lb_count += 1
        
        if lb_count >= 2:
            return ArchitectureType.LOAD_BALANCED
        
        # 检查微服务特征
        microservice_indicators = [
            r'gateway',
            r'service-mesh',
            r'istio',
            r'envoy',
            r'linkerd',
            r'kubernetes',
        ]
        
        combined = f"{json.dumps(headers)} {body}"
        ms_matches = sum(1 for pattern in microservice_indicators 
                       if re.search(pattern, combined, re.IGNORECASE))
        
        if ms_matches >= 2:
            return ArchitectureType.MICROSERVICES
        
        # 默认返回单体架构
        return ArchitectureType.MONOLITHIC
    
    def _check_cdn_presence(self, headers: Dict[str, str]) -> bool:
        """检查是否使用了CDN"""
        cdn_headers = {
            'cf-ray': 'Cloudflare',
            'x-cdn': 'Generic CDN',
            'x-akamai-transformed': 'Akamai',
            'x-sucuri-id': 'Sucuri',
            'x-amz-cf-id': 'CloudFront',
            'x-azure-ref': 'Azure CDN',
            'via': 'Generic Proxy/CDN',
        }
        
        for header, cdn_name in cdn_headers.items():
            if header in headers:
                return True
        
        return False
    
    def _check_load_balancing(self, headers: Dict[str, str], 
                             body: str) -> bool:
        """检查是否使用了负载均衡"""
        
        # 检查负载均衡Cookie
        lb_cookies = ['AWSELB', 'BIGipServer', '__cfduid']
        set_cookie = headers.get('set-cookie', '')
        if any(cookie in set_cookie for cookie in lb_cookies):
            return True
        
        # 检查Via头
        via = headers.get('via', '')
        if 'load' in via.lower() or 'balance' in via.lower():
            return True
        
        # 检查Server头的多个值
        server = headers.get('server', '')
        if ';' in server or ',' in server:
            return True
        
        return False
    
    def _identify_auth_mechanism(self, body: str, 
                                headers: Dict[str, str]) -> Tuple[AuthType, List[str], Dict[str, Any]]:
        """
        识别认证机制
        
        Returns:
            (认证类型, 认证端点列表, 会话配置)
        """
        auth_type = AuthType.NONE
        auth_endpoints = []
        session_config = {}
        
        body_lower = body.lower()
        headers_str = json.dumps(headers).lower()
        
        # 检查Session Cookie认证
        session_cookies = ['sessionid', 'jsessionid', 'phpsessid', 'asp.net_sessionid']
        set_cookie = headers.get('set-cookie', '')
        if any(cookie in set_cookie.lower() for cookie in session_cookies):
            auth_type = AuthType.SESSION_COOKIE
            session_config['type'] = 'session_cookie'
            # 提取cookie名称
            for cookie in session_cookies:
                if cookie in set_cookie.lower:
                    session_config['cookie_name'] = cookie
                    break
        
        # 检查JWT Token认证
        jwt_patterns = [
            r'authorization:\s*bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            r'"token"\s*:\s*"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"',
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        ]
        for pattern in jwt_patterns:
            if re.search(pattern, body_lower) or re.search(pattern, headers_str):
                auth_type = AuthType.JWT_TOKEN
                session_config['type'] = 'jwt'
                break
        
        # 检查OAuth2
        oauth2_patterns = [
            r'oauth2',
            r'oauth/authorize',
            r'oauth/token',
            r'/authorize\?',
            r'/token\?',
            r'client_id=',
            r'redirect_uri=',
        ]
        oauth2_matches = sum(1 for p in oauth2_patterns if p in body_lower)
        if oauth2_matches >= 2:
            auth_type = AuthType.OAUTH2
            session_config['type'] = 'oauth2'
        
        # 检查Basic Auth
        if 'www-authenticate' in headers and 'basic' in headers['www-authenticate'].lower():
            auth_type = AuthType.BASIC_AUTH
            session_config['type'] = 'basic'
        
        # 发现认证端点
        auth_endpoint_patterns = [
            (r'href=["\']([^"\']*login[^"\']*)["\']', 'Login Page'),
            (r'action=["\']([^"\']*auth[^"\']*)["\']', 'Auth Endpoint'),
            (r'href=["\']([^"\']*signin[^"\']*)["\']', 'Sign In Page'),
            (r'href=["\']([^"\']*register[^"\']*)["\']', 'Register Page'),
            (r'href=["\']([^"\']*logout[^"\']*)["\']', 'Logout Endpoint'),
            (r'href=["\']([^"\']*oauth[^"\']*)["\']', 'OAuth Endpoint'),
            (r'href=["\']([^"\']*sso[^"\']*)["\']', 'SSO Endpoint'),
        ]
        
        for pattern, desc in auth_endpoint_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                if match not in auth_endpoints:
                    auth_endpoints.append(match)
        
        # 检查表单认证
        form_auth_patterns = [
            r'<form[^>]*action=["\'][^"\']*login["\']',
            r'<form[^>]*action=["\'][^"\']*auth["\']',
            r'name=["\'](username|email|user|login)["\']',
            r'name=["\'](password|passwd|pass)["\']',
            r'type=["\']password["\']',
        ]
        
        form_auth_matches = sum(1 for p in form_auth_patterns if re.search(p, body, re.IGNORECASE))
        if form_auth_matches >= 2:
            if auth_type == AuthType.NONE:
                auth_type = AuthType.FORM_BASED
            session_config['has_login_form'] = True
        
        return auth_type, auth_endpoints, session_config
    
    def _discover_entry_points(self, body: str, base_url: str) -> List[EntryPoint]:
        """从HTML中发现入口点"""
        entries = []
        
        # 链接发现
        link_patterns = [
            (r'href=["\']([^"\']+)["\']', 'GET'),
            (r'action=["\']([^"\']+)["\']', 'POST'),
            (r'src=["\']([^"\']+\.js)["\']', 'GET'),
            (r'src=["\']([^"\']+\.css)["\']', 'GET'),
        ]
        
        seen_urls = set()
        for pattern, method in link_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for url in matches:
                # 过滤无效URL
                if url.startswith(('javascript:', 'mailto:', '#', 'tel:', 'data:')):
                    continue
                
                # 转换为绝对URL
                if url.startswith('/'):
                    full_url = base_url.rstrip('/') + url
                elif url.startswith('http'):
                    full_url = url
                else:
                    continue
                
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    
                    # 推断功能
                    functionality = self._infer_functionality(url)
                    risk_score = self._calculate_risk_score(url, functionality)
                    
                    entries.append(EntryPoint(
                        url=full_url,
                        method=method,
                        functionality=functionality,
                        risk_score=risk_score,
                    ))
        
        # 按风险评分排序
        entries.sort(key=lambda x: x.risk_score, reverse=True)
        
        return entries[:50]  # 返回前50个高风险入口
    
    def _discover_api_endpoints(self, body: str, base_url: str) -> List[EntryPoint]:
        """发现API端点"""
        api_entries = []
        
        # REST API模式
        rest_patterns = [
            r'["\'](/api/v?\d+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.put\(["\']([^"\']+)["\']',
            r'\.delete\(["\']([^"\']+)["\']',
        ]
        
        seen_urls = set()
        for pattern in rest_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for url in matches:
                if url.startswith('/'):
                    full_url = base_url.rstrip('/') + url
                else:
                    continue
                
                if full_url not in seen_urls:
                    seen_urls.add(full_url)
                    
                    api_entries.append(EntryPoint(
                        url=full_url,
                        method='GET',  # 默认GET，实际需要根据上下文判断
                        functionality='API Endpoint',
                        risk_score=0.7,  # API端点通常风险较高
                    ))
        
        # GraphQL端点
        graphql_patterns = [
            r'["\'](/graphql)["\']',
            r'["\'](/graphiql)["\']',
            r'new\s+GraphQL',
        ]
        
        for pattern in graphql_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                url = match.group(1)
                if url.startswith('/'):
                    full_url = base_url.rstrip('/') + url
                else:
                    full_url = url
                
                api_entries.append(EntryPoint(
                    url=full_url,
                    method='POST',
                    functionality='GraphQL Endpoint',
                    risk_score=0.8,
                ))
        
        return api_entries[:30]
    
    async def _probe_sensitive_paths(self, target: str, 
                                    client: httpx.AsyncClient) -> List[str]:
        """探测敏感路径是否存在"""
        discovered = []
        
        # 限制探测的路径数量以避免过多请求
        paths_to_check = self.SENSITIVE_PATHS[:30]
        
        for path in paths_to_check:
            if path in self._visited_urls:
                continue
            
            url = target.rstrip('/') + path
            self._visited_urls.add(url)
            
            try:
                resp = await client.get(url, follow_redirects=False)
                
                # 如果返回200或3xx，说明路径存在
                if resp.status_code < 400:
                    discovered.append({
                        'path': path,
                        'url': url,
                        'status_code': resp.status_code,
                        'size': len(resp.content),
                    })
                    
            except Exception:
                pass
        
        return discovered
    
    def _identify_third_party_components(self, body: str) -> Dict[str, str]:
        """识别第三方组件及其版本"""
        components = {}
        
        for component, sig in self.THIRD_PARTY_SIGNATURES.items():
            # 检查是否使用了该组件
            used = any(re.search(p, body, re.IGNORECASE) for p in sig['patterns'])
            
            if used:
                # 尝试提取版本
                version_match = re.search(sig['extract_version'], body, re.IGNORECASE)
                version = version_match.group(1) if version_match else 'Unknown'
                
                components[component.capitalize()] = version
        
        return components
    
    def _infer_functionality(self, url: str) -> str:
        """根据URL推断功能"""
        url_lower = url.lower()
        
        functional_keywords = {
            'login': 'Authentication',
            'logout': 'Logout',
            'register': 'Registration',
            'admin': 'Administration',
            'dashboard': 'Dashboard',
            'api': 'API Endpoint',
            'upload': 'File Upload',
            'download': 'File Download',
            'search': 'Search',
            'profile': 'User Profile',
            'settings': 'Settings',
            'config': 'Configuration',
            'backup': 'Backup',
            'debug': 'Debug',
            'console': 'Console',
            'test': 'Testing',
            'graphql': 'GraphQL',
            'rest': 'REST API',
            'docs': 'Documentation',
            'help': 'Help',
            'contact': 'Contact',
            'about': 'About',
        }
        
        for keyword, func in functional_keywords.items():
            if keyword in url_lower:
                return func
        
        return 'General'
    
    def _calculate_risk_score(self, url: str, functionality: str) -> float:
        """计算入口点的风险评分"""
        score = 0.3  # 基础分
        
        url_lower = url.lower()
        
        # 高风险关键词
        high_risk_keywords = {
            'admin': 0.3,
            'upload': 0.25,
            'api': 0.2,
            'config': 0.25,
            'debug': 0.3,
            'test': 0.2,
            'backup': 0.25,
            'console': 0.3,
            'shell': 0.35,
            'exec': 0.3,
            'cmd': 0.35,
            'graphql': 0.2,
        }
        
        for keyword, bonus in high_risk_keywords.items():
            if keyword in url_lower:
                score += bonus
        
        # 功能性风险
        high_risk_functions = [
            'Administration', 'File Upload', 'Configuration',
            'Debug', 'Console', 'API Endpoint', 'GraphQL',
        ]
        
        if functionality in high_risk_functions:
            score += 0.15
        
        # 参数存在性
        if '?' in url:
            score += 0.05
        
        return min(score, 1.0)
    
    def _determine_primary_framework(self, technologies: List[TechnologyInfo]) -> Optional[str]:
        """确定主要框架"""
        frameworks = [t for t in technologies if t.category == 'framework']
        if frameworks:
            return frameworks[0].name
        return None
    
    def _determine_primary_language(self, technologies: List[TechnologyInfo]) -> Optional[str]:
        """确定主要编程语言"""
        languages = [t for t in technologies if t.category == 'language']
        if languages:
            return languages[0].name
        return None
    
    def _determine_primary_database(self, technologies: List[TechnologyInfo]) -> Optional[str]:
        """确定主要数据库"""
        databases = [t for t in technologies if t.category == 'database']
        if databases:
            return databases[0].name
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取侦察统计信息"""
        return {
            "visited_urls_count": len(self._visited_urls),
            "probe_history_count": len(self._probe_history),
        }


def create_recon_engine(max_depth: int = 3, timeout: float = 10.0) -> ReconEngine:
    """创建侦察引擎实例的便捷函数"""
    return ReconEngine(max_depth=max_depth, timeout=timeout)
