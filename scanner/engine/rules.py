"""
scanner.engine.rules
--------------------
规则引擎：提供基于框架、置信度、多重证据的漏洞判定与误报过滤逻辑。

核心逻辑：
1. 框架自动识别与版本探测
2. 漏洞置信度动态调整 (ConfidenceAdjustment)
3. 多维度证据计数 (Evidence Counting)
4. 跨框架误报防护 (Cross-Framework Protection)
5. 严格/中等/宽松验证等级 (ValidationLevel)
"""

from enum import Enum
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
import re
import logging

logger = logging.getLogger(__name__)

class FrameworkType(Enum):
    UNKNOWN = "unknown"
    THINKPHP = "thinkphp"
    DRUPAL = "drupal"
    DJANGO = "django"
    LARAVEL = "laravel"
    WORDPRESS = "wordpress"
    SPRING = "spring"
    STRUTS2 = "struts2"

class ValidationLevel(Enum):
    LOOSE = 1      # 宽松：命中即报
    MODERATE = 2   # 中等：需要一定置信度或多个证据
    STRICT = 3     # 严格：需要高置信度和框架匹配

@dataclass
class FrameworkSignature:
    framework: FrameworkType
    headers: Dict[str, str] = field(default_factory=dict)
    body_patterns: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)
    exclusive_signatures: List[str] = field(default_factory=list)
    version_patterns: List[str] = field(default_factory=list)

@dataclass
class ConfidenceAdjustment:
    factor_name: str
    condition: str
    adjustment: float
    description: str

@dataclass
class ExclusionRule:
    rule_id: str
    condition: str
    exclusion_patterns: List[str] = field(default_factory=list)
    description: str = ""

@dataclass
class DetectionRule:
    plugin_id: str
    expected_frameworks: List[FrameworkType] = field(default_factory=list)
    validation_level: ValidationLevel = ValidationLevel.MODERATE
    min_confidence: float = 0.3
    required_evidence_count: int = 1
    exclusion_rules: List[str] = field(default_factory=list)
    confidence_adjustments: List[ConfidenceAdjustment] = field(default_factory=list)

# =============================================================================
# 框架指纹定义
# =============================================================================

FRAMEWORK_SIGNATURES: Dict[FrameworkType, FrameworkSignature] = {
    FrameworkType.THINKPHP: FrameworkSignature(
        framework=FrameworkType.THINKPHP,
        headers={
            "X-Powered-By": r"ThinkPHP",
        },
        body_patterns=[
            r"十年磨一剑",
            r"ThinkPHP",
            r"think_session",
            r"Var_Pathinfo",
            r"think-error",
            r"thinkphp_show_page_trace",
        ],
        url_patterns=[
            r"s=/index/index",
            r"public/static",
            r"\?s=",
        ],
        exclusive_signatures=[
            "X-Powered-By: ThinkPHP",
            "Think\\Db\\Exception",
            "Think\\Exception",
            "thinkphp_show_page_trace",
            "十年磨一剑",
        ],
        version_patterns=[
            r"ThinkPHP\s*v?([0-9\.]+)",
        ],
    ),
    FrameworkType.DRUPAL: FrameworkSignature(
        framework=FrameworkType.DRUPAL,
        headers={
            "X-Generator": r"Drupal",
            "X-Drupal-Cache": r".*",
        },
        body_patterns=[
            r"Drupal\.settings",
            r"sites/default/files",
            r"drupal\.js",
            r'name="form_build_id"',
            r"jQuery\.extend\(Drupal\.settings",
        ],
        url_patterns=[
            r"sites/default/files",
            r"node/add",
            r"user/register",
            r"q=user",
        ],
        exclusive_signatures=[
            "X-Generator: Drupal",
            "Drupal.settings",
            "form_build_id",
            "_drupal_ajax",
            "sites/default/files",
        ],
        version_patterns=[
            r"Drupal\s*([0-9\.]+)",
        ],
    ),
    FrameworkType.DJANGO: FrameworkSignature(
        framework=FrameworkType.DJANGO,
        headers={
            "X-Frame-Options": r"DENY",
            "Server": r"WSGIServer",
        },
        body_patterns=[
            r"csrfmiddlewaretoken",
            r"django\.js",
            r"It worked!",
            r"Django debug page",
        ],
        url_patterns=[
            r"/admin/login/",
            r"/static/admin/",
            r"csrfmiddlewaretoken",
        ],
        exclusive_signatures=[
            "csrfmiddlewaretoken",
            "IntegrityError",
            "UNIQUE constraint failed",
            "django.jQuery",
        ],
        version_patterns=[
            r"Django\s*([0-9\.]+)",
        ],
    ),
}

# =============================================================================
# 误报过滤规则
# =============================================================================

EXCLUSION_RULES: Dict[str, ExclusionRule] = {
    "response_has_thinkphp_exclusive_sig": ExclusionRule(
        rule_id="response_has_thinkphp_exclusive_sig",
        condition="framework_mismatch",
        exclusion_patterns=[
            r"X-Powered-By:\s*ThinkPHP",
            r"Think\\Db\\Exception",
            r"Var_Pathinfo",
        ],
        description="当响应包含ThinkPHP独有特征时，排除非ThinkPHP漏洞误报",
    ),
    "response_has_drupal_exclusive_sig": ExclusionRule(
        rule_id="response_has_drupal_exclusive_sig",
        condition="framework_mismatch",
        exclusion_patterns=[
            r"X-Generator:\s*Drupal",
            r"Drupal\.settings",
            r"sites/default/files",
        ],
        description="当响应包含Drupal独有特征时，排除非Drupal漏洞误报",
    ),
    "response_has_django_exclusive_sig": ExclusionRule(
        rule_id="response_has_django_exclusive_sig",
        condition="framework_mismatch",
        exclusion_patterns=[
            r"csrfmiddlewaretoken",
            r"IntegrityError",
            r"UNIQUE constraint failed",
        ],
        description="当响应包含Django独有特征时，排除非Django漏洞误报",
    ),
}

# =============================================================================
# 漏洞检测判定规则 (DetectionRules)
# =============================================================================

DETECTION_RULES: Dict[str, DetectionRule] = {
    "thinkphp-sqli": DetectionRule(
        plugin_id="thinkphp-sqli",
        expected_frameworks=[FrameworkType.THINKPHP],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.40,
        required_evidence_count=2,
        exclusion_rules=[
            "response_has_drupal_exclusive_sig",
            "response_has_django_exclusive_sig",
        ],
        confidence_adjustments=[
            ConfidenceAdjustment(
                factor_name="framework_match",
                condition="target_is_thinkphp",
                adjustment=0.20,
                description="目标确认是ThinkPHP框架，提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="framework_mismatch",
                condition="target_is_not_thinkphp",
                adjustment=-0.20,
                description="目标不是ThinkPHP框架，降低置信度",
            ),
            ConfidenceAdjustment(
                factor_name="thinkphp_exclusive_hit",
                condition="response_has_thinkphp_exclusive_sig",
                adjustment=0.25,
                description="响应包含ThinkPHP独有特征（如Trace或Db异常），大幅提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="sql_error_match",
                condition="response_has_sql_error",
                adjustment=0.15,
                description="响应包含通用SQL错误特征",
            ),
        ],
    ),
    "drupal-cve-2019-6341": DetectionRule(
        plugin_id="drupal-cve-2019-6341",
        expected_frameworks=[FrameworkType.DRUPAL],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.35,
        required_evidence_count=2,
        exclusion_rules=[
            "response_has_thinkphp_exclusive_sig",
            "response_has_django_exclusive_sig",
        ],
        confidence_adjustments=[
            ConfidenceAdjustment(
                factor_name="framework_match",
                condition="target_is_drupal",
                adjustment=0.20,
                description="目标确认是Drupal框架，提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="drupal_exclusive_hit",
                condition="response_has_drupal_exclusive_sig",
                adjustment=0.25,
                description="响应包含Drupal独有特征，大幅提升置信度",
            ),
        ],
    ),
    "django-cve-2017-12794": DetectionRule(
        plugin_id="django-cve-2017-12794",
        expected_frameworks=[FrameworkType.DJANGO],
        validation_level=ValidationLevel.MODERATE,
        min_confidence=0.25,
        required_evidence_count=1,
        exclusion_rules=[
            "response_has_thinkphp_exclusive_sig",
            "response_has_drupal_exclusive_sig",
        ],
        confidence_adjustments=[
            ConfidenceAdjustment(
                factor_name="framework_match",
                condition="target_is_django",
                adjustment=0.20,
                description="目标确认是Django框架，提升置信度",
            ),
            ConfidenceAdjustment(
                factor_name="django_exclusive_hit",
                condition="response_has_django_exclusive_sig",
                adjustment=0.25,
                description="响应包含Django独有特征（如调试页错误），大幅提升置信度",
            ),
        ],
    ),
}

# =============================================================================
# 关键词库
# =============================================================================

HIGH_SPECIFICITY_SQLI_KEYWORDS = [
    "XPATH syntax error",
    "extractvalue()",
    "updatexml()",
    "SQLSTATE[42",
    "SQLSTATE[HY000]",
]

THINKPHP_EXCLUSIVE_SQLI_KEYWORDS = [
    "Think\\Db\\Exception",
    "Think\\Exception",
    "thinkphp_show_page_trace",
]

GENERIC_SQL_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_error",
    "syntax error",
    "ora-01756",
    "unclosed quotation mark",
]

# =============================================================================
# 规则引擎实现
# =============================================================================

class RuleEngine:
    def __init__(self, config_path: Optional[str] = None):
        self._framework_signatures = FRAMEWORK_SIGNATURES
        self._exclusion_rules = EXCLUSION_RULES
        self._detection_rules = DETECTION_RULES
        
    def detect_framework(self, response_body: str, response_headers: Dict[str, str], request_url: str) -> Tuple[List[FrameworkType], Dict[FrameworkType, float]]:
        detected = []
        confidences = {}
        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        
        for fw_type, sig in self._framework_signatures.items():
            score = 0.0
            # Header match
            for h, p in sig.headers.items():
                if h in response_headers and re.search(p, response_headers[h], re.I):
                    score += 0.4
            # Body patterns
            for p in sig.body_patterns:
                if re.search(p, response_body, re.I):
                    score += 0.2
            # URL patterns
            for p in sig.url_patterns:
                if re.search(p, request_url, re.I):
                    score += 0.2
            # Exclusive signatures
            for es in sig.exclusive_signatures:
                if es.lower() in body_lower or es.lower() in header_text:
                    score += 0.5
            
            if score > 0.3:
                detected.append(fw_type)
                confidences[fw_type] = min(score, 1.0)
                
        if not detected:
            detected.append(FrameworkType.UNKNOWN)
            confidences[FrameworkType.UNKNOWN] = 1.0
            
        return detected, confidences

    def detect_version(self, framework: FrameworkType, response_body: str, response_headers: Dict[str, str]) -> Optional[str]:
        sig = self._framework_signatures.get(framework)
        if not sig: return None
        combined = response_body + str(response_headers)
        for p in sig.version_patterns:
            m = re.search(p, combined, re.I)
            if m: return m.group(1)
        return None

    def validate_vulnerability(self, plugin_id: str, detected_frameworks: List[FrameworkType], response_body: str, response_headers: Dict[str, str], request_url: str, matched_keywords: List[str]) -> Tuple[bool, str]:
        rule = self._detection_rules.get(plugin_id)
        if not rule: return True, "No rule defined"
        
        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        
        # Check exclusion rules
        for ex_id in rule.exclusion_rules:
            ex_rule = self._exclusion_rules.get(ex_id)
            if not ex_rule: continue
            
            if ex_rule.condition == "framework_mismatch":
                triggered = any(re.search(p, body_lower + header_text, re.I) for p in ex_rule.exclusion_patterns)
                if triggered:
                    # If current framework is expected, it's NOT an exclusion
                    if not any(fw in rule.expected_frameworks for fw in detected_frameworks):
                        return False, f"Exclusion triggered: {ex_rule.description}"
        
        # Check framework mismatch for STRICT level
        if rule.validation_level == ValidationLevel.STRICT:
            if not any(fw in rule.expected_frameworks for fw in detected_frameworks):
                return False, f"Framework mismatch for STRICT rule (expected {rule.expected_frameworks})"
                
        return True, "Valid"

    def adjust_confidence(self, plugin_id: str, base_confidence: float, detected_frameworks: List[FrameworkType], response_body: str, response_headers: Dict[str, str], request_url: str, matched_keywords: List[str]) -> Tuple[float, List[str]]:
        rule = self._detection_rules.get(plugin_id)
        if not rule: return base_confidence, []
        
        confidence = base_confidence
        details = []
        body_lower = response_body.lower()
        header_text = str(response_headers).lower()
        
        for adj in rule.confidence_adjustments:
            triggered = False
            if adj.condition == "target_is_thinkphp":
                triggered = FrameworkType.THINKPHP in detected_frameworks
            elif adj.condition == "target_is_not_thinkphp":
                triggered = FrameworkType.THINKPHP not in detected_frameworks
            elif adj.condition == "target_is_drupal":
                triggered = FrameworkType.DRUPAL in detected_frameworks
            elif adj.condition == "target_is_django":
                triggered = FrameworkType.DJANGO in detected_frameworks
            elif adj.condition == "response_has_thinkphp_exclusive_sig":
                thinkphp_sig = self._framework_signatures.get(FrameworkType.THINKPHP)
                if thinkphp_sig:
                    triggered = any(es.lower() in body_lower or es.lower() in header_text for es in thinkphp_sig.exclusive_signatures)
            elif adj.condition == "response_has_drupal_exclusive_sig":
                drupal_sig = self._framework_signatures.get(FrameworkType.DRUPAL)
                if drupal_sig:
                    triggered = any(es.lower() in body_lower or es.lower() in header_text for es in drupal_sig.exclusive_signatures)
            elif adj.condition == "response_has_django_exclusive_sig":
                django_sig = self._framework_signatures.get(FrameworkType.DJANGO)
                if django_sig:
                    triggered = any(es.lower() in body_lower or es.lower() in header_text for es in django_sig.exclusive_signatures)
            elif adj.condition == "response_has_sql_error":
                triggered = any(err.lower() in body_lower for err in GENERIC_SQL_ERRORS)
            elif adj.condition == "response_has_other_framework_sig":
                expected = set(rule.expected_frameworks)
                for fw in detected_frameworks:
                    if fw not in expected and fw != FrameworkType.UNKNOWN:
                        triggered = True
                        break
            
            if triggered:
                confidence += adj.adjustment
                details.append(f"{adj.factor_name}: {adj.adjustment:+.2f} ({adj.description})")
                
        return max(0.0, min(1.0, confidence)), details

    def get_min_confidence(self, plugin_id: str) -> float:
        rule = self._detection_rules.get(plugin_id)
        return rule.min_confidence if rule else 0.3

    def get_required_evidence_count(self, plugin_id: str) -> int:
        rule = self._detection_rules.get(plugin_id)
        return rule.required_evidence_count if rule else 1
